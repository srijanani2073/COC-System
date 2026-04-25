from supabase import create_client
from storage3.exceptions import StorageApiError

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    raise ValueError("Missing Supabase environment variables")

supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

class DuplicateFileError(Exception):
    pass

def upload_file_to_supabase(file, case_id, evidence_code, version):
    filename = file.filename
    storage_path = f"case_{case_id}/{evidence_code}/v{version}_{filename}"

    try:
        file.stream.seek(0)
        supabase.storage.from_("evidence-files").upload(
            storage_path,
            file.read(),
            file_options={"content-type": file.content_type}
        )
        return storage_path
    except StorageApiError as e:
        error = e.args[0] if e.args else {}
        if isinstance(error, dict) and error.get("statusCode") == 409:
            raise DuplicateFileError("FILE_ALREADY_EXISTS")
        raise

def upload_encrypted_bytes_to_supabase(encrypted_bytes: bytes, storage_path: str) -> str:
    """
    Replace the file at storage_path with AES-encrypted bytes.
    Uses upsert=True to overwrite the plaintext file that was uploaded first.
    Called immediately after evidence_id is obtained so HKDF can derive the key.
    Returns storage_path unchanged (same path, now encrypted content).
    """
    try:
        supabase.storage.from_("evidence-files").upload(
            storage_path,
            encrypted_bytes,
            file_options={
                "content-type": "application/octet-stream",
                "upsert": "true",
            }
        )
    except StorageApiError as e:
        # If upsert isn't supported in this version, try remove + re-upload
        try:
            supabase.storage.from_("evidence-files").remove([storage_path])
        except Exception:
            pass
        supabase.storage.from_("evidence-files").upload(
            storage_path,
            encrypted_bytes,
            file_options={"content-type": "application/octet-stream"}
        )
    return storage_path


def get_public_url(storage_path):
    # NOTE: Only used during the upload flow to get a temporary reference URL.
    # For actual user downloads, always use get_signed_url() instead —
    # it enforces authentication and produces a time-limited link.
    return (
        f"{SUPABASE_URL}/storage/v1/object/public/"
        f"evidence-files/{storage_path}"
    )


def get_signed_url(storage_path: str, expires_in: int = 3600) -> str:
    """
    Generate a time-limited signed URL for a private evidence file.

    Args:
        storage_path: Path inside the 'evidence-files' bucket.
        expires_in:   Seconds until the URL expires (default: 1 hour).

    Returns:
        A signed URL string that expires after `expires_in` seconds.

    Raises:
        StorageApiError: If Supabase cannot generate the URL.

    NOTE: For this to work the 'evidence-files' bucket must be set to
    PRIVATE in the Supabase dashboard (Storage → Policies). Public buckets
    ignore signed URLs and serve files to anyone with the path.
    """
    response = supabase.storage.from_("evidence-files").create_signed_url(
        storage_path,
        expires_in
    )
    # Supabase Python SDK returns a dict with key 'signedURL'
    signed_url = response.get("signedURL") or response.get("signed_url") or response.get("data", {}).get("signedURL")
    if not signed_url:
        raise StorageApiError(f"Failed to generate signed URL for {storage_path}: {response}")
    return signed_url


def fetch_encrypted_bytes(storage_path: str) -> bytes:
    """
    Download the raw (encrypted) bytes of an evidence file from Supabase
    directly to the server — the client never receives the ciphertext.

    Used by the secure download route: server fetches → decrypts → streams
    plaintext to the authenticated user. The AES key never leaves the server.

    Raises:
        StorageApiError: If the download fails.
    """
    response = supabase.storage.from_("evidence-files").download(storage_path)
    # SDK returns bytes directly
    if isinstance(response, (bytes, bytearray)):
        return bytes(response)
    # Some SDK versions return a Response-like object
    if hasattr(response, "content"):
        return response.content
    raise StorageApiError(f"Unexpected response type from Supabase download: {type(response)}")
