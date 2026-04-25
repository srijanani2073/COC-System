"""
ECMS Crypto Pipeline
====================
AES key derivation:
    MASTER_SECRET (from .env) + evidence_id
    → HKDF-SHA256 → 32-byte AES-256 key

This means NO aes key is stored in the database.
The key is re-derived on demand using the same master secret + evidence_id.

RSA keys:
    Stored in <project_root>/keys/  (persistent, not /tmp)
"""

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256, HMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import HKDF
import hashlib
import os
import base64
from datetime import datetime

# ── Key paths — persistent inside project ──────────────────────────────────
_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_HERE)          # one level up from cyber/
KEYS_DIR = os.path.join(_PROJECT_ROOT, "keys")
os.makedirs(KEYS_DIR, exist_ok=True)

# ── Master secret for AES key derivation ──────────────────────────────────
# In production, load from environment variable. Fallback for dev only.
MASTER_SECRET = os.environ.get(
    "ECMS_MASTER_SECRET",
    "ecms-dev-master-secret-change-in-production-2024"
).encode("utf-8")


def derive_aes_key(evidence_id: int) -> bytes:
    """
    Derive a deterministic 32-byte AES-256 key from MASTER_SECRET + evidence_id.

    Uses HKDF (HMAC-based Key Derivation Function) with SHA-256.
    Same inputs always produce the same key — no key storage needed.

    Flow:
        MASTER_SECRET + evidence_id
              │
              ▼
         HKDF-SHA256 (salt=evidence_id bytes, info=b"ecms-aes-key")
              │
              ▼
        32-byte AES-256 key (unique per evidence item)
    """
    salt = str(evidence_id).encode("utf-8")   # unique per evidence
    info = b"ecms-aes-key"
    key = HKDF(
        master=MASTER_SECRET,
        key_len=32,
        salt=salt,
        hashmod=SHA256,
        context=info,
        num_keys=1
    )
    return key


class CryptoPipeline:

    def __init__(self):
        self.rsa_key_file = os.path.join(KEYS_DIR, "rsa_private.pem")
        self.rsa_pub_file = os.path.join(KEYS_DIR, "rsa_public.pem")
        self._initialize_rsa_keys()

    def _initialize_rsa_keys(self):
        """Generate RSA-2048 keypair if not already present in keys/."""
        if not os.path.exists(self.rsa_key_file):
            key = RSA.generate(2048)
            with open(self.rsa_key_file, "wb") as f:
                f.write(key.export_key("PEM"))
            with open(self.rsa_pub_file, "wb") as f:
                f.write(key.publickey().export_key("PEM"))

    def get_private_key(self):
        with open(self.rsa_key_file, "rb") as f:
            return RSA.import_key(f.read())

    def get_public_key(self):
        with open(self.rsa_pub_file, "rb") as f:
            return RSA.import_key(f.read())

    # ── Hashing ────────────────────────────────────────────────────────────

    def compute_sha256(self, file_data: bytes) -> str:
        return hashlib.sha256(file_data).hexdigest()

    # ── RSA signing ────────────────────────────────────────────────────────

    def generate_rsa_signature(self, file_hash: str) -> str:
        private_key = self.get_private_key()
        hash_obj = SHA256.new(file_hash.encode("utf-8"))
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return base64.b64encode(signature).decode("utf-8")

    def verify_rsa_signature(self, file_hash: str, signature_b64: str) -> bool:
        try:
            public_key = self.get_public_key()
            signature = base64.b64decode(signature_b64)
            hash_obj = SHA256.new(file_hash.encode("utf-8"))
            pkcs1_15.new(public_key).verify(hash_obj, signature)
            return True
        except (ValueError, TypeError):
            return False

    # ── AES-256-CBC with HKDF-derived key ─────────────────────────────────

    def encrypt_file_aes256(self, file_data: bytes, evidence_id: int) -> dict:
        """
        Encrypt file_data using AES-256-CBC.
        Key is derived from MASTER_SECRET + evidence_id — NOT stored.
        IV is random and stored in DB (safe to store; not a secret).
        """
        key = derive_aes_key(evidence_id)
        iv = get_random_bytes(16)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(file_data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)

        return {
            "encrypted_data": encrypted_data,
            "iv": base64.b64encode(iv).decode("utf-8"),
            # key is intentionally NOT included — it's derived on demand
        }

    def decrypt_file_aes256(self, encrypted_data: bytes, iv_b64: str, evidence_id: int) -> bytes:
        """Re-derive key from evidence_id, then decrypt."""
        key = derive_aes_key(evidence_id)
        iv = base64.b64decode(iv_b64)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        return unpad(decrypted_padded, AES.block_size)

    # ── Full pipeline ──────────────────────────────────────────────────────

    def process_evidence_upload(self, file_data: bytes, evidence_id: int) -> dict:
        """
        Full upload pipeline:
            1. SHA-256 hash of plaintext
            2. RSA-2048 sign the hash
            3. AES-256-CBC encrypt using HKDF-derived key
            4. Return — only IV is stored (no key in DB)
        """
        file_hash = self.compute_sha256(file_data)
        signature = self.generate_rsa_signature(file_hash)
        encryption_result = self.encrypt_file_aes256(file_data, evidence_id)

        return {
            "evidence_id": evidence_id,
            "file_hash_sha256": file_hash,
            "rsa_signature": signature,
            "encrypted_data": encryption_result["encrypted_data"],
            "encryption_key": None,           # not stored — derived on demand
            "encryption_iv": encryption_result["iv"],
            "encryption_algorithm": "AES-256-CBC (HKDF-derived key)",
            "key_derivation": "HKDF-SHA256 (MASTER_SECRET + evidence_id)",
            "signature_algorithm": "RSA-2048-PKCS1v15",
            "processed_at": datetime.utcnow().isoformat(),
        }

    def verify_evidence_integrity(
        self, encrypted_data: bytes, encryption_iv: str,
        evidence_id: int, expected_hash: str, signature: str
    ) -> dict:
        """Decrypt using derived key, recompute hash, verify signature."""
        try:
            decrypted_data = self.decrypt_file_aes256(encrypted_data, encryption_iv, evidence_id)
            computed_hash = self.compute_sha256(decrypted_data)
            hash_match = computed_hash == expected_hash
            signature_valid = self.verify_rsa_signature(computed_hash, signature) if signature else False

            return {
                "success": True,
                "hash_match": hash_match,
                "signature_valid": signature_valid,
                "integrity_verified": hash_match and signature_valid,
                "computed_hash": computed_hash,
                "expected_hash": expected_hash,
                "verified_at": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "integrity_verified": False,
                "verified_at": datetime.utcnow().isoformat(),
            }


# ── Module-level singleton ─────────────────────────────────────────────────
crypto_pipeline = CryptoPipeline()


def process_evidence_file(file_data: bytes, evidence_id: int) -> dict:
    return crypto_pipeline.process_evidence_upload(file_data, evidence_id)


def verify_evidence_file(encrypted_data: bytes, encryption_iv: str,
                         evidence_id: int, expected_hash: str, signature: str) -> dict:
    return crypto_pipeline.verify_evidence_integrity(
        encrypted_data, encryption_iv, evidence_id, expected_hash, signature
    )
