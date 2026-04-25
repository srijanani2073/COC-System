"""
ECMS Crypto Pipeline (Vercel-Compatible)
=======================================

AES key derivation:
    MASTER_SECRET (from env) + evidence_id
    → HKDF-SHA256 → 32-byte AES-256 key

RSA keys:
    Loaded from environment variables:
        PRIVATE_KEY
        PUBLIC_KEY

No filesystem usage. Fully serverless-safe.
"""

from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import HKDF

import hashlib
import os
import base64
from datetime import datetime


# ── Master secret for AES key derivation ──────────────────────────────────
MASTER_SECRET = os.environ.get(
    "ECMS_MASTER_SECRET",
    "ecms-dev-master-secret-change-in-production-2024"
).encode("utf-8")


def load_rsa_keys():
    """Load RSA keys from environment variables."""
    private_key_str = os.environ.get("PRIVATE_KEY")
    public_key_str = os.environ.get("PUBLIC_KEY")

    if not private_key_str or not public_key_str:
        raise ValueError("Missing RSA keys in environment variables")

    # Fix newline formatting if needed (Vercel safe)
    private_key_str = private_key_str.replace("\\n", "\n")
    public_key_str = public_key_str.replace("\\n", "\n")

    private_key = RSA.import_key(private_key_str)
    public_key = RSA.import_key(public_key_str)

    return private_key, public_key


def derive_aes_key(evidence_id: int) -> bytes:
    """Derive deterministic AES-256 key using HKDF."""
    salt = str(evidence_id).encode("utf-8")
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
        pass  # No filesystem or key initialization

    # ── Hashing ────────────────────────────────────────────

    def compute_sha256(self, file_data: bytes) -> str:
        return hashlib.sha256(file_data).hexdigest()

    # ── RSA signing ────────────────────────────────────────

    def generate_rsa_signature(self, file_hash: str) -> str:
        private_key, _ = load_rsa_keys()
        hash_obj = SHA256.new(file_hash.encode("utf-8"))
        signature = pkcs1_15.new(private_key).sign(hash_obj)
        return base64.b64encode(signature).decode("utf-8")

    def verify_rsa_signature(self, file_hash: str, signature_b64: str) -> bool:
        try:
            _, public_key = load_rsa_keys()
            signature = base64.b64decode(signature_b64)
            hash_obj = SHA256.new(file_hash.encode("utf-8"))
            pkcs1_15.new(public_key).verify(hash_obj, signature)
            return True
        except (ValueError, TypeError):
            return False

    # ── AES-256-CBC with HKDF-derived key ─────────────────

    def encrypt_file_aes256(self, file_data: bytes, evidence_id: int) -> dict:
        key = derive_aes_key(evidence_id)
        iv = get_random_bytes(16)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_data = pad(file_data, AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)

        return {
            "encrypted_data": encrypted_data,
            "iv": base64.b64encode(iv).decode("utf-8"),
        }

    def decrypt_file_aes256(self, encrypted_data: bytes, iv_b64: str, evidence_id: int) -> bytes:
        key = derive_aes_key(evidence_id)
        iv = base64.b64decode(iv_b64)

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encrypted_data)
        return unpad(decrypted_padded, AES.block_size)

    # ── Full pipeline ──────────────────────────────────────

    def process_evidence_upload(self, file_data: bytes, evidence_id: int) -> dict:
        file_hash = self.compute_sha256(file_data)
        signature = self.generate_rsa_signature(file_hash)
        encryption_result = self.encrypt_file_aes256(file_data, evidence_id)

        return {
            "evidence_id": evidence_id,
            "file_hash_sha256": file_hash,
            "rsa_signature": signature,
            "encrypted_data": encryption_result["encrypted_data"],
            "encryption_key": None,
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
        try:
            decrypted_data = self.decrypt_file_aes256(
                encrypted_data, encryption_iv, evidence_id
            )

            computed_hash = self.compute_sha256(decrypted_data)
            hash_match = computed_hash == expected_hash
            signature_valid = self.verify_rsa_signature(
                computed_hash, signature
            ) if signature else False

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


# ── Singleton ─────────────────────────────────────────────

crypto_pipeline = CryptoPipeline()


def process_evidence_file(file_data: bytes, evidence_id: int) -> dict:
    return crypto_pipeline.process_evidence_upload(file_data, evidence_id)


def verify_evidence_file(
    encrypted_data: bytes, encryption_iv: str,
    evidence_id: int, expected_hash: str, signature: str
) -> dict:
    return crypto_pipeline.verify_evidence_integrity(
        encrypted_data, encryption_iv, evidence_id, expected_hash, signature
    )
