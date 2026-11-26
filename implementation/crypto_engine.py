"""
Innovative Hybrid Cryptographic File Protection and Integrity Verification
Core Cryptographic Engine: AES-256 (GCM), RSA-2048 (OAEP & PSS), and SHA-256
"""

import os
import json
import base64
import hashlib
from typing import Tuple, Optional, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def compute_sha256(data: bytes) -> str:
    """Computes SHA-256 cryptographic hash of data and returns hex string."""
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def compute_sha256_bytes(data: bytes) -> bytes:
    """Computes SHA-256 cryptographic digest as raw bytes."""
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.digest()


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[str, str]:
    """
    Generates an RSA Keypair (2048-bit).
    Returns (private_key_pem, public_key_pem) as strings.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    return private_pem, public_pem


def load_private_key(private_pem: str, password: Optional[str] = None):
    """Loads an RSA private key object from PEM string."""
    pwd_bytes = password.encode('utf-8') if password else None
    return serialization.load_pem_private_key(
        private_pem.encode('utf-8'),
        password=pwd_bytes
    )


def load_public_key(public_pem: str):
    """Loads an RSA public key object from PEM string."""
    return serialization.load_pem_public_key(
        public_pem.encode('utf-8')
    )


def generate_aes_key() -> bytes:
    """Generates a cryptographically secure 256-bit (32 bytes) random AES key."""
    return os.urandom(32)


def aes_encrypt(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    """
    Encrypts plaintext using AES-256-GCM.
    Returns: (nonce + ciphertext_with_tag, nonce)
    AESGCM encrypt() appends the 16-byte authentication tag to the ciphertext.
    Nonce is 12 bytes.
    """
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext_with_tag, nonce


def aes_decrypt(ciphertext_with_tag: bytes, key: bytes, nonce: bytes) -> bytes:
    """
    Decrypts ciphertext using AES-256-GCM.
    Verifies authentication tag; raises exception if tampered.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext_with_tag, None)


def rsa_encrypt_aes_key(aes_key: bytes, recipient_public_pem: str) -> bytes:
    """
    Encrypts 256-bit AES session key using Recipient's RSA Public Key with OAEP padding.
    """
    public_key = load_public_key(recipient_public_pem)
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def rsa_decrypt_aes_key(encrypted_aes_key: bytes, recipient_private_pem: str, password: Optional[str] = None) -> bytes:
    """
    Decrypts AES session key using Recipient's RSA Private Key with OAEP padding.
    """
    private_key = load_private_key(recipient_private_pem, password)
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key


def sign_data(data: bytes, sender_private_pem: str, password: Optional[str] = None) -> bytes:
    """
    Generates a Digital Signature for data using Sender's RSA Private Key.
    Uses PSS padding with SHA-256.
    """
    private_key = load_private_key(sender_private_pem, password)
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(data: bytes, signature: bytes, sender_public_pem: str) -> bool:
    """
    Verifies Digital Signature using Sender's RSA Public Key.
    Returns True if authentic and untampered, False otherwise.
    """
    try:
        public_key = load_public_key(sender_public_pem)
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derives a 256-bit AES key from a password string using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode('utf-8'))


def encrypt_private_key(private_pem: str, password: str, salt: bytes) -> str:
    """Encrypts private key PEM with user password-derived AES key for database safe-keeping."""
    key = derive_key_from_password(password, salt)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, private_pem.encode('utf-8'), None)
    payload = nonce + encrypted
    return base64.b64encode(payload).decode('utf-8')


def decrypt_private_key(encrypted_payload_b64: str, password: str, salt: bytes) -> str:
    """Decrypts private key PEM using user password-derived AES key."""
    payload = base64.b64decode(encrypted_payload_b64.encode('utf-8'))
    nonce = payload[:12]
    ciphertext = payload[12:]
    key = derive_key_from_password(password, salt)
    aesgcm = AESGCM(key)
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    return decrypted.decode('utf-8')


def create_hybrid_package(
    file_bytes: bytes,
    filename: str,
    sender_username: str,
    sender_private_pem: str,
    recipient_username: str,
    recipient_public_pem: str,
) -> Dict[str, Any]:
    """
    Executes the Complete Innovative Hybrid Cryptographic Workflow:
    1. Computes SHA-256 of plaintext file.
    2. Signs SHA-256 hash using Sender's RSA Private Key (Digital Signature).
    3. Generates random 256-bit AES session key.
    4. Encrypts file using AES-256-GCM.
    5. Encrypts AES session key using Recipient's RSA-2048 Public Key.
    6. Assembles self-contained cryptographic package.
    """
    # Step 1: Hashing
    sha256_hash = compute_sha256(file_bytes)

    # Step 2: Sender Authentication (Digital Signature over file content)
    signature = sign_data(file_bytes, sender_private_pem)

    # Step 3 & 4: Symmetric Encryption
    aes_session_key = generate_aes_key()
    ciphertext_with_tag, nonce = aes_encrypt(file_bytes, aes_session_key)

    # Step 5: Asymmetric Key Wrapping
    encrypted_aes_key = rsa_encrypt_aes_key(aes_session_key, recipient_public_pem)

    package = {
        "format": "HCP-v1.0 (Hybrid Cryptographic Package)",
        "metadata": {
            "filename": filename,
            "file_size": len(file_bytes),
            "sender": sender_username,
            "recipient": recipient_username,
            "hash_algorithm": "SHA-256",
            "symmetric_cipher": "AES-256-GCM",
            "asymmetric_cipher": "RSA-2048-OAEP",
            "signature_scheme": "RSA-2048-PSS-SHA256"
        },
        "crypto": {
            "sha256_checksum": sha256_hash,
            "sender_signature_b64": base64.b64encode(signature).decode('utf-8'),
            "encrypted_aes_key_b64": base64.b64encode(encrypted_aes_key).decode('utf-8'),
            "aes_nonce_b64": base64.b64encode(nonce).decode('utf-8'),
            "ciphertext_b64": base64.b64encode(ciphertext_with_tag).decode('utf-8'),
        }
    }
    return package


def decrypt_and_verify_hybrid_package(
    package: Dict[str, Any],
    recipient_private_pem: str,
    sender_public_pem: str
) -> Dict[str, Any]:
    """
    Decrypts and validates the Hybrid Cryptographic Package:
    1. Decrypts AES key using Recipient's RSA Private Key.
    2. Decrypts ciphertext using recovered AES key & nonce.
    3. Verifies SHA-256 digest of decrypted data.
    4. Verifies Sender's Digital Signature using Sender's RSA Public Key.
    """
    result = {
        "success": False,
        "filename": package["metadata"]["filename"],
        "plaintext_bytes": None,
        "sha256_match": False,
        "signature_valid": False,
        "calculated_sha256": None,
        "expected_sha256": package["crypto"]["sha256_checksum"],
        "error_message": None
    }

    try:
        encrypted_aes_key = base64.b64decode(package["crypto"]["encrypted_aes_key_b64"])
        nonce = base64.b64decode(package["crypto"]["aes_nonce_b64"])
        ciphertext_with_tag = base64.b64decode(package["crypto"]["ciphertext_b64"])
        signature = base64.b64decode(package["crypto"]["sender_signature_b64"])
        expected_hash = package["crypto"]["sha256_checksum"]

        # Step 1: Recover AES key
        try:
            aes_session_key = rsa_decrypt_aes_key(encrypted_aes_key, recipient_private_pem)
        except Exception as e:
            result["error_message"] = f"Unauthorized Access / RSA Key Error: Unable to decrypt AES session key with provided private key. ({str(e)})"
            return result

        # Step 2: Decrypt file payload
        try:
            decrypted_bytes = aes_decrypt(ciphertext_with_tag, aes_session_key, nonce)
        except Exception as e:
            result["error_message"] = "Ciphertext Tamper Detected! AES-GCM Authentication Tag mismatch (data was modified in transit)."
            return result

        # Step 3: Verify Integrity with SHA-256
        calculated_hash = compute_sha256(decrypted_bytes)
        result["calculated_sha256"] = calculated_hash
        result["sha256_match"] = (calculated_hash.lower() == expected_hash.lower())

        # Step 4: Verify Sender Authentication with RSA Signature
        result["signature_valid"] = verify_signature(decrypted_bytes, signature, sender_public_pem)

        if result["sha256_match"] and result["signature_valid"]:
            result["success"] = True
            result["plaintext_bytes"] = decrypted_bytes
        else:
            if not result["sha256_match"]:
                result["error_message"] = f"Integrity check failed: Computed SHA-256 ({calculated_hash[:16]}...) does not match expected ({expected_hash[:16]}...)."
            elif not result["signature_valid"]:
                result["error_message"] = "Sender Authentication Failed: Digital signature does not match sender's public key!"

    except Exception as e:
        result["error_message"] = f"Decryption/Verification failure: {str(e)}"

    return result


def tamper_package_ciphertext(package: Dict[str, Any]) -> Dict[str, Any]:
    """Tamper demonstration: flips 1 byte in the ciphertext."""
    tampered = json.loads(json.dumps(package))
    raw_cipher = base64.b64decode(tampered["crypto"]["ciphertext_b64"])
    if len(raw_cipher) > 16:
        # Flip a bit in the middle of ciphertext
        mutable = bytearray(raw_cipher)
        mutable[len(mutable) // 2] ^= 0xFF
        tampered["crypto"]["ciphertext_b64"] = base64.b64encode(bytes(mutable)).decode('utf-8')
    return tampered


def tamper_package_signature(package: Dict[str, Any]) -> Dict[str, Any]:
    """Tamper demonstration: corrupts the digital signature."""
    tampered = json.loads(json.dumps(package))
    raw_sig = base64.b64decode(tampered["crypto"]["sender_signature_b64"])
    mutable = bytearray(raw_sig)
    mutable[0] ^= 0xAA
    tampered["crypto"]["sender_signature_b64"] = base64.b64encode(bytes(mutable)).decode('utf-8')
    return tampered
