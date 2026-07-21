import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken


def _derive_key(password: str) -> bytes:
    """Derive a Fernet-compatible key from a password via SHA-256.

    ponytail: no salt, no PBKDF2. An attacker with the stego text can brute
    the password faster than with a salted KDF. Fernet's HMAC still rejects
    wrong passwords cleanly. Upgrade to PBKDF2+random salt if the threat
    model includes offline brute force.
    """
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_message(message: bytes, password: str) -> bytes:
    if not isinstance(message, bytes):
        raise TypeError("message must be bytes")
    if not isinstance(password, str):
        raise TypeError("password must be str")
    key = _derive_key(password)
    return Fernet(key).encrypt(message)


def decrypt_message(ciphertext: bytes, password: str) -> bytes:
    if not isinstance(ciphertext, bytes):
        raise TypeError("ciphertext must be bytes")
    if not isinstance(password, str):
        raise TypeError("password must be str")
    key = _derive_key(password)
    return Fernet(key).decrypt(ciphertext)
