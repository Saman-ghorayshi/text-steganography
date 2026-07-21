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


import struct


def _bytes_to_bits(data: bytes) -> str:
    return "".join(f"{byte:08b}" for byte in data)


def _bits_to_bytes(bits: str) -> bytes:
    # pad up to byte boundary with zeros (trailing partial byte is meaningless)
    pad = len(bits) % 8
    if pad:
        bits = bits + "0" * (8 - pad)
    return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))


def _length_prefix(data: bytes) -> bytes:
    if len(data) > 0xFFFFFFFF:
        raise ValueError("payload too large for 4-byte length header")
    return struct.pack(">I", len(data)) + data


def _read_length_prefixed(bits: str) -> bytes:
    """Read a 4-byte big-endian length prefix from a bit string then that many bytes."""
    if len(bits) < 32:
        raise ValueError("not enough bits for length header")
    length = int(bits[:32], 2)
    needed = 32 + length * 8
    if len(bits) < needed:
        raise ValueError(
            f"declared {length} bytes but only have {(len(bits)-32)//8} bytes of payload"
        )
    payload_bits = bits[32:needed]
    return _bits_to_bytes(payload_bits)


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


# ---------------------------------------------------------------------------
# Method: whitespace (SNOW-style)
# Each payload bit becomes a trailing space (0) or tab (1) on a line of cover.
# ---------------------------------------------------------------------------


def ws_encode(data: bytes, cover: str) -> str:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not isinstance(cover, str):
        raise TypeError("cover must be str")
    if "\t" in cover or cover != cover.rstrip(" \t\n"):
        # Existing trailing whitespace would be misread as payload bits on decode.
        raise ValueError("cover text must not contain tabs or trailing whitespace/blank lines")
    payload = _length_prefix(data)
    bits = _bytes_to_bits(payload)
    lines = cover.split("\n")
    # Each line gets at most one bit. Pad with empty lines if needed.
    while len(lines) < len(bits):
        lines.append("")
    for i, bit in enumerate(bits):
        lines[i] += "\t" if bit == "1" else " "
    return "\n".join(lines)


def ws_decode(text: str) -> bytes:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    lines = text.split("\n")
    bits = ""
    for line in lines:
        # Walk backwards from end of line; the trailing whitespace encodes bits
        # in order last-written = least-significant, so we prepend each bit to
        # build the chunk in the correct left-to-right order for this line.
        trailing = ""
        for ch in reversed(line):
            if ch == " ":
                trailing = "0" + trailing
            elif ch == "\t":
                trailing = "1" + trailing
            else:
                break
        bits += trailing
    if len(bits) < 32:
        return b""
    try:
        return _read_length_prefixed(bits)
    except ValueError:
        return b""
