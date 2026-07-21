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
    if "\t" in cover:
        # Existing tabs would be misread as payload bits on decode.
        raise ValueError("cover text must not contain tabs")
    # Trailing whitespace on any non-empty line would be misread as payload.
    # A trailing newline is fine (it's just a line separator).
    for i, line in enumerate(cover.split("\n")):
        if line != line.rstrip(" \t"):
            raise ValueError(
                f"cover text line {i} has trailing whitespace, "
                "would be misread as payload on decode"
            )
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


# ---------------------------------------------------------------------------
# Method: zero-width Unicode
# Payload bits become U+200B (0) or U+200C (1) inserted after the first
# visible character of the cover. The decoder scans the whole text and reads
# every zero-width character regardless of position.
# ---------------------------------------------------------------------------

_ZWS = "\u200b"   # zero-width space     -> bit 0
_ZWNJ = "\u200c"  # zero-width non-joiner -> bit 1
_ZW_CHAR_TO_BIT = {_ZWS: "0", _ZWNJ: "1"}
_BIT_TO_ZW_CHAR = {"0": _ZWS, "1": _ZWNJ}
# chars we recognize as payload on decode; other zero-width chars are ignored
_PAYLOAD_ZW_CHARS = frozenset(_ZW_CHAR_TO_BIT)


def zw_encode(data: bytes, cover: str) -> str:
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not isinstance(cover, str):
        raise TypeError("cover must be str")
    if _PAYLOAD_ZW_CHARS & set(cover):
        raise ValueError("cover text already contains payload zero-width chars")
    payload = _length_prefix(data)
    bits = _bytes_to_bits(payload)
    zws = "".join(_BIT_TO_ZW_CHAR[b] for b in bits)
    if not cover:
        return zws
    # insert all payload chars after the first character; placement is cosmetic
    # because the decoder reads ALL zw chars regardless of position.
    # ponytail: cluster after char[0] is detectable by steganalysis. Distribute
    # evenly across the cover for resistance if needed.
    return cover[0] + zws + cover[1:]


def zw_decode(text: str) -> bytes:
    if not isinstance(text, str):
        raise TypeError("text must be str")
    bits = "".join(_ZW_CHAR_TO_BIT[ch] for ch in text if ch in _PAYLOAD_ZW_CHARS)
    if len(bits) < 32:
        return b""
    try:
        return _read_length_prefixed(bits)
    except ValueError:
        return b""


# ---------------------------------------------------------------------------
# High-level convenience wrappers (encrypt+encode, decode+decrypt in one call)
# ---------------------------------------------------------------------------

def hide(secret: bytes, password: str, cover: str, method: str) -> str:
    """Encrypt then stego-encode. method is 'ws' or 'zw'."""
    ct = encrypt_message(secret, password)
    if method == "ws":
        return ws_encode(ct, cover)
    if method == "zw":
        return zw_encode(ct, cover)
    raise ValueError(f"unknown method: {method!r}")


def reveal(stego_text: str, password: str, method: str) -> bytes:
    """Stego-decode then decrypt. Returns the original secret bytes."""
    if method == "ws":
        ct = ws_decode(stego_text)
    elif method == "zw":
        ct = zw_decode(stego_text)
    else:
        raise ValueError(f"unknown method: {method!r}")
    if not ct:
        raise ValueError("no hidden message found in input")
    return decrypt_message(ct, password)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

import argparse
import sys


def _read_text(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def _write_text(path: str, text: str) -> None:
    if path == "-":
        sys.stdout.write(text)
    else:
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="steg",
        description="Hide and extract secret messages in plain text using "
                    "whitespace or zero-width Unicode steganography.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encode", help="hide a secret message in cover text")
    enc.add_argument("-m", "--method", choices=["ws", "zw"], required=True,
                      help="ws = whitespace (space/tab at end of lines), "
                           "zw = zero-width Unicode chars")
    enc.add_argument("-p", "--password", required=True, help="encryption password")
    enc.add_argument("-s", "--secret", required=True, help="secret message text to hide")
    enc.add_argument("-c", "--cover", default="-",
                      help="cover text file (default: stdin)")
    enc.add_argument("-o", "--output", default="-",
                      help="output file for stego text (default: stdout)")

    dec = sub.add_parser("decode", help="extract a secret message from stego text")
    dec.add_argument("-m", "--method", choices=["ws", "zw"], required=True,
                      help="ws = whitespace, zw = zero-width Unicode")
    dec.add_argument("-p", "--password", required=True, help="decryption password")
    dec.add_argument("-i", "--input", default="-",
                     help="input stego text (default: stdin)")
    dec.add_argument("-o", "--output", default="-",
                     help="output file for secret (default: stdout)")

    # ponytail: skipped - analyze subcommand to detect whether a text contains
    # hidden stego payload without the password. Add when needed.
    return parser


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "encode":
        cover = _read_text(args.cover)
        try:
            stego = hide(args.secret.encode("utf-8"), args.password, cover, args.method)
        except (ValueError, TypeError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        _write_text(args.output, stego)
        return 0

    if args.command == "decode":
        stego = _read_text(args.input)
        try:
            secret = reveal(stego, args.password, args.method)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        except InvalidToken:
            print("error: wrong password or corrupted payload", file=sys.stderr)
            return 3
        _write_text(args.output, secret.decode("utf-8"))
        return 0

    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    sys.exit(main())
