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
# Method: image (PNG LSB)
# Payload bits become the LSB of consecutive RGB channel bytes, walked in
# scan order (row-major, R->G->B per pixel). Alpha is skipped so transparency
# stays identical. Pillow is a SOFT import: text-only users don't need it.
# ---------------------------------------------------------------------------

def img_capacity(width: int, height: int) -> int:
    """Bytes of ciphertext an image of given dims can hide via RGB-channel LSB.

    3 channel bytes per pixel, one bit each, minus the 4-byte length header.
    Raises ValueError on non-positive dims, TypeError on non-int input.
    """
    if not isinstance(width, int) or isinstance(width, bool):
        raise TypeError("width must be int")
    if not isinstance(height, int) or isinstance(height, bool):
        raise TypeError("height must be int")
    if width <= 0 or height <= 0:
        raise ValueError(f"dims must be positive, got {width}x{height}")
    return (width * height * 3) // 8 - 4


# ---------------------------------------------------------------------------
# Steganalysis helper: detect payload + read declared length WITHOUT password.
# Demonstrates the boundary: steganography hides content, not existence.
# Uses the same bit readers as the encoders; payload chars survive identifying.
# ---------------------------------------------------------------------------


def analyze(text: str, method: str) -> dict:
    """Report on whether `text` carries a hidden payload via `method`.

    Returns a dict with keys:
      method              - the method passed in
      payload_chars      - how many payload characters were found
      payload_byte_count - floor(payload_chars / 8), what would be decoded
      declared_length     - length read from the 4-byte header (int or None)
      header_corrupted    - bool: header bits were present but produced a
                            length that exceeds the available payload bytes
    No password required. Does not decrypt.
    """
    if method not in ("ws", "zw"):
        raise ValueError(f"unknown method: {method!r}")
    if not isinstance(text, str):
        raise TypeError("text must be str")

    if method == "zw":
        bits = "".join(_ZW_CHAR_TO_BIT[ch] for ch in text if ch in _PAYLOAD_ZW_CHARS)
    else:  # ws
        bits = ""
        for line in text.split("\n"):
            trailing = ""
            for ch in reversed(line):
                if ch == " ":
                    trailing = "0" + trailing
                elif ch == "\t":
                    trailing = "1" + trailing
                else:
                    break
            bits += trailing

    payload_chars = len(bits)
    payload_byte_count = payload_chars // 8

    if payload_chars < 32:
        return {
            "method": method,
            "payload_chars": payload_chars,
            "payload_byte_count": payload_byte_count,
            "declared_length": None,
            "header_corrupted": False,
        }

    declared = int(bits[:32], 2)
    header_corrupted = declared * 8 > (payload_chars - 32)
    return {
        "method": method,
        "payload_chars": payload_chars,
        "payload_byte_count": payload_byte_count,
        "declared_length": declared,
        "header_corrupted": header_corrupted,
    }


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
import json
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


def _print_analysis(result: dict, json_output: bool) -> None:
    """Human (default) or JSON line for the analyze() result."""
    if json_output:
        print(json.dumps(result))
        return
    if result["payload_chars"] == 0:
        print(f"[{result['method']}] no payload characters found")
        return
    declared = result["declared_length"]
    if declared is None:
        print(f"[{result['method']}] {result['payload_chars']} payload chars - "
              f"{result['payload_byte_count']} bytes encoded, length header "
              "not readable")
        return
    note = " (header looks corrupted: declared length exceeds payload bytes)" \
        if result["header_corrupted"] else ""
    print(f"[{result['method']}] {result['payload_chars']} payload chars - "
          f"{result['payload_byte_count']} bytes encoded, declared "
          f"{declared} bytes payload{note}")


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
    dec.add_argument("--analyze", action="store_true",
                     help="only report what the stego text carries; do not "
                          "decrypt. Exits 0 if a payload header is readable, "
                          "2 if none. Does not require the password to be "
                          "correct.")

    det = sub.add_parser("detect",
                         help="steganalysis: detect hidden payload WITHOUT the "
                              "password. Reads the declared length header.")
    det.add_argument("-m", "--method", choices=["ws", "zw"], required=True,
                      help="ws = whitespace, zw = zero-width Unicode")
    det.add_argument("-i", "--input", default="-",
                     help="input text to analyze (default: stdin)")
    det.add_argument("--json", action="store_true",
                     help="emit machine-readable JSON instead of human text")
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
        if args.analyze:
            # Report payload without decryption. Password is irrelevant here,
            # but argparse still required it on the route - tolerate either way.
            try:
                result = analyze(stego, args.method)
            except (ValueError, TypeError) as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            _print_analysis(result, json_output=False)
            return 0 if result["declared_length"] is not None else 2
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

    if args.command == "detect":
        text = _read_text(args.input)
        try:
            result = analyze(text, args.method)
        except (ValueError, TypeError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        _print_analysis(result, json_output=args.json)
        return 0 if result["declared_length"] is not None else 2

    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    sys.exit(main())
