import base64
import hashlib
import os

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


def _require_pil():
    try:
        from PIL import Image  # noqa: F401
        return Image
    except ImportError as e:
        raise ImportError(
            "image method requires Pillow: pip install Pillow"
        ) from e


def img_encode(data: bytes, cover_png: bytes) -> bytes:
    """Hide `data` in the LSBs of an RGB PNG. Returns new PNG bytes.

    RGB channels only (alpha untouched). Capacity = img_capacity(w, h).
    Raises ValueError if the cover is too small or `cover_png` is not a PNG.
    Raises ImportError with install hint if Pillow is unavailable.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    if not isinstance(cover_png, bytes):
        raise TypeError("cover_png must be bytes")
    Image = _require_pil()
    import io as _io

    try:
        img = Image.open(_io.BytesIO(cover_png))
    except Exception as e:
        raise ValueError(f"cover is not a readable image: {e}")
    img.load()

    # Convert to whatever mode it's in; we keep mode but operate on RGB(A) list
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    pixels = list(img.getdata())
    has_alpha = img.mode == "RGBA"
    width, height = img.size
    capacity = (width * height * 3) // 8 - 4
    payload = _length_prefix(data)
    if len(payload) > capacity:
        raise ValueError(
            f"cover too small: need {len(payload)} bytes of LSB capacity, have {capacity}"
        )
    bits = _bytes_to_bits(payload)

    out = []
    bit_idx = 0
    for px in pixels:
        channels = list(px)
        # strip alpha if present so tuple length matches image mode
        if not has_alpha and len(channels) > 3:
            channels = channels[:3]
        # write into R, G, B only (alpha untouched on RGBA covers)
        for ch in range(3):
            if bit_idx < len(bits):
                channels[ch] = (channels[ch] & 0xFE) | (bits[bit_idx] == "1")
                bit_idx += 1
        out.append(tuple(channels))

    stego_img = Image.new(img.mode, img.size)
    stego_img.putdata(out)
    buf = _io.BytesIO()
    stego_img.save(buf, format="PNG")
    return buf.getvalue()


def img_decode(stego_png: bytes) -> bytes:
    """Recover the payload hidden by img_encode. Returns the bytes (empty on
    a malformed/empty payload so callers can signal 'no hidden message').
    """
    if not isinstance(stego_png, bytes):
        raise TypeError("stego_png must be bytes")
    Image = _require_pil()
    import io as _io

    try:
        img = Image.open(_io.BytesIO(stego_png))
    except Exception as e:
        raise ValueError(f"stego is not a readable image: {e}")
    img.load()
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    pixels = list(img.getdata())

    bits = ""
    for px in pixels:
        for ch in range(3):
            bits += str(px[ch] & 1)

    if len(bits) < 32:
        return b""
    declared = int(bits[:32], 2)
    needed = 32 + declared * 8
    if needed > len(bits):
        return b""  # truncated / corrupted
    return _bits_to_bytes(bits[32:needed])


# ---------------------------------------------------------------------------
# Method: audio (WAV 16-bit LSB)
# Each payload bit goes into the LSB of a 16-bit signed PCM sample. One bit
# per channel sample, walked in frame order, channels in order. Only 16-bit
# signed PCM is supported: 8-bit unsigned, 24/32-bit float or compressed
# WAVs (ADPCM, A-law) would mangle the payload. Pillow-style soft import
# is not needed because wave + struct are stdlib.
# ponytail: a real lossless-only codec panel (FLAC, ALAC) is academic; WAV
# 16-bit PCM is the only uncompressed portable format Python ships a reader
# for. Add wider format support when a real cover track in another format
# is actually supplied by someone.
# ---------------------------------------------------------------------------

def wav_capacity(nframes: int, nchannels: int) -> int:
    """Bytes of ciphertext a 16-bit PCM WAV can hide via sample-LSB.

    One bit per 16-bit sample, one sample per channel per frame. Capacity =
    (nframes * nchannels) bits // 8, minus the 4-byte length header.
    Raises ValueError on non-positive dims, TypeError on non-int (or bool) input.
    """
    if not isinstance(nframes, int) or isinstance(nframes, bool):
        raise TypeError("nframes must be int")
    if not isinstance(nchannels, int) or isinstance(nchannels, bool):
        raise TypeError("nchannels must be int")
    if nframes <= 0 or nchannels <= 0:
        raise ValueError(
            f"nframes and nchannels must be positive, got {nframes}/{nchannels}"
        )
    return (nframes * nchannels) // 8 - 4


def _wav_open(cover_bytes: bytes):
    """Open a WAV from bytes with the stdlib wave module. Raises ValueError
    on anything wave can't read (truncated, bad header, not a WAV at all).
    Returns the wave.Wave_read object so the caller can pull params + frames.
    """
    import io as _io
    import wave as _wave
    if not isinstance(cover_bytes, (bytes, bytearray)):
        raise TypeError("wav input must be bytes")
    try:
        return _wave.open(_io.BytesIO(cover_bytes), "rb")
    except _wave.Error as e:
        raise ValueError(f"not a readable WAV: {e}") from e


def wav_encode(data: bytes, cover_wav: bytes) -> bytes:
    """Hide `data` in the LSBs of a 16-bit signed PCM WAV. Returns new WAV bytes.

    One payload bit per 16-bit sample, walked in frame order, channels in
    order (L then R per frame for stereo). Refuses anything that isn't
    16-bit PCM (`sampwidth != 2`) because 8-bit is unsigned and the LSB math
    differs, and 24/32-bit float or compressed WAVs would mangle the payload.
    Raises ValueError if the cover is too small or `cover_wav` is not a WAV.
    """
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    w = _wav_open(cover_wav)
    nchannels = w.getnchannels()
    nframes = w.getnframes()
    sampwidth = w.getsampwidth()
    if sampwidth != 2:
        raise ValueError(
            f"only 16-bit signed PCM WAV supported (sampwidth=2), got sampwidth={sampwidth}"
        )
    capacity = wav_capacity(nframes, nchannels)
    payload = _length_prefix(data)
    if len(payload) > capacity:
        raise ValueError(
            f"cover too small: need {len(payload)} bytes of LSB capacity, "
            f"have {capacity}"
        )
    framerate = w.getframerate()
    frames = bytearray(w.readframes(nframes))
    w.close()
    # total 16-bit samples = len(frames) // 2 (sampwidth=2)
    n_samples = len(frames) // 2
    bits = _bytes_to_bits(payload)
    import struct as _struct
    # walk samples in order; write one payload bit into each sample's LSB
    for i in range(n_samples):
        if i >= len(bits):
            break
        offset = i * 2
        # unpack as UNSIGNED to avoid Python's arbitrary-precision &
        # turning negative signed samples into huge positive ints.
        u = _struct.unpack_from("<H", frames, offset)[0]
        u = (u & 0xFFFE) | (1 if bits[i] == "1" else 0)
        _struct.pack_into("<H", frames, offset, u)
    # rebuild the WAV with identical params + modified frames
    import io as _io
    import wave as _wave
    out = _io.BytesIO()
    with _wave.open(out, "wb") as wo:
        wo.setnchannels(nchannels)
        wo.setsampwidth(sampwidth)
        wo.setframerate(framerate)
        wo.writeframes(bytes(frames))
    return out.getvalue()


def wav_decode(stego_wav: bytes) -> bytes:
    """Recover the payload hidden by wav_encode. Returns the bytes (empty on
    a malformed/empty payload so callers can signal 'no hidden message').
    Raises ValueError if the input is not a readable WAV.
    """
    if not isinstance(stego_wav, (bytes, bytearray)):
        raise TypeError("stego_wav must be bytes")
    w = _wav_open(stego_wav)
    sampwidth = w.getsampwidth()
    if sampwidth != 2:
        w.close()
        raise ValueError(
            f"only 16-bit signed PCM WAV supported (sampwidth=2), got sampwidth={sampwidth}"
        )
    nframes = w.getnframes()
    frames = w.readframes(nframes)
    w.close()
    n_samples = len(frames) // 2
    import struct as _struct
    bits = []
    for i in range(n_samples):
        offset = i * 2
        # unsigned read — the LSB of the 16-bit value is the payload bit
        u = _struct.unpack_from("<H", frames, offset)[0]
        bits.append("1" if (u & 1) else "0")
    bitstr = "".join(bits)
    if len(bitstr) < 32:
        return b""
    declared = int(bitstr[:32], 2)
    if declared == 0:
        return b""
    needed = 32 + declared * 8
    if needed > len(bitstr):
        return b""  # truncated / corrupted
    return _bits_to_bytes(bitstr[32:needed])


# ---------------------------------------------------------------------------
# Steganalysis helper: detect payload + read declared length WITHOUT password.
# Demonstrates the boundary: steganography hides content, not existence.
# Uses the same bit readers as the encoders; payload chars survive identifying.
# ---------------------------------------------------------------------------


def _analyze_img(png_bytes) -> dict:
    """Steganalysis on a PNG: read LSB-payload length header and report an
    LSB-distribution snapshot. No password. 'suspicious' is intentionally
    conservative: a readable non-zero declared length that fits inside the
    image's LSB capacity is itself the steganographic signal — random LSB
    noise produces a declared length of 0 or a value > capacity. Real
    portfolios want a chi-square steganalyzer; this is the honest minimum.
    """
    if not isinstance(png_bytes, (bytes, bytearray)):
        raise TypeError("img analyze input must be bytes")
    if not isinstance(png_bytes, bytes):
        png_bytes = bytes(png_bytes)

    Image = _require_pil()
    import io as _io
    try:
        img = Image.open(_io.BytesIO(png_bytes))
    except Exception as e:
        raise ValueError(f"stego is not a readable image: {e}")
    img.load()
    if img.mode not in ("RGB", "RGBA"):
        img = img.convert("RGB")
    pixels = list(img.getdata())

    total_channels = 0
    ones = 0
    bits = ""
    for px in pixels:
        for ch in range(3):
            b = px[ch] & 1
            bits += str(b)
            total_channels += 1
            if b:
                ones += 1
    zeros = total_channels - ones
    pct_ones = ones / total_channels if total_channels else 0.0

    base = {
        "method": "img",
        "lsb_distribution": {
            "total_channels": total_channels,
            "ones": ones,
            "zeros": zeros,
            "pct_ones": round(pct_ones, 4),
        },
        "declared_length": None,
        "header_corrupted": False,
        "suspicious": False,
        "reason": None,
        # mirror text keys so generic _print_analysis can render summary fields
        "payload_chars": total_channels,
        "payload_byte_count": total_channels // 8,
    }

    if len(bits) < 32:
        return base
    declared = int(bits[:32], 2)
    total_bytes = (total_channels - 32) // 8
    if declared == 0:
        # an all-zero LSB header reads length 0 — no payload. Don't flag.
        base["declared_length"] = None  # treat like "no readable header"
        return base
    declared_fits = declared * 8 + 32 <= total_channels
    if not declared_fits:
        base["declared_length"] = declared
        base["header_corrupted"] = True
        base["suspicious"] = True
        base["reason"] = (
            f"declared {declared} bytes but image only stores {total_bytes} LSB bytes"
        )
        return base
    base["declared_length"] = declared
    base["suspicious"] = True
    base["reason"] = (
        f"LSB stream contains a readable length header declaring {declared} "
        f"bytes of payload that fits the image capacity "
        f"({total_bytes} LSB bytes) — random LSB noise would not"
    )
    return base


def _analyze_wav(wav_bytes) -> dict:
    """Steganalysis on a 16-bit PCM WAV: read sample-LSB length header and
    report the sample-LSB distribution. No password. 'suspicious' mirrors
    the img contract: a readable non-zero declared length that fits inside
    the WAV's sample LSB capacity is itself the steganographic signal —
    random LSB noise would not produce such a tight prefix. Real portfolios
    want a chi-square steganalyzer; this is the honest minimum.
    """
    if not isinstance(wav_bytes, (bytes, bytearray)):
        raise TypeError("wav analyze input must be bytes")
    if not isinstance(wav_bytes, bytes):
        wav_bytes = bytes(wav_bytes)

    w = _wav_open(wav_bytes)
    if w.getsampwidth() != 2:
        w.close()
        raise ValueError(
            f"only 16-bit signed PCM WAV supported (sampwidth=2), "
            f"got sampwidth={w.getsampwidth()}"
        )
    nframes = w.getnframes()
    nchannels = w.getnchannels()
    frames = w.readframes(nframes)
    w.close()

    total_samples = len(frames) // 2
    import struct as _struct
    ones = 0
    bits = []
    for i in range(total_samples):
        offset = i * 2
        u = _struct.unpack_from("<H", frames, offset)[0]
        b = u & 1
        bits.append("1" if b else "0")
        if b:
            ones += 1
    zeros = total_samples - ones
    pct_ones = ones / total_samples if total_samples else 0.0
    bitstr = "".join(bits)

    base = {
        "method": "wav",
        "sample_lsb_distribution": {
            "total_samples": total_samples,
            "ones": ones,
            "zeros": zeros,
            "pct_ones": round(pct_ones, 4),
        },
        "declared_length": None,
        "header_corrupted": False,
        "suspicious": False,
        "reason": None,
        # mirror the keys generic _print_analysis can render
        "payload_chars": total_samples,
        "payload_byte_count": total_samples // 8,
    }

    if len(bitstr) < 32:
        return base
    declared = int(bitstr[:32], 2)
    total_bytes = (total_samples - 32) // 8
    if declared == 0:
        base["declared_length"] = None
        return base
    declared_fits = declared * 8 + 32 <= total_samples
    if not declared_fits:
        base["declared_length"] = declared
        base["header_corrupted"] = True
        base["suspicious"] = True
        base["reason"] = (
            f"declared {declared} bytes but WAV only stores "
            f"{total_bytes} sample-LSB bytes"
        )
        return base
    base["declared_length"] = declared
    base["suspicious"] = True
    base["reason"] = (
        f"sample-LSB stream contains a readable length header declaring "
        f"{declared} bytes of payload that fits the WAV capacity "
        f"({total_bytes} sample-LSB bytes) — random LSB noise would not"
    )
    return base


def analyze(text, method: str) -> dict:
    """Report on whether `text` carries a hidden payload via `method`.

    For text methods (ws, zw), `text` is a str. For `method == 'img'`,
    `text` is the stego PNG bytes.

    Returns a dict with keys (text methods):
      method              - the method passed in
      payload_chars      - how many payload characters were found
      payload_byte_count - floor(payload_chars / 8), what would be decoded
      declared_length     - length read from the 4-byte header (int or None)
      header_corrupted    - bool: header bits were present but produced a
                            length that exceeds the available payload bytes
    For method == 'img' adds:
      lsb_distribution   - dict {total_channels, ones, zeros, pct_ones}
      suspicious         - bool: did the LSB stream look structured?
                           (readable non-zero declared length that fits the
                           image is, itself, the steganographic signal)
      reason             - str when suspicious is True, else None
    For method == 'wav' adds:
      sample_lsb_distribution - dict {total_samples, ones, zeros, pct_ones}
      suspicious         - bool: did the sample-LSB stream look structured?
      reason             - str when suspicious is True, else None
    No password required. Does not decrypt.
    """
    if method not in ("ws", "zw", "img", "wav"):
        raise ValueError(f"unknown method: {method!r}")

    if method == "img":
        return _analyze_img(text)
    if method == "wav":
        return _analyze_wav(text)

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
    """Encrypt then stego-encode (text methods). method is 'ws' or 'zw'."""
    ct = encrypt_message(secret, password)
    if method == "ws":
        return ws_encode(ct, cover)
    if method == "zw":
        return zw_encode(ct, cover)
    raise ValueError(f"unknown method: {method!r}")


def reveal(stego_text: str, password: str, method: str) -> bytes:
    """Stego-decode then decrypt (text methods). Returns original secret bytes."""
    if method == "ws":
        ct = ws_decode(stego_text)
    elif method == "zw":
        ct = zw_decode(stego_text)
    else:
        raise ValueError(f"unknown method: {method!r}")
    if not ct:
        raise ValueError("no hidden message found in input")
    return decrypt_message(ct, password)


# Image variants: cover and stego are bytes (PNG file bytes), not str.
def hide_img(secret: bytes, password: str, cover_png: bytes) -> bytes:
    """Encrypt then hide in a PNG cover. Returns stego PNG bytes."""
    ct = encrypt_message(secret, password)
    return img_encode(ct, cover_png)


def reveal_img(stego_png: bytes, password: str) -> bytes:
    """Decode an LSB-PNG payload then decrypt. Raises if stego carries nothing."""
    ct = img_decode(stego_png)
    if not ct:
        raise ValueError("no hidden message found in input")
    return decrypt_message(ct, password)


# Audio variants: cover and stego are bytes (WAV file bytes), not str.
def hide_wav(secret: bytes, password: str, cover_wav: bytes) -> bytes:
    """Encrypt then hide in a 16-bit PCM WAV cover. Returns stego WAV bytes."""
    ct = encrypt_message(secret, password)
    return wav_encode(ct, cover_wav)


def reveal_wav(stego_wav: bytes, password: str) -> bytes:
    """Decode an LSB-WAV payload then decrypt. Raises if stego carries nothing."""
    ct = wav_decode(stego_wav)
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


def _read_bytes(path: str) -> bytes:
    if path == "-":
        return getattr(sys.stdin, "buffer", sys.stdin).read()
    with open(path, "rb") as f:
        return f.read()


def _write_bytes(path: str, data: bytes) -> None:
    if path == "-":
        getattr(sys.stdout, "buffer", sys.stdout).write(data)
    else:
        with open(path, "wb") as f:
            f.write(data)


def _png_only(path: str) -> None:
    """Refuse any non-PNG output extension for the image method. JPEG/WebP
    would re-encode lossy and silently destroy the LSB payload — letting it
    through is a footgun, not a feature.
    """
    lower = path.lower()
    if lower != "-" and not (lower.endswith(".png") or os.path.basename(lower) == ""):
        raise ValueError(
            f"refusing non-PNG output {path!r}: lossy encoders (JPEG, WebP) "
            "would destroy the LSB payload"
        )


def _wav_only(path: str) -> None:
    """Refuse any non-WAV output extension for the audio method. MP3, AAC,
    OGG, and FLAC-conversion would re-encode lossy (or re-pack) and destroy
    the sample LSB payload — mirrors _png_only.
    """
    lower = path.lower()
    if lower != "-" and not (lower.endswith(".wav") or os.path.basename(lower) == ""):
        raise ValueError(
            f"refusing non-WAV output {path!r}: lossy encoders (MP3, AAC, OGG) "
            "would destroy the sample-LSB payload"
        )


def _print_analysis(result: dict, json_output: bool) -> None:
    """Human (default) or JSON line for the analyze() result."""
    if json_output:
        print(json.dumps(result))
        return
    if result["method"] == "img":
        _print_analysis_img(result)
        return
    if result["method"] == "wav":
        _print_analysis_wav(result)
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


def _print_analysis_img(result: dict) -> None:
    """Human render of an img analyze() result."""
    d = result["lsb_distribution"]
    print(f"[img] {d['total_channels']} LSB channel bits "
          f"({d['ones']} ones / {d['zeros']} zeros, "
          f"{d['pct_ones']*100:.2f}% ones)")
    if result["declared_length"] is None:
        if not result["suspicious"]:
            print("[img] no readable length header in LSB stream")
        return
    declared = result["declared_length"]
    note = " (header looks corrupted: declared length exceeds LSB capacity)" \
        if result["header_corrupted"] else ""
    flag = "SUSPICIOUS" if result["suspicious"] else "ok"
    print(f"[img] declared {declared} bytes payload{note} — {flag}")
    if result["reason"]:
        print(f"[img] reason: {result['reason']}")


def _print_analysis_wav(result: dict) -> None:
    """Human render of a wav analyze() result."""
    d = result["sample_lsb_distribution"]
    print(f"[wav] {d['total_samples']} sample LSB bits "
          f"({d['ones']} ones / {d['zeros']} zeros, "
          f"{d['pct_ones']*100:.2f}% ones)")
    if result["declared_length"] is None:
        if not result["suspicious"]:
            print("[wav] no readable length header in sample LSB stream")
        return
    declared = result["declared_length"]
    note = " (header looks corrupted: declared length exceeds sample-LSB capacity)" \
        if result["header_corrupted"] else ""
    flag = "SUSPICIOUS" if result["suspicious"] else "ok"
    print(f"[wav] declared {declared} bytes payload{note} — {flag}")
    if result["reason"]:
        print(f"[wav] reason: {result['reason']}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="steg",
        description="Hide and extract secret messages in plain text using "
                    "whitespace or zero-width Unicode steganography.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encode", help="hide a secret message in cover text")
    enc.add_argument("-m", "--method", choices=["ws", "zw", "img", "wav"], required=True,
                      help="ws = whitespace (space/tab at end of lines), "
                           "zw = zero-width Unicode chars, "
                           "img = PNG LSB in pixel channel bytes, "
                           "wav = 16-bit PCM WAV sample LSB")
    enc.add_argument("-p", "--password", required=True, help="encryption password")
    enc.add_argument("-s", "--secret", required=True, help="secret message text to hide")
    enc.add_argument("-c", "--cover", default="-",
                      help="cover text file or, for -m img, PNG cover path "
                           "(default: stdin)")
    enc.add_argument("-o", "--output", default="-",
                      help="output file for stego text/image (default: stdout). "
                           "For -m img, must end in .png; lossy formats are refused.")

    dec = sub.add_parser("decode", help="extract a secret message from stego text")
    dec.add_argument("-m", "--method", choices=["ws", "zw", "img", "wav"], required=True,
                      help="ws = whitespace, zw = zero-width, img = PNG LSB, "
                           "wav = 16-bit PCM WAV sample LSB")
    dec.add_argument("-p", "--password", required=True, help="decryption password")
    dec.add_argument("-i", "--input", default="-",
                     help="input stego text or, for -m img, stego PNG path "
                          "(default: stdin)")
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
    det.add_argument("-m", "--method", choices=["ws", "zw", "img", "wav"], required=True,
                      help="ws = whitespace, zw = zero-width, img = PNG LSB, "
                           "wav = 16-bit PCM WAV sample LSB")
    det.add_argument("-i", "--input", default="-",
                     help="input text to analyze (default: stdin)")
    det.add_argument("--json", action="store_true",
                     help="emit machine-readable JSON instead of human text")
    return parser


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "encode":
        try:
            if args.method == "img":
                _png_only(args.output)
                cover = _read_bytes(args.cover)
                stego = hide_img(args.secret.encode("utf-8"), args.password, cover)
                _write_bytes(args.output, stego)
            elif args.method == "wav":
                _wav_only(args.output)
                cover = _read_bytes(args.cover)
                stego = hide_wav(args.secret.encode("utf-8"), args.password, cover)
                _write_bytes(args.output, stego)
            else:
                cover = _read_text(args.cover)
                stego = hide(args.secret.encode("utf-8"), args.password, cover, args.method)
                _write_text(args.output, stego)
        except (ValueError, TypeError, ImportError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        return 0

    if args.command == "decode":
        if args.method in ("img", "wav") and args.analyze:
            try:
                data = _read_bytes(args.input)
                result = analyze(data, args.method)
            except (ValueError, TypeError, ImportError) as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            _print_analysis(result, json_output=False)
            return 0 if result["declared_length"] is not None else 2
        if args.method == "img":
            try:
                stego = _read_bytes(args.input)
            except OSError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            try:
                secret = reveal_img(stego, args.password)
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            except InvalidToken:
                print("error: wrong password or corrupted payload", file=sys.stderr)
                return 3
            _write_text(args.output, secret.decode("utf-8"))
            return 0
        if args.method == "wav":
            try:
                stego = _read_bytes(args.input)
            except OSError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            try:
                secret = reveal_wav(stego, args.password)
            except ValueError as e:
                print(f"error: {e}", file=sys.stderr)
                return 2
            except InvalidToken:
                print("error: wrong password or corrupted payload", file=sys.stderr)
                return 3
            _write_text(args.output, secret.decode("utf-8"))
            return 0

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
        try:
            if args.method in ("img", "wav"):
                data = _read_bytes(args.input)
            else:
                data = _read_text(args.input)
            result = analyze(data, args.method)
        except (ValueError, TypeError, ImportError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        _print_analysis(result, json_output=args.json)
        return 0 if result["declared_length"] is not None else 2

    parser.error(f"unknown command: {args.command}")


if __name__ == "__main__":
    sys.exit(main())
