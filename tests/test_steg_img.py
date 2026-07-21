"""Tests for the image (PNG LSB) steganography method.

Run with: python -m pytest tests/test_steg_img.py
Requires Pillow (soft dep in steg.py). CI installs it via requirements.txt.
"""
import io
import os
import random

import pytest

from steg import img_capacity, img_encode, img_decode, hide, reveal


# ---------------------------------------------------------------------------
# helpers for building cover PNGs in-memory (no binary fixtures in git)
# ---------------------------------------------------------------------------

def _make_png_bytes(width, height, mode="RGB", fill=0):
    """Build a small PNG of solid color, return its PNG bytes."""
    from PIL import Image
    img = Image.new(mode, (width, height), fill)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# capacity helper (no Pillow needed)
# ---------------------------------------------------------------------------

def test_img_capacity_rgb():
    # width*height*3 channels // 8 bits/byte, minus 4-byte length header
    assert img_capacity(256, 256) == (256 * 256 * 3) // 8 - 4


def test_img_capacity_rectangular():
    assert img_capacity(100, 50) == (100 * 50 * 3) // 8 - 4


def test_img_capacity_negative_dim_raises():
    with pytest.raises(ValueError):
        img_capacity(-1, 10)
    with pytest.raises(ValueError):
        img_capacity(10, -1)


def test_img_capacity_zero_dim_raises():
    # zero-size image can't hold anything; signal as ValueError so the
    # caller path (cover too small) gets a single error class to catch
    with pytest.raises(ValueError):
        img_capacity(0, 10)
    with pytest.raises(ValueError):
        img_capacity(10, 0)


def test_img_capacity_non_int_raises():
    with pytest.raises(TypeError):
        img_capacity(1.5, 10)
    with pytest.raises(TypeError):
        img_capacity(10, "10")


# ---------------------------------------------------------------------------
# img_encode / img_decode round-trips (need Pillow)
# ---------------------------------------------------------------------------

def test_img_round_trip_basic():
    cover = _make_png_bytes(64, 64)
    stego = img_encode(b"hello world", cover)
    assert img_decode(stego) == b"hello world"


def test_img_round_trip_rgb_at_capacity_edge():
    # payload exactly fills capacity
    w = h = 50
    cover = _make_png_bytes(w, h)
    cap = img_capacity(w, h)
    payload = bytes(range(cap % 256)) * (cap // 256) + bytes(cap % 256)
    payload = payload[:cap]
    stego = img_encode(payload, cover)
    assert img_decode(stego) == payload


def test_img_cover_too_small_raises():
    cover = _make_png_bytes(2, 2)
    # capacity tiny (~0 bytes); any real payload exceeds it
    payload = b"x" * 10
    with pytest.raises(ValueError, match="cover too small"):
        img_encode(payload, cover)


def test_img_rgba_preserves_alpha():
    cover = _make_png_bytes(32, 32, mode="RGBA", fill=(1, 2, 3, 200))
    stego = img_encode(b"payload bytes here", cover)
    assert img_decode(stego) == b"payload bytes here"
    # verify alpha channel bits are unchanged
    from PIL import Image
    a_orig = list(Image.open(io.BytesIO(cover)).getdata())
    a_steg = list(Image.open(io.BytesIO(stego)).getdata())
    assert [px[3] for px in a_orig] == [px[3] for px in a_steg]


def test_img_zero_payload_round_trip():
    cover = _make_png_bytes(16, 16)
    stego = img_encode(b"", cover)
    assert img_decode(stego) == b""


def test_img_stego_looks_like_cover_channel_bytes_preserved():
    # stego has same dimensions and the high 7 bits of each channel byte
    # differ only in LSBs (we only touch LSBs)
    from PIL import Image
    cover = _make_png_bytes(40, 40, fill=(64, 128, 192))
    stego = img_encode(b"some really real payload bytes", cover)
    c = list(Image.open(io.BytesIO(cover)).getdata())
    s = list(Image.open(io.BytesIO(stego)).getdata())
    assert len(c) == len(s)
    for cpx, spx in zip(c, s):
        for ch in range(3):
            assert cpx[ch] >> 1 == spx[ch] >> 1, "non-LSB bits changed"


def test_img_random_fuzz_round_trip():
    random.seed(2026)
    for _ in range(20):
        w = random.randint(8, 80)
        h = random.randint(8, 80)
        cap = img_capacity(w, h)
        n = random.randint(0, cap)
        payload = bytes(random.randint(0, 255) for _ in range(n))
        cover = _make_png_bytes(w, h)
        stego = img_encode(payload, cover)
        assert img_decode(stego) == payload, f"failed for {w}x{h} payload={n} bytes"


def test_img_not_png_bytes_raises():
    with pytest.raises(ValueError):
        img_decode(b"this is not a png")


def test_img_truncated_returns_empty():
    # corrupt the LSB stream by zeroing the FIRST half of pixels' LSBs so
    # the length header is unreadable. We can't just trim trailing PNG
    # bytes — Pillow decodes the pixel stream fine without the trailing
    # chunks — and zeroing the tail of a small image can leave the whole
    # payload intact if it fits in the front half. Truncate the front.
    from PIL import Image
    cover = _make_png_bytes(16, 16)
    stego = img_encode(b"a long enough payload here", cover)
    img = Image.open(io.BytesIO(stego))
    img.load()
    pixels = list(img.getdata())
    cut = len(pixels) // 2
    # zero out LSBs of the first half — destroys the length header
    truncated = [
        (px[0] & 0xFE, px[1] & 0xFE, px[2] & 0xFE) for px in pixels[:cut]
    ] + pixels[cut:]
    img.putdata(truncated)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    assert img_decode(buf.getvalue()) == b""

