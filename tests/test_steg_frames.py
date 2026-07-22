"""Tests for the frames (PNG sequence LSB) steganography method.

Run with: python -m pytest tests/test_steg_frames.py
Requires Pillow (soft dep in steg.py). CI installs it via requirements.txt.
"""
import io
import os
import random
import tempfile

import pytest

from steg import (
    frames_capacity,
    frames_encode, frames_decode,
    img_capacity,
)


# ---------------------------------------------------------------------------
# helpers for building cover PNG dirs in-memory (no binary fixtures in git)
# ---------------------------------------------------------------------------

def _make_png_bytes(width, height, mode="RGB", fill=0):
    """Build a small PNG of solid color, return its PNG bytes."""
    from PIL import Image
    img = Image.new(mode, (width, height), fill)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _make_frames_dir(tmp, nframes, width=32, height=32, fill=0):
    """Write nframes identical PNGs into tmp/frame000.png..frameNNN.png.
    Returns the dir path.
    """
    d = os.path.join(tmp, "frames")
    os.makedirs(d)
    for i in range(nframes):
        path = os.path.join(d, f"frame{i:03d}.png")
        with open(path, "wb") as f:
            f.write(_make_png_bytes(width, height, fill=fill))
    return d


# ---------------------------------------------------------------------------
# capacity helper
# ---------------------------------------------------------------------------

def test_frames_capacity_single_frame():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_frames_dir(tmp, 1, 32, 32)
        cap = frames_capacity(d)
        expected = img_capacity(32, 32)  # single frame = same as img
        assert cap == expected


def test_frames_capacity_multi_frame():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_frames_dir(tmp, 5, 32, 32)
        cap = frames_capacity(d)
        # shared length header subtracted once, not per frame
        expected = 5 * (32 * 32 * 3) // 8 - 4
        assert cap == expected


def test_frames_capacity_non_dir_raises():
    with pytest.raises(ValueError, match="not a directory"):
        frames_capacity("/no/such/dir/ever")


def test_frames_capacity_empty_dir_raises():
    with tempfile.TemporaryDirectory() as tmp:
        d = os.path.join(tmp, "empty")
        os.makedirs(d)
        with pytest.raises(ValueError, match="no PNG"):
            frames_capacity(d)


# ---------------------------------------------------------------------------
# frames_encode / frames_decode round-trips
# ---------------------------------------------------------------------------

def test_frames_round_trip_single_frame():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_frames_dir(tmp, 1, 64, 64)
        payload = b"hello frames"
        result = frames_encode(payload, d)
        # result is a list of (filename, bytes) tuples
        assert len(result) == 1
        assert result[0][0] == "frame000.png"
        decoded = frames_decode({name: data for name, data in result})
        assert decoded == payload


def test_frames_round_trip_multi_frame():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_frames_dir(tmp, 3, 64, 64)
        payload = b"a longer payload that spans multiple frames for real"
        result = frames_encode(payload, d)
        assert len(result) == 3
        decoded = frames_decode({name: data for name, data in result})
        assert decoded == payload


def test_frames_round_trip_empty_payload():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_frames_dir(tmp, 2, 32, 32)
        result = frames_encode(b"", d)
        decoded = frames_decode({name: data for name, data in result})
        assert decoded == b""


def test_frames_capacity_edge_round_trip():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_frames_dir(tmp, 2, 64, 64)
        cap = frames_capacity(d)
        # cap includes space for the 4-byte length prefix; data bytes = cap - 4
        n = cap - 4
        payload = bytes(range(256)) * (n // 256) + bytes(n % 256)
        payload = payload[:n]
        result = frames_encode(payload, d)
        decoded = frames_decode({name: data for name, data in result})
        assert decoded == payload


def test_frames_cover_too_small_raises():
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_frames_dir(tmp, 1, 4, 4)  # tiny: 4*4*3//8 - 4 = 2
        with pytest.raises(ValueError, match="cover too small"):
            frames_encode(b"x" * 50, d)


def test_frames_non_uniform_dims_raises():
    with tempfile.TemporaryDirectory() as tmp:
        d = os.path.join(tmp, "mixed")
        os.makedirs(d)
        # frame 0 = 32x32, frame 1 = 64x64 — non-uniform
        with open(os.path.join(d, "frame000.png"), "wb") as f:
            f.write(_make_png_bytes(32, 32))
        with open(os.path.join(d, "frame001.png"), "wb") as f:
            f.write(_make_png_bytes(64, 64))
        with pytest.raises(ValueError, match="uniform"):
            frames_encode(b"test", d)


def test_frames_not_a_dir_raises():
    with pytest.raises((ValueError, FileNotFoundError)):
        frames_encode(b"test", "/no/such/dir")


def test_frames_random_fuzz():
    random.seed(2028)
    for _ in range(10):
        nframes = random.randint(1, 4)
        w = random.randint(16, 64)
        h = random.randint(16, 64)
        with tempfile.TemporaryDirectory() as tmp:
            d = _make_frames_dir(tmp, nframes, w, h)
            cap = frames_capacity(d)
            n = random.randint(0, min(cap, 200))
            payload = bytes(random.randint(0, 255) for _ in range(n))
            result = frames_encode(payload, d)
            decoded = frames_decode({name: data for name, data in result})
            assert decoded == payload, (
                f"failed for {nframes} frames {w}x{h} payload={n} bytes"
            )


def test_frames_only_lsb_changes():
    """Verify high bits of every channel byte preserved — only LSB touched."""
    from PIL import Image
    with tempfile.TemporaryDirectory() as tmp:
        d = _make_frames_dir(tmp, 2, 32, 32)
        # read original cover pixels for comparison
        cover_pixels = list(Image.open(
            io.BytesIO(_make_png_bytes(32, 32, fill=0)
        )).getdata())
        payload = b"some payload bytes here for real"
        result = frames_encode(payload, d)
        for fname, data in result:
            img = Image.open(io.BytesIO(data))
            img.load()
            for cpx, spx in zip(cover_pixels, img.getdata()):
                for ch in range(3):
                    assert cpx[ch] >> 1 == spx[ch] >> 1, (
                        f"non-LSB bits changed: {cpx[ch]} -> {spx[ch]}"
                    )
