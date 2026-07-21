"""Tests for the image (PNG LSB) steganography method.

Run with: python -m pytest tests/test_steg_img.py
Requires Pillow (soft dep in steg.py). CI installs it via requirements.txt.
"""
import io
import os
import random

import pytest

from steg import img_capacity, img_encode, img_decode, hide, reveal, hide_img, reveal_img


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


# ---------------------------------------------------------------------------
# hide_img / reveal_img — high-level encrypt+encode / decode+decrypt
# ---------------------------------------------------------------------------

def test_hide_img_reveal_img_round_trip():
    cover = _make_png_bytes(64, 64)
    secret = b"meet at dawn at the docks"
    stego = hide_img(secret, "horse staple", cover)
    assert reveal_img(stego, "horse staple") == secret


def test_reveal_img_no_payload_raises():
    cover = _make_png_bytes(16, 16)  # natural PNG, no LSB payload -> decode empty
    with pytest.raises(ValueError, match="no hidden message"):
        reveal_img(cover, "pw")


def test_reveal_img_wrong_password_returns_invalidtoken():
    from cryptography.fernet import InvalidToken
    cover = _make_png_bytes(64, 64)
    stego = hide_img(b"the eagle flies at midnight", "right", cover)
    with pytest.raises(InvalidToken):
        reveal_img(stego, "wrong")


# ---------------------------------------------------------------------------
# CLI: encode -m img / decode -m img via binary file paths
# ---------------------------------------------------------------------------

import sys
import tempfile
import io  # already imported above

from steg import main


def _run_cli_img(argv):
    """Call main(argv) for img CLI (no stdin). Returns (rc, stdout, stderr)."""
    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        rc = main(argv)
        return rc, sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr


def test_cli_encode_decode_img_via_file():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.png")
        stego_path = os.path.join(tmp, "stego.png")
        with open(cover_path, "wb") as f:
            f.write(_make_png_bytes(64, 64))
        rc, _, err = _run_cli_img([
            "encode", "-m", "img", "-p", "mypw",
            "-s", "top secret image payload",
            "-c", cover_path, "-o", stego_path,
        ])
        assert rc == 0, f"encode failed: {err}"
        # stego should be a real PNG
        from PIL import Image
        Image.open(stego_path).verify()
        rc, out, err = _run_cli_img([
            "decode", "-m", "img", "-p", "mypw",
            "-i", stego_path,
        ])
        assert rc == 0, f"decode failed: {err}"
        assert out == "top secret image payload"


def test_cli_encode_img_refuses_jpeg_output():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.png")
        with open(cover_path, "wb") as f:
            f.write(_make_png_bytes(32, 32))
        rc, _, err = _run_cli_img([
            "encode", "-m", "img", "-p", "pw", "-s", "secret",
            "-c", cover_path, "-o", os.path.join(tmp, "out.jpg"),
        ])
        assert rc == 2, f"expected rc=2 got {rc}, err={err}"
        assert ".jpg" in err or "png" in err, f"expected a png/jpg note in: {err}"


def test_cli_encode_img_wrong_password_returns_3():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.png")
        stego_path = os.path.join(tmp, "stego.png")
        with open(cover_path, "wb") as f:
            f.write(_make_png_bytes(64, 64))
        rc, _, _ = _run_cli_img([
            "encode", "-m", "img", "-p", "right",
            "-s", "secret", "-c", cover_path, "-o", stego_path,
        ])
        assert rc == 0
        rc, out, err = _run_cli_img([
            "decode", "-m", "img", "-p", "wrong", "-i", stego_path,
        ])
        assert rc == 3
        assert "wrong password" in err or "corrupted" in err


def test_cli_encode_img_cover_too_small_returns_2():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.png")
        with open(cover_path, "wb") as f:
            f.write(_make_png_bytes(2, 2))  # tiny
        rc, _, err = _run_cli_img([
            "encode", "-m", "img", "-p", "pw",
            "-s", "x" * 50,  # payload > capacity
            "-c", cover_path, "-o", os.path.join(tmp, "stego.png"),
        ])
        assert rc == 2
        assert "cover too small" in err


# ---------------------------------------------------------------------------
# detect -m img / analyze(img) steganalysis (no password needed)
# ---------------------------------------------------------------------------

from steg import analyze as _analyze_img


def test_analyze_img_reads_declared_length_without_password():
    cover = _make_png_bytes(80, 80)
    stego = hide_img(b"a real secret here", "pw", cover)
    result = _analyze_img(stego, "img")
    assert result["method"] == "img"
    assert result["declared_length"] is not None
    # declared length equals the ciphertext byte length, NOT the plaintext
    ct = encrypt_msg_for_test(b"a real secret here", "pw")
    assert result["declared_length"] == len(ct)


def encrypt_msg_for_test(msg, pw):
    from steg import encrypt_message
    return encrypt_message(msg, pw)


def test_analyze_img_on_plain_png_returns_zero_payload():
    cover = _make_png_bytes(64, 64)  # solid color, all LSBs = 0
    result = _analyze_img(cover, "img")
    # For img, "payload_chars" is the count of bits the decoder reads that are
    # non-natural — here it's 0 because every LSB is 0, treated as declared_length 0
    # with no payload bytes. (Same convention as text analyze where empty means
    # "no readable length header". For img we set declared_length=None when the
    # header reads 0 bytes, matching the text "no payload found" semantics.)
    assert result["declared_length"] is None
    assert result["header_corrupted"] is False
    assert "lsb_distribution" in result
    assert result["suspicious"] is False  # zero or unreadable header, no payload


def test_analyze_img_marks_stego_suspicious():
    """A payload-bearing image's LSBs differ from a natural photo: the
    ciphertext bits are uniform-pseudo-random while natural LSBs are too,
    but our length header is highly structured (mostly zeros - typical
    Fernet payloads are short relative to cover capacity). The simplest
    honest signal: LSBs of a payload region are different from LSBs of
    an unused region.
    """
    cover = _make_png_bytes(128, 128)
    stego = hide_img(b"a real payload here ok", "pw", cover)
    result = _analyze_img(stego, "img")
    assert result["declared_length"] is not None
    assert result["suspicious"] is True
    assert "reason" in result


def test_analyze_img_rejects_non_bytes():
    with pytest.raises(TypeError):
        _analyze_img("not bytes", "img")


def test_analyze_img_rejects_bad_png():
    with pytest.raises(ValueError):
        _analyze_img(b"not a png at all", "img")


def test_analyze_img_rejects_unknown_method():
    with pytest.raises(ValueError):
        _analyze_img(b"\x89PNG\r", "bogus")


# ---------------------------------------------------------------------------
# CLI: detect -m img
# ---------------------------------------------------------------------------

def test_cli_detect_img_reads_length_without_password():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.png")
        stego_path = os.path.join(tmp, "stego.png")
        with open(cover_path, "wb") as f:
            f.write(_make_png_bytes(80, 80))
        rc, _, err = _run_cli_img([
            "encode", "-m", "img", "-p", "pw",
            "-s", "hidden image secret",
            "-c", cover_path, "-o", stego_path,
        ])
        assert rc == 0, f"encode failed: {err}"
        rc, out, err = _run_cli_img(["detect", "-m", "img", "-i", stego_path])
        assert rc == 0  # declared_length readable
        assert "declared" in out or "bytes" in out


def test_cli_detect_img_on_plain_png_exits_2():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.png")
        with open(cover_path, "wb") as f:
            f.write(_make_png_bytes(64, 64))
        rc, out, err = _run_cli_img(["detect", "-m", "img", "-i", cover_path])
        assert rc == 2



