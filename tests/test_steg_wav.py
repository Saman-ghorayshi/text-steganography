"""Tests for the audio (WAV 16-bit LSB) steganography method.

Run with: python -m pytest tests/test_steg_wav.py
Uses only the stdlib `wave` and `struct` — no new dependency.
"""
import io
import os
import random
import struct
import wave

import pytest

from steg import (
    wav_capacity,
    wav_encode, wav_decode,
    hide_wav, reveal_wav,
    analyze as _analyze_wav,
)


# ---------------------------------------------------------------------------
# helpers for building cover WAVs in-memory (no binary fixtures in git)
# ---------------------------------------------------------------------------

def _make_wav_bytes(nframes, nchannels=1, sampwidth=2, framerate=8000,
                    sample_fill=0):
    """Build a small 16-bit PCM WAV with solid-amplitude samples. Returns WAV bytes."""
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(nchannels)
        w.setsampwidth(sampwidth)
        w.setframerate(framerate)
        # build sample frames: each sample = sampwidth bytes of `sample_fill`
        sample = (struct.pack("<h", sample_fill)
                  if sampwidth == 2 else
                  bytes([sample_fill & 0xFF]) * sampwidth)
        # for multi-channel, repeat the sample per frame nchannels times
        frame = sample * nchannels
        w.writeframes(frame * nframes)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# capacity helper (no wave import needed)
# ---------------------------------------------------------------------------

def test_wav_capacity_mono():
    # one bit per sample, one sample per frame mono
    # nframes bits // 8 bits_per_byte, minus 4-byte length header
    assert wav_capacity(nframes=8000, nchannels=1) == 8000 // 8 - 4


def test_wav_capacity_stereo():
    # 2 channels = 2 samples per frame = 2 bits per frame
    assert wav_capacity(nframes=8000, nchannels=2) == (8000 * 2) // 8 - 4


def test_wav_capacity_negative_raises():
    with pytest.raises(ValueError):
        wav_capacity(-1, 1)
    with pytest.raises(ValueError):
        wav_capacity(1, -1)


def test_wav_capacity_zero_raises():
    with pytest.raises(ValueError):
        wav_capacity(0, 1)
    with pytest.raises(ValueError):
        wav_capacity(1, 0)


def test_wav_capacity_non_int_raises():
    with pytest.raises(TypeError):
        wav_capacity(1.5, 1)
    with pytest.raises(TypeError):
        wav_capacity(1, "1")


def test_wav_capacity_bool_rejected():
    # bool is a subclass of int but is not a real count; reject for parity with img
    with pytest.raises(TypeError):
        wav_capacity(True, 1)
    with pytest.raises(TypeError):
        wav_capacity(1, True)


# ---------------------------------------------------------------------------
# wav_encode / wav_decode round-trips
# ---------------------------------------------------------------------------

def test_wav_round_trip_basic_mono():
    cover = _make_wav_bytes(nframes=1000, nchannels=1)
    stego = wav_encode(b"hello wav world", cover)
    assert wav_decode(stego) == b"hello wav world"


def test_wav_round_trip_stereo():
    cover = _make_wav_bytes(nframes=1000, nchannels=2)
    stego = wav_encode(b"stereo secret payload here", cover)
    assert wav_decode(stego) == b"stereo secret payload here"


def test_wav_round_trip_empty_payload():
    cover = _make_wav_bytes(nframes=500, nchannels=1)
    stego = wav_encode(b"", cover)
    assert wav_decode(stego) == b""


def test_wav_capacity_edge_round_trip():
    # 4-byte length prefix sits inside; data of cap-4 bytes exactly fits
    nframes = 2000
    nchannels = 1
    cover = _make_wav_bytes(nframes, nchannels)
    cap = wav_capacity(nframes, nchannels)
    n = cap - 4
    payload = bytes((i % 256) for i in range(n))
    stego = wav_encode(payload, cover)
    assert wav_decode(stego) == payload
    # one byte over capacity must raise politely, not silently corrupt
    with pytest.raises(ValueError, match="cover too small|too short"):
        wav_encode(payload + b"\x00", cover)


def test_wav_cover_too_short_raises():
    cover = _make_wav_bytes(nframes=10, nchannels=1)  # ~1 byte capacity
    with pytest.raises(ValueError, match="cover too small|too short|capacity"):
        wav_encode(b"x" * 50, cover)


def test_wav_non_16bit_raises():
    # 8-bit PCM is unsigned; we refuse anything that isn't 16-bit signed PCM
    cover = _make_wav_bytes(nframes=500, nchannels=1, sampwidth=1)
    with pytest.raises(ValueError, match="16"):
        wav_encode(b"some payload", cover)


def test_wav_stego_only_lsb_changes():
    # verify high bits of every sample preserved — only LSB touched
    cover = _make_wav_bytes(nframes=400, nchannels=1, sample_fill=1234)
    stego = wav_encode(b"a payload of bytes here", cover)
    c_frames = wave.open(io.BytesIO(cover), "rb").readframes(400)
    s_frames = wave.open(io.BytesIO(stego), "rb").readframes(400)
    assert len(c_frames) == len(s_frames)
    # each 2-byte sample: high bits preserved, only LSB differs
    for i in range(0, len(c_frames), 2):
        c_samp = struct.unpack("<h", c_frames[i:i+2])[0]
        s_samp = struct.unpack("<h", s_frames[i:i+2])[0]
        assert c_samp >> 1 == s_samp >> 1, (
            f"non-LSB bits changed at sample {i//2}: {c_samp} -> {s_samp}"
        )


def test_wav_round_trip_random_fuzz():
    random.seed(2027)
    for _ in range(15):
        nframes = random.randint(80, 2000)
        nchannels = random.choice([1, 2])
        cap = wav_capacity(nframes, nchannels)
        n = random.randint(0, max(0, cap - 4))
        payload = bytes(random.randint(0, 255) for _ in range(n))
        cover = _make_wav_bytes(nframes, nchannels, sample_fill=random.randint(-32768, 32767))
        stego = wav_encode(payload, cover)
        assert wav_decode(stego) == payload, (
            f"failed for {nframes}frames/{nchannels}ch payload={n} bytes"
        )


def test_wav_truncated_returns_empty():
    # zero out LSBs of the first half of samples — destroys the length header
    cover = _make_wav_bytes(nframes=400, nchannels=1)
    stego = wav_encode(b"a long payload to span enough samples here", cover)
    w = wave.open(io.BytesIO(stego), "rb")
    nframes = w.getnframes()
    frames = w.readframes(nframes)
    # clear LSB of first half of samples
    out = bytearray(frames)
    n_samples = len(out) // 2
    for i in range(n_samples // 2):
        out[i * 2 + 1] &= 0xFE  # clear the LSB of the low byte... wait
    # actually the LSB of a 16-bit signed sample is bit 0 of the LOW byte (little-endian)
    # clear bit 0 of the low byte (= LSB of the sample) for first half
    out = bytearray(frames)
    for i in range(n_samples // 2):
        out[i * 2] &= 0xFE  # low byte's bit 0 = sample LSB
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w2:
        w2.setnchannels(w.getnchannels())
        w2.setsampwidth(w.getsampwidth())
        w2.setframerate(w.getframerate())
        w2.writeframes(bytes(out))
    assert wav_decode(buf.getvalue()) == b""


def test_wav_not_wav_bytes_raises():
    with pytest.raises(ValueError):
        wav_decode(b"this is not a wav file at all")


# ---------------------------------------------------------------------------
# hide_wav / reveal_wav — encrypt+encode / decode+decrypt
# ---------------------------------------------------------------------------

def test_hide_wav_reveal_wav_round_trip():
    cover = _make_wav_bytes(nframes=2000, nchannels=1)
    secret = b"the eagle flies at midnight"
    stego = hide_wav(secret, "horse staple", cover)
    assert reveal_wav(stego, "horse staple") == secret


def test_reveal_wav_no_payload_raises():
    cover = _make_wav_bytes(nframes=500, nchannels=1)
    with pytest.raises(ValueError, match="no hidden message"):
        reveal_wav(cover, "pw")


def test_reveal_wav_wrong_password_returns_invalidtoken():
    from cryptography.fernet import InvalidToken
    cover = _make_wav_bytes(nframes=2000, nchannels=1)
    stego = hide_wav(b"the eagle flies at midnight", "right", cover)
    with pytest.raises(InvalidToken):
        reveal_wav(stego, "wrong")


# ---------------------------------------------------------------------------
# CLI: encode -m wav / decode -m wav via binary file paths
# ---------------------------------------------------------------------------

import sys
import tempfile

from steg import main


def _run_cli_wav(argv):
    old_stdout, old_stderr = sys.stdout, sys.stderr
    sys.stdout = io.StringIO()
    sys.stderr = io.StringIO()
    try:
        rc = main(argv)
        return rc, sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr


def test_cli_encode_decode_wav_via_file():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.wav")
        stego_path = os.path.join(tmp, "stego.wav")
        with open(cover_path, "wb") as f:
            f.write(_make_wav_bytes(nframes=2000, nchannels=1))
        rc, _, err = _run_cli_wav([
            "encode", "-m", "wav", "-p", "mypw",
            "-s", "top secret audio payload",
            "-c", cover_path, "-o", stego_path,
        ])
        assert rc == 0, f"encode failed: {err}"
        # stego should be a real WAV (parseable by wave)
        with wave.open(stego_path, "rb") as w:
            assert w.getnframes() == 2000
        rc, out, err = _run_cli_wav([
            "decode", "-m", "wav", "-p", "mypw",
            "-i", stego_path,
        ])
        assert rc == 0, f"decode failed: {err}"
        assert out == "top secret audio payload"


def test_cli_encode_wav_refuses_mp3_output():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.wav")
        with open(cover_path, "wb") as f:
            f.write(_make_wav_bytes(nframes=500, nchannels=1))
        rc, _, err = _run_cli_wav([
            "encode", "-m", "wav", "-p", "pw", "-s", "secret",
            "-c", cover_path, "-o", os.path.join(tmp, "out.mp3"),
        ])
        assert rc == 2, f"expected rc=2 got {rc}, err={err}"
        assert "mp3" in err.lower() or "wav" in err.lower()


def test_cli_encode_wav_wrong_password_returns_3():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.wav")
        stego_path = os.path.join(tmp, "stego.wav")
        with open(cover_path, "wb") as f:
            f.write(_make_wav_bytes(nframes=1000, nchannels=1))
        rc, _, _ = _run_cli_wav([
            "encode", "-m", "wav", "-p", "right",
            "-s", "secret", "-c", cover_path, "-o", stego_path,
        ])
        assert rc == 0
        rc, _, err = _run_cli_wav([
            "decode", "-m", "wav", "-p", "wrong", "-i", stego_path,
        ])
        assert rc == 3
        assert "wrong password" in err or "corrupted" in err


def test_cli_encode_wav_cover_too_small_returns_2():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.wav")
        with open(cover_path, "wb") as f:
            f.write(_make_wav_bytes(nframes=20, nchannels=1))  # tiny
        rc, _, err = _run_cli_wav([
            "encode", "-m", "wav", "-p", "pw",
            "-s", "x" * 200,  # payload > capacity
            "-c", cover_path, "-o", os.path.join(tmp, "stego.wav"),
        ])
        assert rc == 2
        assert "cover too small" in err or "too short" in err or "capacity" in err


# ---------------------------------------------------------------------------
# detect -m wav / analyze(wav) steganalysis (no password needed)
# ---------------------------------------------------------------------------

def test_analyze_wav_reads_declared_length_without_password():
    cover = _make_wav_bytes(nframes=2000, nchannels=1)
    stego = hide_wav(b"a real audio secret here", "pw", cover)
    result = _analyze_wav(stego, "wav")
    assert result["method"] == "wav"
    assert result["declared_length"] is not None

    from steg import encrypt_message
    ct = encrypt_message(b"a real audio secret here", "pw")
    assert result["declared_length"] == len(ct)


def test_analyze_wav_on_plain_wav_returns_none():
    # solid zero amplitude: all LSBs = 0 -> declared length 0 -> None
    cover = _make_wav_bytes(nframes=1000, nchannels=1, sample_fill=0)
    result = _analyze_wav(cover, "wav")
    assert result["declared_length"] is None
    assert result["header_corrupted"] is False
    assert "sample_lsb_distribution" in result
    assert result["suspicious"] is False


def test_analyze_wav_marks_stego_suspicious():
    cover = _make_wav_bytes(nframes=3000, nchannels=1, sample_fill=10000)
    stego = hide_wav(b"a real payload here ok", "pw", cover)
    result = _analyze_wav(stego, "wav")
    assert result["declared_length"] is not None
    assert result["suspicious"] is True
    assert "reason" in result and result["reason"]


def test_analyze_wav_rejects_non_bytes():
    with pytest.raises(TypeError):
        _analyze_wav("not bytes", "wav")


def test_analyze_wav_rejects_bad_wav():
    with pytest.raises(ValueError):
        _analyze_wav(b"not a wav at all", "wav")


def test_analyze_wav_rejects_unknown_method():
    with pytest.raises(ValueError):
        _analyze_wav(b"RIFF\x00", "bogus")


# ---------------------------------------------------------------------------
# CLI: detect -m wav
# ---------------------------------------------------------------------------

def test_cli_detect_wav_reads_length_without_password():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.wav")
        stego_path = os.path.join(tmp, "stego.wav")
        with open(cover_path, "wb") as f:
            f.write(_make_wav_bytes(nframes=2000, nchannels=1))
        rc, _, err = _run_cli_wav([
            "encode", "-m", "wav", "-p", "pw",
            "-s", "hidden audio secret",
            "-c", cover_path, "-o", stego_path,
        ])
        assert rc == 0, f"encode failed: {err}"
        rc, out, err = _run_cli_wav(["detect", "-m", "wav", "-i", stego_path])
        assert rc == 0  # declared_length readable
        assert "declared" in out or "bytes" in out


def test_cli_detect_wav_on_plain_wav_exits_2():
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.wav")
        with open(cover_path, "wb") as f:
            f.write(_make_wav_bytes(nframes=1000, nchannels=1, sample_fill=0))
        rc, _, _ = _run_cli_wav(["detect", "-m", "wav", "-i", cover_path])
        assert rc == 2


def test_cli_detect_wav_json():
    import json as _json
    with tempfile.TemporaryDirectory() as tmp:
        cover_path = os.path.join(tmp, "cover.wav")
        stego_path = os.path.join(tmp, "stego.wav")
        with open(cover_path, "wb") as f:
            f.write(_make_wav_bytes(nframes=2000, nchannels=1))
        rc, _, _ = _run_cli_wav([
            "encode", "-m", "wav", "-p", "pw",
            "-s", "jsecret", "-c", cover_path, "-o", stego_path,
        ])
        assert rc == 0
        rc, out, _ = _run_cli_wav(["detect", "-m", "wav", "--json", "-i", stego_path])
        assert rc == 0
        r = _json.loads(out.strip().splitlines()[0])
        assert r["method"] == "wav"
        assert r["declared_length"] is not None
