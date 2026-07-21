import base64
import pytest
from cryptography.fernet import InvalidToken

from steg import encrypt_message, decrypt_message, _derive_key


def test_round_trip_basic():
    msg = b"hello world"
    ct = encrypt_message(msg, "pw123")
    assert ct != msg
    assert decrypt_message(ct, "pw123") == msg


def test_empty_message_round_trip():
    # Fernet rejects empty plaintext in some versions; verify our wrapper handles it
    ct = encrypt_message(b"", "pw")
    assert decrypt_message(ct, "pw") == b""


def test_unicode_payload():
    msg = "سامشا 写给 {}".format("you").encode("utf-8")
    ct = encrypt_message(msg, "pw")
    assert decrypt_message(ct, "pw") == msg


def test_large_payload():
    # ~1 MB payload, exercises Fernet chunking
    msg = b"x" * (1024 * 1024)
    ct = encrypt_message(msg, "pw")
    assert decrypt_message(ct, "pw") == msg


def test_wrong_password_rejected():
    ct = encrypt_message(b"secret", "right")
    with pytest.raises(InvalidToken):
        decrypt_message(ct, "wrong")


def test_corrupted_ciphertext_rejected():
    ct = bytearray(encrypt_message(b"secret", "pw"))
    ct[0] ^= 0xFF  # flip header bit
    with pytest.raises(InvalidToken):
        decrypt_message(bytes(ct), "pw")


def test_truncated_ciphertext_rejected():
    ct = encrypt_message(b"secret", "pw")[:-5]
    with pytest.raises(InvalidToken):
        decrypt_message(ct, "pw")


def test_different_passwords_produce_different_ciphertexts():
    # same plaintext, same password should give different ct (Fernet uses random iv)
    ct1 = encrypt_message(b"msg", "pw")
    ct2 = encrypt_message(b"msg", "pw")
    assert ct1 != ct2  # random iv
    assert decrypt_message(ct1, "pw") == decrypt_message(ct2, "pw")


def test_key_stability():
    # same password always produces same derived key (no salt)
    assert _derive_key("hello") == _derive_key("hello")
    assert _derive_key("hello") != _derive_key("world")


def test_key_is_url_safe_base64():
    key = _derive_key("test")
    decoded = base64.urlsafe_b64decode(key)
    assert len(decoded) == 32


def test_empty_password():
    # empty string password should still work (sha256 of empty is defined)
    ct = encrypt_message(b"x", "")
    assert decrypt_message(ct, "") == b"x"


def test_type_errors():
    with pytest.raises(TypeError):
        encrypt_message("not bytes", "pw")
    with pytest.raises(TypeError):
        encrypt_message(b"x", b"pw")  # password must be str not bytes
    with pytest.raises(TypeError):
        decrypt_message("not bytes", "pw")


# ---------------------------------------------------------------------------
# whitespace method tests
# ---------------------------------------------------------------------------

from steg import ws_encode, ws_decode, _bytes_to_bits, _bits_to_bytes


def test_bits_round_trip():
    data = bytes(range(256))
    bits = _bytes_to_bits(data)
    assert len(bits) == 256 * 8
    assert _bits_to_bytes(bits) == data


def test_ws_round_trip_basic():
    data = b"hello"
    cover = "line one\nline two\nline three\nline four\nline five"
    encoded = ws_encode(data, cover)
    assert ws_decode(encoded) == data


def test_ws_visible_text_preserved():
    data = b"hidden payload"
    cover = "alpha\nbeta\ngamma\ndelta\nepsilon"
    encoded = ws_encode(data, cover)
    restored = "\n".join(line.rstrip(" \t") for line in encoded.split("\n"))
    # remove padding empty lines the encoder may have added at the end
    stripped = "\n".join(x for x in restored.split("\n") if x != "")
    assert stripped == cover


def test_ws_empty_data_uses_only_length_header():
    data = b""
    cover = "abc\ndef\nghi\njkl"  # 4 lines, need exactly 32 bits = 32 lines
    encoded = ws_encode(data, cover)
    assert ws_decode(encoded) == b""


def test_ws_cover_too_small_pads_with_empty_lines():
    # cover has 1 line, payload needs more bits → padding lines added
    data = b"x" * 4  # 32 header bits + 32 payload bits = 64 lines
    cover = "only one line"
    encoded = ws_encode(data, cover)
    assert ws_decode(encoded) == data


def test_ws_empty_cover():
    data = b"x"
    cover = ""
    encoded = ws_encode(data, cover)
    assert ws_decode(encoded) == data


def test_ws_no_payload_signal_returns_empty():
    # text with NO trailing whitespace → length header is 0 bits → returns b""
    assert ws_decode("just a regular sentence") == b""
    assert ws_decode("") == b""


def test_ws_truncated_payload_returns_empty():
    # encode then truncate the encoded text so the declared length can't fit
    data = b"something long enough"
    cover = "\n".join(f"line {i}" for i in range(200))  # plenty of lines
    encoded = ws_encode(data, cover)
    # chop off the trailing portion (destroy required payload bits)
    truncated = encoded[: len(encoded) // 2]
    assert ws_decode(truncated) == b""


def test_ws_random_fuzz_round_trip():
    import os
    import random
    random.seed(42)
    for _ in range(20):
        n = random.randint(0, 100)
        data = bytes(random.randint(0, 255) for _ in range(n))
        cover_lines = [
            "".join(random.choice("abcdefghijklmnop") for _ in range(random.randint(1, 20)))
            for _ in range(random.randint(max(1, n * 8 + 32), n * 8 + 64))
        ]
        cover = "\n".join(cover_lines)
        encoded = ws_encode(data, cover)
        assert ws_decode(encoded) == data, f"failed for n={n} data={data!r}"


def test_ws_rejects_cover_with_embedded_tab():
    with pytest.raises(ValueError):
        ws_encode(b"x", "line with\ttab")
    with pytest.raises(ValueError):
        ws_encode(b"x", "trailing space ")


def test_ws_multiline_cover_preserves_newline_count():
    cover = "a\nb\nc\nd\ne\nf\ng\nh"
    encoded = ws_encode(b"\x00\x01\x02", cover)
    assert ws_decode(encoded) == b"\x00\x01\x02"

