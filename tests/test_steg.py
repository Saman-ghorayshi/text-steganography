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


# ---------------------------------------------------------------------------
# zero-width method tests
# ---------------------------------------------------------------------------

from steg import zw_encode, zw_decode, _ZWS, _ZWNJ


def test_zw_round_trip_basic():
    data = b"test"
    cover = "hello world"
    encoded = zw_encode(data, cover)
    assert zw_decode(encoded) == data


def test_zw_invisible_to_naked_eye():
    data = b"secret message"
    cover = "plain text for cover"
    encoded = zw_encode(data, cover)
    # stripping payload chars should give back the cover text unchanged
    cleaned = encoded.replace(_ZWS, "").replace(_ZWNJ, "")
    assert cleaned == cover


def test_zw_empty_data_round_trip():
    data = b""
    cover = "anything"
    encoded = zw_encode(data, cover)
    assert zw_decode(encoded) == data


def test_zw_empty_cover():
    data = b"x"
    cover = ""
    encoded = zw_encode(data, cover)
    assert zw_decode(encoded) == data


def test_zw_no_payload_chars_returns_empty():
    # text with no zw chars → not enough bits for length header
    assert zw_decode("just a regular sentence") == b""
    assert zw_decode("") == b""


def test_zw_random_fuzz_round_trip():
    import random
    random.seed(1337)
    for _ in range(30):
        n = random.randint(0, 200)
        data = bytes(random.randint(0, 255) for _ in range(n))
        cover = "".join(random.choice("abcdefghijklmnop ") for _ in range(random.randint(0, 50)))
        encoded = zw_encode(data, cover)
        assert zw_decode(encoded) == data, f"failed for n={n} data={data!r}"


def test_zw_unicode_cover():
    # cover with non-ASCII chars, just exercises slicing on surrogate-free text
    data = b"hi"
    cover = "سلام 世界"
    encoded = zw_encode(data, cover)
    assert zw_decode(encoded) == data


def test_zw_truncated_returns_empty():
    data = b"a pretty long payload here" * 5
    cover = "cover"
    encoded = zw_encode(data, cover)
    # strip the last 80% of zw chars → declared length won't fit
    # we strip by removing trailing chars; since payload is in the middle,
    # we just cut the encoded text in half. zw chars at the end fall off.
    half = encoded[: len(encoded) // 2]
    assert zw_decode(half) == b""


def test_zw_preserves_cover_when_payload_chars_stripped():
    cover = "the actual text"
    encoded = zw_encode(b"data", cover)
    stripped = "".join(c for c in encoded if c not in (_ZWS, _ZWNJ))
    assert stripped == cover


def test_zw_other_zero_width_chars_ignored_on_decode():
    # cover could accidentally contain U+200D (zw joiner), U+FEFF (BOM) etc.
    # decoder only reads U+200B and U+200C as payload
    import os
    data = os.urandom(32)
    cover = f"prefix\u200d suffix"  # has a ZWJ we don't use
    encoded = zw_encode(data, cover)
    decoded = zw_decode(encoded)
    assert decoded == data
    # the ZWJ in cover must survive (we don't strip it, we just ignore on decode)
    assert "\u200d" in encoded


def test_zw_rejects_cover_with_payload_chars():
    with pytest.raises(ValueError):
        zw_encode(b"x", "cover with " + _ZWS)
    with pytest.raises(ValueError):
        zw_encode(b"x", "cover with " + _ZWNJ)


def test_zw_ends_with_first_char_intact():
    cover = "abcdef"
    encoded = zw_encode(b"x", cover)
    # cover[0] should still be the first char of encoded
    assert encoded[0] == cover[0]


# ---------------------------------------------------------------------------
# end-to-end: encrypt + stego + extract + decrypt for both methods
# ---------------------------------------------------------------------------

from steg import encrypt_message, decrypt_message


def test_end_to_end_zw():
    secret = "meet at dawn at the docks"
    password = "horse battery staple"
    cover = "hi mom, the weather is fine today. love you."
    ct = encrypt_message(secret.encode("utf-8"), password)
    stego = zw_encode(ct, cover)
    # stego text looks identical to cover when zw chars are stripped
    assert "".join(c for c in stego if c not in (_ZWS, _ZWNJ)) == cover
    # decode + decrypt recovers the secret
    recovered_ct = zw_decode(stego)
    assert decrypt_message(recovered_ct, password) == secret.encode("utf-8")


def test_end_to_end_ws():
    secret = "meet at dawn at the docks"
    password = "horse battery staple"
    cover = "\n".join(f"line {i}" for i in range(500))
    ct = encrypt_message(secret.encode("utf-8"), password)
    stego = ws_encode(ct, cover)
    recovered_ct = ws_decode(stego)
    assert decrypt_message(recovered_ct, password) == secret.encode("utf-8")


def test_end_to_end_wrong_password_fails():
    secret = "the answer is 42"
    cover = "some cover" * 50
    ct = encrypt_message(secret.encode("utf-8"), "right")
    stego = zw_encode(ct, cover)
    recovered_ct = zw_decode(stego)
    with pytest.raises(InvalidToken):
        decrypt_message(recovered_ct, "wrong")


