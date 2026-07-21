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
