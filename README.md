# text-steganography

Hide secret messages inside plain text using two steganography methods, with password-based encryption. The hidden bytes are AES-encrypted before encoding, so even if an attacker detects the payload, they cannot read the message without the password.

Live demo: https://samsha.github.io/text-steganography/

A self-contained browser demo (single HTML file, no dependencies, no backend) implements the same encryption and steganography in JavaScript using the Web Crypto API. Open the demo, hide a message in some cover text, send the result, and the recipient can extract it with the password.

## Methods

This tool implements two steganography techniques. Each has different robustness properties, so choose based on how the cover text will be transported.

### Zero-width Unicode

Insert invisible Unicode characters (`U+200B` and `U+200C`) into the cover text. The text looks identical to the naked eye. Each invisible character encodes one bit of payload.

- The cover text displays exactly as before - you cannot see the difference in any text editor.
- Survives copy-paste in most contexts (text files, emails, code comments, README files).
- Does not survive platforms that sanitize zero-width characters. WhatsApp, Discord, and some email clients strip them.
- The encoded text is a bit longer than the cover, but the extra characters are invisible.

### Whitespace (SNOW-style)

Append a trailing space (bit 0) or tab (bit 1) to the end of each line of the cover text. This is the technique used by `stegsnow` and similar tools.

- Each line gets exactly one bit encoded in its trailing whitespace.
- Survives text editors and most copy-paste. Does not survive tools that strip trailing whitespace (Markdown renderers, code formatters, `git diff` in some configs).
- Cover text needs at least one line per payload bit. Small covers get padded with empty lines, which is detectable.
- Tabs are visually distinct in many editors, so the encoding may be slightly visible.

## How it works

1. **Encrypt.** The secret message is encrypted with the password using Fernet, which provides AES-128-CBC plus HMAC-SHA256 authentication. The key is derived from the password via SHA-256. Fernet's random IV means the same message encrypted twice with the same password produces different ciphertext.
2. **Length-prefix.** A 4-byte big-endian length header is prepended to the ciphertext so the decoder knows how many bytes to read back. Without it, the decoder would read trailing whitespace or zero-width chars forever.
3. **Encode the bits.** The length prefix plus ciphertext is converted to a bit string. Each bit becomes either a space/tab (whitespace method) or a zero-width character (zero-width method), inserted into the cover text.
4. **Decode.** Reverse the pipeline: extract every trailing whitespace or zero-width character from the cover text, convert back to bits, read the length header, read the ciphertext bytes, decrypt with the password.

## Installation

```
pip install cryptography
```

Python 3.11 or newer. The only runtime dependency is `cryptography`. `pytest` is required for tests.

## Usage

Hide a secret message using zero-width characters:

```
echo "hello world" | python steg.py encode -m zw -p mypassword -s "the secret payload" -o encoded.txt
```

Extract it back:

```
python steg.py decode -m zw -p mypassword -i encoded.txt
```

Same operations with the whitespace method:

```
printf "line one\nline two\nline three\n" | python steg.py encode -m ws -p mypassword -s "the secret payload" -o encoded.txt
python steg.py decode -m ws -p mypassword -i encoded.txt
```

Use stdin/stdout by omitting the file arguments (or passing `-`):

```
python steg.py encode -m zw -p mypw -s "secret" < cover.txt > stego.txt
python steg.py decode -m zw -p mypw < stego.txt
```

Exit codes:
- `0` - success
- `2` - input error (bad cover text, no payload found, missing args)
- `3` - decryption failed (wrong password or corrupted payload)

## Using the library directly

```python
from steg import hide, reveal

# Hide
stego_text = hide(b"meet at dawn", "mypassword", cover_text, "zw")
# Stego text looks like cover_text, with invisible characters inserted

# Reveal
secret_bytes = reveal(stego_text, "mypassword", "zw")
print(secret_bytes.decode("utf-8"))  # "meet at dawn"
```

The two layers can also be used separately:

```python
from steg import encrypt_message, decrypt_message, zw_encode, zw_decode

ciphertext = encrypt_message(b"secret", "password")
stego = zw_encode(ciphertext, "cover text")
recovered = decrypt_message(zw_decode(stego), "password")
```

## Method comparison

| Property | zero-width | whitespace |
|---|---|---|
| Invisible to naked eye | Yes | No (trailing tabs visible in some editors) |
| Survives copy-paste | Yes | Yes |
| Survives whitespace stripping | Yes | No |
| Survives Unicode sanitizing | No | Yes |
| Cover text size requirement | None | At least one line per payload bit |
| Detectable by layperson | No | Possibly (trailing tab in some editors) |

Pick zero-width for text that will be read by humans and copy-pasted as text. Pick whitespace for contexts that strip zero-width characters but preserve trailing whitespace (raw text files, some source code, plain text email).

## Detection

Steganography hides bytes from the eye, not from statistical analysis. The browser demo includes a Detect tab that:

- Counts zero-width characters in the text - they never appear in normal prose, so any count above zero indicates a hidden payload.
- Counts trailing tabs across lines - trailing tabs are rare in normal text, and many lines with trailing tabs indicate a whitespace payload.
- Reads the declared length from the bit string as a length header without needing the password, so it can reveal how many payload bytes are hidden even without the key.

This demonstrates a fundamental property of LSB-style steganography: it hides content from humans, not from analysis tools. The password protects the message content, not the existence of the message.

## Tests

```
python -m pytest tests/ -v
```

The test suite includes round-trip tests, fuzz tests (random byte payloads across random cover sizes), edge cases (empty cover, empty payload, truncated payload, corrupted ciphertext, wrong password, Unicode cover text, 1 MB payloads), and end-to-end tests driving the CLI through `main()`.

## Limitations

- **Key derivation is SHA-256 without a salt.** An attacker who intercepts the stego text can brute-force the password faster than with PBKDF2. Fernet's HMAC still rejects wrong passwords cleanly. Upgrade to PBKDF2 with a random salt if brute-force resistance is part of the threat model.
- **Whitespace method needs one cover line per payload bit.** Small covers get padded with empty lines, which makes large payloads detectable by line count.
- **Zero-width method clusters all payload characters after the first character of the cover.** A statistical attacker could detect the cluster. Distributing them evenly across the cover would improve steganalysis resistance.
- **Neither method survives lossy transport.** Screenshots, OCR, text-to-speech, and some Markdown renderers destroy the payload.
- **Browser demo uses AES-GCM, not Fernet.** Fernet is Python-specific and has no JavaScript equivalent. The browser demo uses Web Crypto's AES-256-GCM with the same SHA-256 key derivation. Encoded text from the Python tool cannot be decoded by the browser demo and vice versa, but the same password works on both sides of each tool.

## Project layout

```
steg.py              tool and library (encryption + steganography, CLI, hide/reveal wrappers)
tests/test_steg.py   test suite
demo/index.html      self-contained browser demo
README.md
LICENSE
```

## Acknowledgments

The whitespace encoding scheme is the same idea used by Matthew Kwan's `stegsnow` (`SNOW`) - bits encoded as trailing spaces and tabs at the end of text lines. The zero-width Unicode technique is the same idea used by several open-source tools, including `pyUnicodeSteganography` and `ZW Steg`.

## License

MIT
