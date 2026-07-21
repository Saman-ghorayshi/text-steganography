# text-steganography

Hide secret messages inside plain text using two steganography methods, with password-based encryption. Messages can only be extracted with the correct password.

Live demo: (link after Pages is enabled)

## Methods

- **Zero-width Unicode**: invisible characters (U+200B, U+200C) inserted into the cover text. The text looks identical to the naked eye. Survives most text editors and copy-paste. Does not survive platforms that sanitize zero-width characters (WhatsApp, Discord, some email clients).
- **Whitespace (SNOW-style)**: tabs and spaces appended to the end of each line of the cover text, encoding bits. Survives most text editors and copy-paste. Does not survive tools that strip trailing whitespace (Markdown renderers, code formatters, some chat apps).

Both methods encrypt the secret message with the password before hiding it. Without the password, the hidden bytes are ciphertext that cannot be read.

## How it works

1. The secret message is encrypted with the password using Fernet (AES-128-CBC + HMAC-SHA256). The key is derived from the password with SHA-256.
2. The ciphertext bytes are converted to a bit string with a 4-byte length header prepended (so the decoder knows how many bytes to read back).
3. The bits are encoded into the cover text using one of the two methods:
   - Whitespace: each line gets one bit appended as either a space (0) or a tab (1).
   - Zero-width: each bit becomes either U+200B (0) or U+200C (1), inserted after the first character of the cover text.
4. Decoding reverses the process: extract the bits from the cover text, read the length header, read the ciphertext bytes, decrypt with the password.

## Installation

```
pip install cryptography
```

Python 3.11 or newer. Only the `cryptography` package is required.

## Usage

Hide a secret message using zero-width characters:

```
echo "hello world" | python steg.py encode -m zw -p mypassword -s "the secret payload" -o encoded.txt
```

Extract it back:

```
python steg.py decode -m zw -p mypassword -i encoded.txt
```

Same operations with whitespace:

```
echo -e "line one\nline two\nline three" | python steg.py encode -m ws -p mypassword -s "the secret payload" -o encoded.txt
python steg.py decode -m ws -p mypassword -i encoded.txt
```

## Method comparison

| Method | Invisible | Survives copy-paste | Survives whitespace stripping | Survives unicode sanitizing |
|---|---|---|---|---|
| Zero-width | Yes | Yes | Yes | No |
| Whitespace | No (trailing tabs/spaces) | Yes | No | Yes |

Pick zero-width for text that will be read by humans and copy-pasted as text. Pick whitespace for contexts that strip zero-width characters but preserve trailing whitespace (raw text files, some source code).

## Limitations

- The key derivation uses SHA-256 without a salt. An attacker who intercepts the stego text can brute-force the password faster than with PBKDF2. Fernet's built-in HMAC still rejects wrong passwords cleanly. Upgrade the key derivation to PBKDF2 with a random salt if brute-force resistance is part of the threat model.
- The whitespace method needs at least one cover line per payload bit. Small cover texts get padded with empty lines, which makes large payloads detectable by line count.
- The zero-width method inserts all payload characters after the first character of the cover text. A statistical attacker could detect the cluster. Distribute them evenly for better steganalysis resistance.
- Neither method survives lossy transport (screenshots, OCR, text-to-speech).

## Demo

The `demo/index.html` file is a single-page browser app that implements the same logic in JavaScript using the Web Crypto API (AES-GCM instead of Fernet). Open it in any browser or visit the live demo linked above.

## Tests

```
python -m pytest tests/ -v
```

## License

MIT
