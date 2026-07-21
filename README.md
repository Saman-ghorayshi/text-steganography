# text-steganography

Hide secret messages inside plain text, images, or audio using four steganography methods, with password-based encryption. The hidden bytes are AES-encrypted before encoding, so even if an attacker detects the payload, they cannot read the message without the password.

Live demo: https://username.github.io/text-steganography/

A self-contained browser demo (single HTML file, no dependencies, no backend) implements the same encryption and steganography in JavaScript using the Web Crypto API. Open the demo, hide a message in some cover text, send the result, and the recipient can extract it with the password.

## Methods

This tool implements four steganography techniques. Each has different robustness properties, so choose based on how the cover will be transported.

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

### Image (PNG LSB)

Hide a payload in the least-significant bits of the R, G, and B channels of a PNG cover image. Each pixel carries three payload bits (one per channel), walked in scan order. Alpha is never touched, so transparency stays identical.

- The cover image looks identical to the eye — pixel values change by at most 1 per channel.
- Works only on PNGs (lossless). Outputting JPEG/WebP is refused explicitly because lossy re-encode would silently destroy the LSB payload.
- Capacity is `width * height * 3 / 8 - 4` bytes — a 256x256 PNG hides ~24 KiB of ciphertext, 1024x1024 hides ~384 KiB.
- Does not survive re-encoding through any lossy codec (JPEG, WebP with lossy mode), or any image tool that re-quantizes or rebuilds pixels.

### Audio (WAV 16-bit PCM LSB)

Hide a payload in the least-significant bit of each 16-bit signed PCM sample of a WAV cover. One payload bit per sample, walked in frame order, channels in order (L then R per frame for stereo).

- The cover sounds identical — each sample value changes by at most 1 unit out of 65,536, a ~0.0015% difference the ear cannot detect.
- Works only on 16-bit signed little-endian PCM WAVs. 8-bit unsigned, 24/32-bit float, and compressed WAVs (ADPCM, A-law) are refused explicitly because the LSB math or the re-packing would silently destroy the payload.
- Capacity is `nframes * nchannels / 8 - 4` bytes — an 8,000-frame mono WAV at 8 kHz (1 second of audio) hides ~996 bytes; a 44,100-frame stereo WAV (1 second of CD audio) hides ~11,021 bytes.
- Does not survive re-encoding through any lossy codec (MP3, AAC, OGG, or FLAC-conversion with re-quantization). The CLI refuses `.mp3`/`.aac`/`.ogg` output for this method.

## How it works

1. **Encrypt.** The secret message is encrypted with the password using Fernet, which provides AES-128-CBC plus HMAC-SHA256 authentication. The key is derived from the password via SHA-256. Fernet's random IV means the same message encrypted twice with the same password produces different ciphertext.
2. **Length-prefix.** A 4-byte big-endian length header is prepended to the ciphertext so the decoder knows how many bytes to read back. Without it, the decoder would read trailing whitespace or zero-width chars forever.
3. **Encode the bits.** The length prefix plus ciphertext is converted to a bit string. Each bit becomes either a space/tab (whitespace method) or a zero-width character (zero-width method), inserted into the cover text.
4. **Decode.** Reverse the pipeline: extract every trailing whitespace or zero-width character from the cover text, convert back to bits, read the length header, read the ciphertext bytes, decrypt with the password.

## Installation

```
pip install cryptography Pillow
```

Python 3.11 or newer. Runtime dependencies are `cryptography` (always) and `Pillow` (only for `-m img`). The image import is lazy inside `img_encode`/`img_decode`, so text users do not need Pillow installed. `pytest` is required for tests.

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

Hide a secret in a PNG image (lossless LSB):

```
python steg.py encode -m img -p mypassword -s "the secret payload" -c cover.png -o stego.png
python steg.py decode -m img -p mypassword -i stego.png
```

Non-PNG output extensions are refused to prevent silently destroying the payload:

```
$ python steg.py encode -m img -p mypassword -s "secret" -c cover.png -o stego.jpg
error: refusing non-PNG output 'stego.jpg': lossy encoders (JPEG, WebP) would destroy the LSB payload
```

Hide a secret in a 16-bit PCM WAV cover (lossless audio LSB):

```
python steg.py encode -m wav -p mypassword -s "the secret payload" -c cover.wav -o stego.wav
python steg.py decode -m wav -p mypassword -i stego.wav
```

Non-WAV audio output extensions are refused for the same reason as non-PNG:

```
$ python steg.py encode -m wav -p mypassword -s "secret" -c cover.wav -o stego.mp3
error: refusing non-WAV output 'stego.mp3': lossy encoders (MP3, AAC, OGG) would destroy the sample-LSB payload
```

Use stdin/stdout by omitting the file arguments (or passing `-`):

```
python steg.py encode -m zw -p mypw -s "secret" < cover.txt > stego.txt
python steg.py decode -m zw -p mypw < stego.txt
```

Detect hidden payload without decrypting (no password required):

```
python steg.py detect -m zw -i stego.txt
python steg.py detect -m zw --json -i stego.txt | jq .
python steg.py detect -m img -i stego.png         # reports LSB distribution
python steg.py detect -m img --json -i stego.png  # machine-readable
python steg.py detect -m wav -i stego.wav         # reports sample-LSB distribution
python steg.py detect -m wav --json -i stego.wav  # machine-readable
```

Same information without decrypting, from the decode verb:

```
python steg.py decode -m zw -p wrongpassword --analyze -i stego.txt
```

Exit codes:
- `0` - success
- `2` - input error (bad cover text, no payload found, missing args, no payload in detect)
- `3` - decryption failed (wrong password or corrupted payload)

## Using the library directly

```python
from steg import hide, reveal

# Hide (text methods)
stego_text = hide(b"meet at dawn", "mypassword", cover_text, "zw")
# Stego text looks like cover_text, with invisible characters inserted

# Reveal (text methods)
secret_bytes = reveal(stego_text, "mypassword", "zw")
print(secret_bytes.decode("utf-8"))  # "meet at dawn"
```

For the image method the cover and stego are bytes (PNG file contents):
```python
from steg import hide_img, reveal_img

with open("cover.png", "rb") as f:
    cover_png = f.read()
stego_png = hide_img(b"meet at dawn", "mypassword", cover_png)
with open("stego.png", "wb") as f:
    f.write(stego_png)
# Reveal
secret_bytes = reveal_img(stego_png, "mypassword")
```

For the audio method the cover and stego are bytes (WAV file contents):
```python
from steg import hide_wav, reveal_wav

with open("cover.wav", "rb") as f:
    cover_wav = f.read()
stego_wav = hide_wav(b"meet at dawn", "mypassword", cover_wav)
with open("stego.wav", "wb") as f:
    f.write(stego_wav)
# Reveal
secret_bytes = reveal_wav(stego_wav, "mypassword")
```

The two layers can also be used separately:

```python
from steg import encrypt_message, decrypt_message, zw_encode, zw_decode

ciphertext = encrypt_message(b"secret", "password")
stego = zw_encode(ciphertext, "cover text")
recovered = decrypt_message(zw_decode(stego), "password")
```

## Method comparison

| Property | zero-width | whitespace | image (PNG LSB) | audio (WAV 16-bit PCM LSB) |
|---|---|---|---|---|
| Cover type | text | text | PNG image | 16-bit signed PCM WAV |
| Invisible to naked eye | Yes | No (trailing tabs visible in some editors) | Yes (pixel values change by at most 1) | Inaudible (sample values change by at most 1 of 65,536) |
| Survives copy-paste | Yes | Yes | N/A (binary; copy-paste of images depends on the tool, but bits stay intact on a byte-for-byte PNG copy) | N/A (binary; depends on exact-byte transport) |
| Survives lossy re-encode | N/A | N/A | No (JPEG, WebP destroy LSBs; only PNG and other lossless formats preserve them) | No (MP3, AAC, OGG destroy sample LSBs; only uncompressed PCM WAV preserves them) |
| Survives whitespace stripping | Yes | No | N/A | N/A |
| Survives Unicode sanitizing | No | Yes | N/A | N/A |
| Cover size requirement | None | At least one line per payload bit | `width * height * 3 / 8 - 4` bytes of payload space | `nframes * nchannels / 8 - 4` bytes of payload space |
| Capacity | Low (one bit per cover char inserted) | One bit per cover line | High (~384 KiB in 1024x1024) | Medium (~996 bytes in 1s of 8kHz mono; ~11 KiB in 1s of CD-quality stereo) |
| Detectable by layperson | No | Possibly (trailing tabs) | No | No |
| Detectable by steganalysis | Yes (cluster after char[0]) | Yes (trailing whitespace is rare) | Yes (LSB distribution differs from natural LSB noise) | Yes (sample-LSB distribution differs from natural LSB noise) |

Pick zero-width for text that will be read by humans and copy-pasted as text. Pick whitespace for contexts that strip zero-width characters but preserve trailing whitespace (raw text files, some source code, plain text email). Pick image if the cover is a PNG you control end-to-end — it's the highest-capacity option and survives any lossless transport, but dies the moment anyone re-encodes it lossy. Pick audio if the cover is a 16-bit PCM WAV you control end-to-end — the payload rides each sample's LSB and is inaudible, but it dies the moment anyone re-encodes it through a lossy codec (MP3, AAC, OGG) or even a lossless re-pack that re-quantizes.

## Detection

Steganography hides bytes from the eye, not from statistical analysis. The browser demo includes a Detect tab that:

- Counts zero-width characters in the text - they never appear in normal prose, so any count above zero indicates a hidden payload.
- Counts trailing tabs across lines - trailing tabs are rare in normal text, and many lines with trailing tabs indicate a whitespace payload.
- Reads the declared length from the bit string as a length header without needing the password, so it can reveal how many payload bytes are hidden even without the key.

For the image method, `python steg.py detect -m img` reports the LSB distribution (how many ones vs zeros across all R/G/B channels) and a simple `suspicious` flag: a readable non-zero length header that fits inside the image's LSB capacity is itself the steganographic signal — random LSB noise would not produce such a tight length prefix. This is the honest minimum for a portfolio piece; a real chi-square steganalyzer is a follow-up.

For the audio method, `python steg.py detect -m wav -i stego.wav` reports the sample-LSB distribution (how many ones vs zeros across every 16-bit sample) and the same readable-header `suspicious` flag. The length header survives without the password, so `detect` can tell an attacker exactly how many bytes are hidden in the cover audio — the same honesty as the image method.

This demonstrates a fundamental property of LSB-style steganography: it hides content from humans, not from analysis tools. The password protects the message content, not the existence of the message.

## Tests

```
python -m pytest tests/ -v
```

The test suite includes round-trip tests, fuzz tests (random byte payloads across random cover sizes), edge cases (empty cover, empty payload, truncated payload, corrupted ciphertext, wrong password, Unicode cover text, 1 MB payloads, RGBA alpha preserved, 8-bit-WAV refusal, cover-too-small capacity rejection), and end-to-end tests driving the CLI through `main()`. The text, image, and audio test modules are split for clarity.

## Limitations

- **Key derivation is SHA-256 without a salt.** An attacker who intercepts the stego text can brute-force the password faster than with PBKDF2. Fernet's HMAC still rejects wrong passwords cleanly. Upgrade to PBKDF2 with a random salt if brute-force resistance is part of the threat model.
- **Whitespace method needs one cover line per payload bit.** Small covers get padded with empty lines, which makes large payloads detectable by line count.
- **Zero-width method clusters all payload characters after the first character of the cover.** A statistical attacker could detect the cluster. Distributing them evenly across the cover would improve steganalysis resistance.
- **Image method writes only the LSB of R, G, B.** Alpha is preserved so transparency stays identical, but only three bits-per-pixel are available. Modifying the alpha channel or using higher bit planes would increase capacity (and detectability).
- **Image method refuses non-PNG output** (JPEG, WebP, etc.) because lossy re-encode destroys the LSB payload. Sending a stego PNG through any tool that re-encodes lossy will silently destroy the hidden message.
- **Image steganalysis here is a length-header sanity check.** The `suspicious` flag is intentionally simple; a real chi-square LSB steganalyzer is a polish follow-up listed in the project plans.
- **Neither text method survives lossy transport.** Screenshots, OCR, text-to-speech, and some Markdown renderers destroy the payload.
- **Audio method writes only the LSB of 16-bit signed PCM samples.** Only a single bit per sample is available. Higher-bit-plane writes would change sample values more (and be audible); multi-format support (8-bit, 24/32-bit float) is left for the format-extension commit named in the project plans.
- **Audio method refuses non-WAV output** (MP3, AAC, OGG, etc.) because lossy re-encode destroys the sample-level LSB payload. Converting a stego WAV to MP3 and back destroys the message silently. Even some lossless formats (FLAC, ALAC) can re-pack samples in ways that break the bit-for-bit round-trip — only uncompressed PCM WAV is guaranteed.
- **Audio steganalysis here is the same length-header sanity check.** The `suspicious` flag on `detect -m wav` is intentionally simple; a real chi-square steganalyzer for audio LSB is in the same polish follow-up as the image detector.
- **Browser demo uses AES-GCM, not Fernet.** Fernet is Python-specific and has no JavaScript equivalent. The browser demo uses Web Crypto's AES-256-GCM with the same SHA-256 key derivation. Encoded text from the Python tool cannot be decoded by the browser demo and vice versa, but the same password works on both sides of each tool.

## Project layout

```
steg.py                tool and library (encryption + steganography, CLI, hide/reveal wrappers)
tests/test_steg.py     text-method test suite (whitespace, zero-width)
tests/test_steg_img.py image-method test suite (PNG LSB, CLI, detect)
tests/test_steg_wav.py audio-method test suite (WAV 16-bit PCM LSB, CLI, detect)
docs/                  teaching pages + live demo (GitHub Pages)
  index.html           landing + demo tabs
  whitespace.html      how the whitespace method works
  zero-width.html      how the zero-width method works
  lsb-image.html       how the image LSB method works
  style.css            shared demo/site styling
requirements.txt       cryptography, Pillow
README.md
LICENSE
```

## Acknowledgments

The whitespace encoding scheme is the same idea used by Matthew Kwan's `stegsnow` (`SNOW`) - bits encoded as trailing spaces and tabs at the end of text lines. The zero-width Unicode technique is the same idea used by several open-source tools, including `pyUnicodeSteganography` and `ZW Steg`.

## License

MIT
