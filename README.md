# ttl

CLI for [ttl.space](https://ttl.space) — end-to-end encrypted ephemeral storage.

🔒 Files are encrypted on your device before upload. The server only stores ciphertext — it never sees your data, your password, or your filename.

⏱️ Every file has a time-to-live. When it expires, the server deletes it permanently.

🤖 **AI-agent ready** — `--json` mode provides structured input/output with auto-generated passwords, deterministic exit codes, and machine-parseable errors. No interactive prompts, no terminal required.

## 📦 Install

🍺 **macOS** (Homebrew)

```
brew install tweenietomatoes/ttl/ttl
```

🐧 **Linux / macOS** (pre-built binary)

Download the latest archive from [Releases](https://github.com/tweenietomatoes/ttl/releases), then:

```
tar xzf ttl_*_linux_amd64.tar.gz
sudo mv ttl /usr/local/bin/
```

🪟 **Windows** (Scoop)

```
scoop bucket add ttl https://github.com/tweenietomatoes/scoop-ttl
scoop install ttl
```

**Go**

```
go install github.com/tweenietomatoes/ttl/cmd/ttl@latest
```

Pre-built binaries for all platforms are available on the [Releases](https://github.com/tweenietomatoes/ttl/releases) page.

## 🚀 Quick start

Send a file — a password is generated automatically:

```
$ ttl send secret.pdf
No password provided. Generate one? [Y/n]: y
Generated password: aB3kL9mX
4.2 MB / 4.2 MB  ·✧★◉✧··✧·✧★◉✧··✧·✧★◉✧··✧·✧★  100%  1.5 MB/s
·✧★◉ Thank goodness, secret.pdf is in orbit (4.2 MB)
IMPORTANT! Save your password — required to download and decrypt the file.
Password: aB3kL9mX
https://ttl.space/aBcDeFgHiJ
```

Download using the full URL:

```
$ ttl get https://ttl.space/aBcDeFgHiJ
Enter password: ········
Password verified
4.2 MB / 4.2 MB  ·✧★◉✧··✧·✧★◉✧··✧·✧★◉✧··✧·✧★  100%  1.5 MB/s
◉★✧· Phew, secret.pdf landed safe and sound (4.2 MB)
```

Or just the 10-character token — same result:

```
$ ttl get aBcDeFgHiJ
```

## 🔥 Burn after reading

Files can self-destruct after the first download. Once retrieved, the server deletes them permanently.

```
$ ttl send -b confidential.pdf
·✧★◉ Thank goodness, confidential.pdf is in orbit (912.0 KB, self-destructs after download)
```

```
$ ttl get aBcDeFgHiJ
Enter password: ········
Password verified
◉★✧· Phew, confidential.pdf landed safe and sound (912.0 KB)

$ ttl get aBcDeFgHiJ
Error: Link not found
```

A second attempt returns an error — the file no longer exists.

## Usage

```
ttl send [-p P] [-t DUR] [-b] [--json] [--timeout D] FILE
ttl get  [-p P] [--json] [--timeout D] [-o DIR] URL or TOKEN
ttl version
```

| Flag | Description |
|------|-------------|
| `-p, --password P` | Encryption / decryption password |
| `-t, --ttl DUR` | Time to live: `5m` `10m` `15m` `30m` `1h` `2h` `3h` `6h` `12h` `24h` `1d` `2d` `3d` `4d` `5d` `6d` `7d` (default: `7d`) |
| `-b, --burn` | Burn after reading — deleted after first download |
| `-o, --output DIR` | Output directory (default: current directory) |
| `--timeout D` | Transfer timeout (e.g. `5m`, `1h`). Default: auto (assumes 1 Mbps) |
| `--server URL` | Server endpoint (default: `https://ttl.space`) |
| `--password-stdin` | Read password from stdin |
| `--password-file F` | Read password from file |
| `--json` | Output JSON to stdout (for scripts and AI agents) |
| `-h3, --http3` | Try HTTP/3 (QUIC) first, fall back to TCP |

## 💡 Examples

Quick share with custom password — expires in 5 minutes:

```
ttl send -p mySecret -t 5m credentials.txt
```

Send with various TTL durations:

```
ttl send -t 5m credentials.txt              # expires in 5 minutes
ttl send -t 1h document.pdf                 # expires in 1 hour
ttl send -t 3d project-archive.tar.gz       # expires in 3 days
ttl send report.xlsx                        # expires in 7 days (default)
```

Burn after reading — file is permanently deleted after the first download:

```
ttl send -b confidential.pdf
```

Download to a specific directory:

```
ttl get -o ~/Downloads aBcDeFgHiJ
```

Scripting — password from stdin (no terminal prompt):

```
echo "mySecretPass" | ttl send --password-stdin backup.tar.gz
```

Password from a file (useful for CI/CD and Docker secrets):

```
ttl send --password-file /run/secrets/pw backup.tar.gz
```

## 🤖 JSON mode (scripts & AI agents)

`--json` makes ttl fully non-interactive — no prompts, no progress bars, just structured JSON on stdout. Designed for AI agents, CI/CD pipelines, and tool-use integrations.

```
$ ttl --json send report.pdf
{"ok":true,"link":"https://ttl.space/xK9mQ2vLpA","filename":"report.pdf","size":2097152,"ttl":"7d","burn":false,"password":"aB3kL9mX"}

$ ttl --json get -p aB3kL9mX xK9mQ2vLpA
{"ok":true,"filename":"report.pdf","size":2097152,"saved_to":"/home/user/report.pdf"}

$ ttl --json get -p aB3kL9mX nonExistent
{"ok":false,"error":"Link not found"}
```

| Behavior | Detail |
|----------|--------|
| Password | Auto-generated and included in response if not provided during send |
| Output | Single JSON object on stdout, nothing on stderr |
| Exit code | `0` on success, `1` on error |
| Errors | `{"ok":false,"error":"..."}` — always parseable |

## 🔑 Password handling

| Method | Usage |
|--------|-------|
| Auto-generate | `ttl send file.txt` — generates an 8-character random password |
| Interactive | Prompted securely with hidden input |
| Flag | `ttl send -p t0pSecret file.txt` — visible in `ps` and shell history |
| Stdin | `echo "t0pSecret" \| ttl send --password-stdin file.txt` |
| File | `ttl send --password-file /run/secrets/pw file.txt` |

Minimum password length is 8 characters. Only one password source can be used at a time — combining `-p`, `--password-stdin`, and `--password-file` is an error. For scripts, prefer `--password-stdin` or `--password-file` over `-p`.

## 🛡️ How it works

### 🔒 Encryption

| Layer | Detail |
|-------|--------|
| Key derivation | Argon2id (time=3, memory=64 MB, single-threaded) |
| Cipher | XChaCha20-Poly1305 (AEAD) |
| Chunking | 64 KB chunks, individually authenticated |
| Metadata | Filename and size encrypted in a separate AEAD block |

All encryption and decryption happens entirely on your device. The server never sees plaintext.

### Two-phase download

Downloads use a two-phase protocol that verifies your password before fetching the full file:

1. **Probe** — the client fetches just the file header and encrypted metadata (~300 bytes). It derives the encryption key from your password and attempts to decrypt the metadata. If the password is wrong, you're told immediately — no bandwidth wasted.

2. **Download** — once verified, the client derives a one-way bearer token from the encryption key and sends it to authenticate the full download. The server verifies the token but never learns the password or the encryption key.

### Key derivation chain

```
password + salt → Argon2id → encryption key
                                 ↓
                             HKDF-Expand → download token (bearer)
                                               ↓
                                           SHA-256 → token hash (stored by server)
```

The server only ever sees the token hash (at upload) and the download token (transiently, at download). It cannot derive the encryption key or the password from either.

### Server-side validation

The server validates every upload before storing it:

- TTL file format (magic bytes, header structure, metadata bounds)
- Non-trivial entropy (rejects unencrypted or low-entropy data)
- Salt and nonce are not all-zeros

This ensures only properly encrypted files are stored, even if a client is buggy.

## Limits

| Limit | Value |
|-------|-------|
| Max file size | 256 MB |
| Max retention | 7 days |
| Uploads per IP | 10 per day, min 3 seconds apart |
| Requests per IP | 30 per 10 seconds |
| Min password | 8 characters |
| Connections per IP | 10 concurrent |

## 📖 Documentation

For the complete guide including the browser interface and the HTTP API, visit [ttl.space/usage](https://ttl.space/usage).

## ⚖️ Licence

[MIT](LICENCE)
