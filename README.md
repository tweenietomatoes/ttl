# ttl

CLI for [ttl.space](https://ttl.space) — Encrypted file transfer. Ephemeral by design, permanent with Orbit.

🔒 Files are encrypted on your device before upload. The server only stores ciphertext — it never sees your data, your password, or your filename.

⏱️ Every file has a time-to-live. When it expires, the server deletes it permanently. With Orbit you can also pin files as **permanent** (kept until you cancel) and lock them to **uploader-only** (only your API key can download).

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

## 🪐 Orbit plan

[Orbit](https://ttl.space/orbit) unlocks larger files, longer retention, permanent storage, uploader-only locks, and a 500 GB pool.

The Orbit key is auto-detected (first match wins):

1. `TTL_API_KEY` environment variable
2. `ttl.key` next to the binary
3. `~/.ttl/key`

When `ttl get` runs with a key configured, it is sent automatically so private (uploader-only) files open transparently.

```
$ ttl activate ttl_orbit_aBcDeFgHiJ...
Orbit plan activated. Key saved to /usr/local/bin/ttl.key

$ ttl plan
Plan: orbit
Max file size: 10.0 GB
Max TTL: 30 days (or permanent)
Uploads per day: 1000000

Usage:
  Uploads today: 3
  Active storage: 4.2 GB / 500.0 GB

$ ttl send -t 30d large-backup.tar.gz

$ ttl send -u -t permanent secrets.tar.zst
·✧★◉ Thank goodness, secrets.tar.zst is in orbit (12.5 MB, permanent, private — uploader's API key required to download)

$ ttl list
  xK9mQ2vLpA    4.2 MB  2026-03-16 10:30 → 2026-04-15 10:30  [active]
  https://ttl.space/xK9mQ2vLpA
  yL3nR7wKqB   12.5 MB  2026-04-20 09:12 → permanent          [active] [private]
  https://ttl.space/yL3nR7wKqB

$ ttl delete xK9mQ2vLpA
Deleted: xK9mQ2vLpA

$ ttl deactivate
Key file removed: /usr/local/bin/ttl.key
```

### 🔐 Uploader-only (private) files

Add `-u` / `--uploader-only` (or `--private`) on send to require the uploader's API key on download. Even with the link and the password, anyone without the key gets a 404 (probe) or 403 (download) — indistinguishable from a wrong-password response.

```
$ ttl send -u -t 1d board-minutes.pdf
·✧★◉ Thank goodness, board-minutes.pdf is in orbit (240.0 KB, private — uploader's API key required to download)

$ TTL_API_KEY="" ttl get aBcDeFgHiJ
Error: Link not found

$ ttl get aBcDeFgHiJ          # API key auto-loaded — opens fine
Password verified
◉★✧· Phew, board-minutes.pdf landed safe and sound (240.0 KB)
```

### ♾️ Permanent storage

`-t permanent` skips the TTL entirely. The file stays until you delete it or your subscription ends. After cancellation a 48-hour grace window arms before hard delete; `ttl plan` displays a red banner with the deadline.

```
$ ttl send -t permanent design-archive.zip
·✧★◉ Thank goodness, design-archive.zip is in orbit (1.2 GB, permanent)
```

Both flags compose: `ttl send -u -t permanent ...`.

## 📋 Usage

```
ttl send [-p P] [-t DUR] [-b] [-u] [--json] [--timeout D] FILE
ttl get  [-p P] [--json] [--timeout D] [-o DIR] URL or TOKEN
ttl activate <key>
ttl deactivate
ttl plan
ttl list
ttl delete <token>
ttl version
```

| Flag | Description |
|------|-------------|
| `-p, --password P` | Encryption / decryption password |
| `-t, --ttl DUR` | Time to live (default: `7d`). See [valid values](#ttl-values) below. |
| `-b, --burn` | Burn after reading — deleted after first download |
| `-u, --uploader-only` | Private file (Orbit) — only the uploader's API key can download. Aliases: `--private` |
| `-o, --output DIR` | Output directory (default: current directory) |
| `--timeout D` | Transfer timeout (e.g. `5m`, `1h`). Default: auto (assumes 1 Mbps) |
| `--password-stdin` | Read password from stdin |
| `--password-file F` | Read password from file |
| `--json` | Output JSON to stdout (for scripts and AI agents) |
| `-h3, --http3` | Try HTTP/3 (QUIC) first, fall back to TCP |

### TTL values

Free tier: `5m` `10m` `15m` `30m` `1h` `2h` `3h` `6h` `12h` `24h` `1d` `2d` `3d` `4d` `5d` `6d` `7d`

Orbit adds: `14d` `15d` `28d` `30d` `permanent`

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

Lock to your API key (private file, Orbit):

```
ttl send -u board-minutes.pdf
```

Pin a file as permanent (Orbit):

```
ttl send -t permanent design-archive.zip
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

## 🔑 Password handling

Password is resolved in this order (first match wins):

| Priority | Method | Usage |
|----------|--------|-------|
| 1 | `-p` flag | `ttl send -p t0pSecret file.txt` — visible in `ps` and shell history |
| 2 | `--password-stdin` | `echo "t0pSecret" \| ttl send --password-stdin file.txt` |
| 3 | `--password-file` | `ttl send --password-file /run/secrets/pw file.txt` |
| 4 | `ttl.password` file | Auto-detected from next to binary or `~/.ttl/password` |
| 5 | Interactive prompt | Prompted securely with hidden input (terminal only) |
| 6 | Auto-generate | If none of the above, generates an 8-character random password (send only) |

Minimum password length is 8 characters. Only one explicit source (`-p`, `--password-stdin`, `--password-file`) can be used at a time. For scripts, prefer `--password-stdin` or `--password-file` over `-p`.

## 🤖 JSON mode (scripts & AI agents)

`--json` makes ttl fully non-interactive — no prompts, no progress bars, just structured JSON on stdout. Designed for AI agents, CI/CD pipelines, and tool-use integrations.

```
$ ttl --json send report.pdf
{"ok":true,"link":"https://ttl.space/xK9mQ2vLpA","filename":"report.pdf","size":2097152,"ttl":"7d","burn":false,"uploader_only":false,"is_permanent":false,"password":"aB3kL9mX"}

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

## 📊 Limits

Limits are fetched from the server at upload time and depend on your plan.

| Limit | Free | Orbit |
|-------|------|-------|
| Max file size | 2 GB | 10 GB |
| Max retention | 7 days | 30 days, or permanent |
| Uploads per day | 10 | effectively unlimited |
| Storage quota | — | 500 GB (expandable) |
| Delete & list | — | ✓ |
| Uploader-only (private) | — | ✓ |
| Min password | 8 characters | 8 characters |
| Requests per IP | 30 per 10 seconds | 30 per 10 seconds |

## 📖 Documentation

For the complete guide including the browser interface and the HTTP API, visit [ttl.space/usage](https://ttl.space/usage).

## ⚖️ Licence

[MIT](LICENCE)
