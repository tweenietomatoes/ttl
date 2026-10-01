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
Generated password: aB3kL9mXq7Rt
4.2 MB / 4.2 MB  ·✧★◉✧··✧·✧★◉✧··✧·✧★◉✧··✧·✧★  100%  1.5 MB/s
·✧★◉ Thank goodness, secret.pdf is in orbit (4.2 MB, expires 2026-10-08 12:00)
IMPORTANT! Save your password — required to download and decrypt the file.
Password: aB3kL9mXq7Rt
Manage key: k7Qm2vXpL9aR4tB8cD1eF6gH3jK5mN0oP2qS4uV7wYz (ttl status / ttl delete -k)
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
·✧★◉ Thank goodness, confidential.pdf is in orbit (912.0 KB, expires 2026-10-08 12:00, self-destructs after download)
```

```
$ ttl get aBcDeFgHiJ
Enter password: ········
Password verified
◉★✧· Phew, confidential.pdf landed safe and sound (912.0 KB)

$ ttl get aBcDeFgHiJ
Error: Link not found. The file may have expired, been downloaded already (burn after reading), or be private (uploader-only)
```

A second attempt returns an error — the file no longer exists.

## 🗝️ Manage key: status and early delete

Every upload comes with a **management key**, printed once by `ttl send` (`manage_key` in `--json`). The server keeps only its hash. It works on any plan and lets you follow the upload or end it early — without an Orbit key. Anyone holding the key can delete the upload, so keep it like the password.

```
$ ttl status aBcDeFgHiJ -k k7Qm2vXpL9aR4tB8cD1eF6gH3jK5mN0oP2qS4uV7wYz
Token:      aBcDeFgHiJ
State:      active
Size:       4.2 MB
Created:    2026-10-01 12:00
Expires:    2026-10-08 12:00
Downloads:  1 (last 2026-10-02 09:12)

$ ttl delete aBcDeFgHiJ -k k7Qm2vXpL9aR4tB8cD1eF6gH3jK5mN0oP2qS4uV7wYz
Deleted: aBcDeFgHiJ
```

The state is one of `active`, `expired`, `burned` or `deleted`. Files opened in parts on the recipient page (a package's file list) show up as "Opened on page", never as downloads.

## 🔁 Resumable transfers

A dropped connection does not restart a transfer:

- **Uploads** above 16 MiB go through the server's resumable upload API: the encrypted stream is sent in 16 MiB parts, each with a SHA-256 `Content-Digest`. A part that fails — a lost connection, a 5xx, bytes altered on the way — is sent again from memory; the rest of the file is untouched. Smaller files go in one request and are sent again in full if the connection breaks. The CLI gives up after 15 minutes without progress.
- **Downloads** resume with a byte-range request from the last byte received; every 64 KiB chunk is authenticated on its own, so a resumed stream decrypts exactly like an unbroken one. Burn-after-reading files cannot be resumed — the server refuses ranges for them, so the first transfer must complete.
- **Ctrl-C** cancels cleanly: an open upload session is handed back to the server, and a partial download is removed.

## 🪐 Orbit plan

[Orbit](https://ttl.space/orbit) unlocks larger files, longer retention, permanent storage, uploader-only locks, and a 500 GB pool.

The Orbit key is auto-detected (first match wins):

1. `TTL_API_KEY` environment variable
2. `ttl.key` next to the binary
3. `~/.ttl/key`

When `ttl get` runs with a key configured, it is sent automatically so private (uploader-only) files open transparently.

`ttl activate` checks the key against the server before saving it, so a mistyped or revoked key is refused on the spot. Prefer `--key-stdin` or `--key-file` over the positional form, which lands in shell history.

```
$ ttl activate --key-file ~/orbit.key
Orbit plan activated. Key saved to /usr/local/bin/ttl.key

$ ttl plan
Plan: orbit
Max file size: 10.0 GB
Max TTL: 30 days (or permanent)
Uploads per day: 1000000
Storage quota: 500.0 GB

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

`ttl list` walks every page the server returns (20 files per page); `-n N` stops after N files. `ttl delete` with an Orbit key deletes any file the key uploaded; with `-k` it deletes by management key instead.

### 🔐 Uploader-only (private) files

Add `-u` / `--uploader-only` (or `--private`) on send to require the uploader's API key on download. Even with the link and the password, anyone without the key gets a 404 (probe) or 403 (download) — indistinguishable from a wrong-password response.

```
$ ttl send -u -t 1d board-minutes.pdf
·✧★◉ Thank goodness, board-minutes.pdf is in orbit (240.0 KB, expires 2026-10-02 12:00, private — uploader's API key required to download)

$ TTL_API_KEY="" ttl get aBcDeFgHiJ
Error: Link not found. The file may have expired, been downloaded already (burn after reading), or be private (uploader-only)

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
ttl status <token> -k KEY
ttl delete <token> [-k KEY]
ttl activate [--key-stdin | --key-file F | <key>]
ttl deactivate
ttl plan
ttl list [-n N]
ttl version
```

| Flag | Description |
|------|-------------|
| `-p, --password P` | Encryption / decryption password |
| `-t, --ttl DUR` | Time to live (default: `7d`). See [valid values](#ttl-values) below. |
| `-b, --burn` | Burn after reading — deleted after first download |
| `-u, --uploader-only` | Private file (Orbit) — only the uploader's API key can download. Aliases: `--private` |
| `-o, --output DIR` | Output directory (default: current directory) |
| `-k, --manage-key KEY` | Management key printed by `ttl send` — status or early delete on any plan |
| `-n, --limit N` | `ttl list`: stop after N files (default: all) |
| `--server URL` | Server to talk to (default: `https://ttl.space`) |
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
| 6 | Auto-generate | If none of the above, generates a 12-character random password (send only) |

Minimum password length is 8 characters. Only one explicit source (`-p`, `--password-stdin`, `--password-file`) can be used at a time. For scripts, prefer `--password-stdin` or `--password-file` over `-p`.

## 🤖 JSON mode (scripts & AI agents)

`--json` makes ttl fully non-interactive — no prompts, no progress bars, just structured JSON on stdout. Designed for AI agents, CI/CD pipelines, and tool-use integrations.

```
$ ttl --json send report.pdf
{"ok":true,"link":"https://ttl.space/xK9mQ2vLpA","token":"xK9mQ2vLpA","filename":"report.pdf","size":2097152,"ttl":"7d","expires_in":604800,"expires_at":1760011200,"burn":false,"uploader_only":false,"is_permanent":false,"manage_key":"k7Qm2vXpL9aR4tB8cD1eF6gH3jK5mN0oP2qS4uV7wYz","password":"aB3kL9mXq7Rt"}

$ ttl --json get -p aB3kL9mXq7Rt xK9mQ2vLpA
{"ok":true,"token":"xK9mQ2vLpA","filename":"report.pdf","size":2097152,"saved_to":"/home/user/report.pdf"}

$ ttl --json status xK9mQ2vLpA -k k7Qm2vXpL9aR4tB8cD1eF6gH3jK5mN0oP2qS4uV7wYz
{"ok":true,"token":"xK9mQ2vLpA","status":{"state":"active","size_bytes":2097152,"created_at":1759406400,"expires_at":1760011200,"permanent":false,"burn":false,"note":false,"uploader_only":false,"downloads":1,"last_download_at":1759492800,"part_reads":0,"last_part_at":0}}

$ ttl --json get -p aB3kL9mXq7Rt nonExistent
{"ok":false,"error":"Link not found. The file may have expired, been downloaded already (burn after reading), or be private (uploader-only)"}
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
| Upload volume per day (per IP) | 10 GB | unlimited |
| Storage quota | — | 500 GB (expandable) |
| Delete | with the manage key | ✓ |
| List | — | ✓ |
| Uploader-only (private) | — | ✓ |
| Min password | 8 characters | 8 characters |
| Requests per IP | 30 per 10 seconds | 30 per 10 seconds |

## 📖 Documentation

For the complete guide including the browser interface and the HTTP API, visit [ttl.space/usage](https://ttl.space/usage).

## ⚖️ Licence

[MIT](LICENCE)
