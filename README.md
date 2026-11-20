# fileion (command-line)

A small command-line program for the Fileion catalogue. It checks a file's SHA-256 against what Fileion lists, and looks up a title and its latest version. Design: [docs/DESIGN.md](docs/DESIGN.md).

- Your file never leaves your computer: it is hashed here, and only the hash is sent.
- Reads only the public Fileion API (`https://fileion.com/api/v1`). Free, no key needed (60 requests a minute per IP).
- MIT licensed, provided as is.

## Usage

```
fileion check <file>... | -      hash the file(s), ask Fileion whether it lists them
fileion check --hash <hex>       the same for a SHA-256 (or SHA-1, MD5) you already have
fileion info <slug>              a title: publisher, platforms, licence, website
fileion latest <slug> [-p os]    the newest version per platform; with -p only the version
fileion version | help
```

Options: `--json` (JSON on stdout, errors too: a usage error is also answered as `{"error":{"code":"usage",…}}` whenever `--json` appears among the arguments), `-q/--quiet` (no output, exit code only), `--key` or env `FILEION_API_KEY` (optional free key for higher limits; prefer the env var, a flag shows in process lists), `--max-wait <seconds>` (default 30), `--allow-unknown` (`check` exits 0 even when some hashes are unknown).

```
$ fileion check installer.exe
installer.exe
  listed      yes
  software    VLC media player (vlc)
  version     3.0.21, windows
  source      official (get.videolan.org)
  virustotal  0 of 70 engines flagged, scanned 2026-11-02 (report: https://www.virustotal.com/…)
  fileion     5 of 5 checks   https://vlc.fileion.com
  checks      Official source ok, Fingerprint ok, VirusTotal ok, Code signature ok, Installer test ok
  sha256      9f2c…e41a

$ V=$(fileion latest vlc -p windows)    # 3.0.21
$ fileion check build/*.zip --json      # for CI: one request for up to 100 files
```

`check` reports what Fileion lists: a known file, its source, version and the numbers behind it. "Not listed" means Fileion has no record of that file; it is not a warning and not a verdict, and a listed file is not a promise about it either.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Found: every hash is known to Fileion (or the title exists) |
| 1 | Not found: a hash Fileion does not list, or no such title |
| 2 | Usage error: bad flags, missing, unreadable or directory path, bad hash |
| 3 | Network or API error: connection, timeout, bad key (401), 5xx, unreadable answer |
| 4 | Rate limited (429) and not cleared within `--max-wait` |

On a 429 the program waits once for `Retry-After` (up to `--max-wait` seconds) and retries; otherwise it exits 4 and prints how long to wait and where to get a free key. If several conditions apply, 2, 3 and 4 win over 1.

## Privacy

No telemetry, no update check, no config file, nothing stored on disk. The only requests are the API calls above, with the header `User-Agent: fileion-cli/<version>` and, if you give one, your API key. `check` sends hashes, never file names or paths.

## Code signing

Unsigned for now. Windows SmartScreen or macOS Gatekeeper may warn on first run (on a Mac, right-click, Open, or `xattr -d com.apple.quarantine <file>`). Each release has a `SHA256SUMS` file; compare it with the file you downloaded (`sha256sum -c SHA256SUMS`, or `shasum -a 256`).

## Build

`./build.sh [version]` builds six files (windows, darwin, linux; amd64, arm64) into `dist/` with `-trimpath` and no build ID, so the same source and Go version give the same bytes. CI (`.github/workflows/build.yml`) runs `gofmt`, `go vet` and `go test` (Linux and Windows), builds twice and compares, and checks the file types. Standard library only; no secrets.
