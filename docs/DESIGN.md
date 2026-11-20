# fileion CLI: design note (step C)

Status: proposal for the owner and DH. No code, release or tag in this step. Go, stdlib only, same version and build pattern as `fileion/fileion-installer` (`go 1.22` in go.mod, `build.sh`, `build.yml`).

## 1. What it does

| Command | API call (exists on `release`, `routes/api-public.php`) | Purpose |
|---|---|---|
| `fileion check <file>...` | `POST /api/v1/files/lookup` `{"hashes":[…]}` (up to 100 per request, counts as ONE request) | Hash each file locally, ask whether Fileion lists that file |
| `fileion check --hash <hex>` | same, or `GET /api/v1/files/{hash}` for exactly one | Same, when you already have the hash |
| `fileion info <slug>` | `GET /api/v1/software/{slug}` | Name, publisher, platforms, licence, website, Fileion page |
| `fileion latest <slug> [--platform windows]` | `GET /api/v1/software/{slug}` | `data.latest` already holds the newest version per platform (`{id, version, released_at}`), so one call is enough |
| `fileion version`, `fileion help` | none | |

No server change is needed. Proposals (not part of this step) are in section 9.

### check: the file never leaves the PC
SHA-256 is computed by streaming the file (`io.Copy` into `sha256.New()`, constant memory, any size). Only the 64-character hex goes out. A directory is refused (exit 2); `check` takes files only. `-` reads stdin.

With several files the CLI sends one batched `POST /files/lookup` (chunks of 100), so a CI job with many artefacts costs one request against the 60/min limit. A single `--hash` uses `GET /files/{hash}` (cacheable, 5 min `public` cache headers).

The API answers each hash `found: true|false`. `found: false` is a normal answer (HTTP 200), not an error. It means "Fileion has no record of this file", which is not a warning and not a verdict.

### What check prints (and does not)
Only what the API returns publicly for a found file: software name and slug, version, platform, file name, size, the Fileion page, the source (`official` / `mirror` / `store` with host), the VirusTotal fields as numbers (`engines`, `flagged`, `scanned_at`, `report_url`) when `scan` is present, and the Fileion checks as a count (`trust.ok` of 5) with each step's status.

It never prints "safe", "clean", "virus-free" or a pass/fail verdict. Exit 0 means "Fileion lists this file", nothing more. Output wording is fixed in the table below; the CLI does not echo `trust.label`. Note for the owner: the API's own step text for the fifth check is "Clean installer" (`TrustChain::STEPS`). v1 prints the step statuses by position and name only for steps 1 to 4 and prints the fifth as "Installer test"; the API wording is the owner's call (section 8).

## 2. Keyless by default
No key needed: 60 requests/min per IP. Optional key: `--key fk_…` or env `FILEION_API_KEY` (flag wins), sent as `Authorization: Bearer`. A key gives 300/min and 25,000/day. The key is never printed, never logged, never put in a URL, and `--key` on the command line is documented as visible in process lists (prefer the env var).

A bad or revoked key is HTTP 401 `invalid_key`: exit 3 with the API message, and no silent retry without the key.

### 429 handling
On HTTP 429 the CLI reads `Retry-After` (seconds):
- default: wait up to `--max-wait` (default 30 s, `0` = never wait) once, then retry once;
- if `Retry-After` is longer than `--max-wait`, or the retry is also 429: exit 4, print `rate limited, retry after N s` and, when keyless, the `error.keys_url` from the response body.
A keyless 429 body is `{"error":{"code":"rate_limited","keys_url":…,"request_id":…}}`; `request_id` is shown on every error, so a user can quote it.

Network timeouts: 15 s per request, up to 2 retries with backoff on connection errors and 502/503/504 only. Nothing else is retried.

## 3. Exit codes (stable, documented, tested)

| Code | Meaning |
|---|---|
| 0 | Every file or title asked about was found (`check`: all hashes known to Fileion; `info`/`latest`: title found) |
| 1 | Not found: at least one hash unknown to Fileion, or slug not found (HTTP 404 `not_found`) |
| 2 | Usage error: bad flags, no file, unreadable file, directory, bad hash format |
| 3 | Network or API error: DNS/TLS/timeout, 401, 5xx, bad JSON, unexpected status |
| 4 | Rate limited (429) and not resolved within `--max-wait` |

If several conditions apply, the highest of 2, 3, 4 wins over 1; 1 wins over 0. `check` with `--allow-unknown` returns 0 when some hashes are unknown (for jobs that only want the report). An unreadable file in a batch is reported, the others are still checked, and the run exits 2.

## 4. Output

Plain output goes to stdout; diagnostics and errors go to stderr; `--json` writes only JSON to stdout. `--quiet` prints nothing (exit code only). No colour unless stdout is a terminal and `NO_COLOR` is unset.

### check, plain
```
$ fileion check vlc-3.0.21-win64.exe
vlc-3.0.21-win64.exe
  listed      yes
  software    VLC media player (vlc)
  version     3.0.21, windows
  source      official (get.videolan.org)
  virustotal  0 of 70 engines flagged, scanned 2026-11-02 (report: https://www.virustotal.com/…)
  fileion     5 of 5 checks   https://vlc.fileion.com/windows
  sha256      9f2c…e41a

$ fileion check unknown.bin
unknown.bin
  listed      no. Fileion has no record of this file (this is not a warning)
  sha256      00ab…77c0
$ echo $?
1
```

### check, --json
An array in the order given, each item the API's own `data` item plus the local `file` and `path` (relative as typed, never absolute). Fields not returned by the API are absent, never invented:
```json
[{"path":"vlc-3.0.21-win64.exe","hash":"9f2c…","found":true,
  "software":{"slug":"vlc","name":"VLC media player","url":"https://vlc.fileion.com"},
  "version":{"id":123,"version":"3.0.21","released_at":"2026-10-30","platform":"windows"},
  "file":{"file_name":"vlc-3.0.21-win64.exe","size":"42 MB","sha256":"9f2c…","source":{"kind":"official","host":"get.videolan.org"},"scan":{"engines":70,"flagged":0,"scanned_at":"2026-11-02","report_url":"…"}},
  "trust":{"ok":5,"steps":[…]}},
 {"path":"unknown.bin","hash":"00ab…","found":false}]
```
The JSON shape is part of the contract: additive changes only; a field is never renamed within `0.x` without a note in the release.

### info / latest
```
$ fileion info vlc
VLC media player (vlc)
  publisher   VideoLAN
  platforms   windows, mac, linux
  licence     GPL-2.0
  website     https://www.videolan.org
  page        https://vlc.fileion.com

$ fileion latest vlc --platform windows
3.0.21
$ fileion latest vlc --json
{"windows":{"id":123,"version":"3.0.21","released_at":"2026-10-30"},"mac":{…}}
```
`latest` prints the bare version on one line when `--platform` is given (made for scripts: `V=$(fileion latest vlc -p windows)`), and a `platform version date` table without it.

### Errors (stderr)
`fileion: rate limited, retry after 42 s (request 01J…)`. With `--json` an error is also JSON on stdout: `{"error":{"code":"rate_limited","message":"…","request_id":"…"}}`, so a CI parser never sees empty output.

## 5. Privacy and security
- No telemetry, no update check, no config file, no cache on disk, no crash reports.
- The only requests are the API calls above to `https://fileion.com/api/v1` (`--api-url` exists for tests only and must be https unless host is localhost). `User-Agent: fileion-cli/<version>`. No user, machine or file name data in any header or body: `check` sends hashes only, never paths.
- Follow redirects only to the same host. TLS verification is never disabled; no `--insecure`.
- The API key is read from the flag or env var only.

## 6. Builds and releases (next step, not now)
- Targets: windows, darwin, linux × amd64, arm64 (six files, pure Go, `CGO_ENABLED=0`). Names `fileion-<os>-<arch>[.exe]`.
- Same recipe as the installer: `build.sh <version>`, `-trimpath -buildvcs=false -ldflags="-s -w -buildid= -X main.version=…"`, built twice in CI and `diff`ed (reproducible), the `GOOS` variables exported in a subshell (the dash lesson).
- File-type check in CI: windows files start `MZ`; linux files `\x7fELF`; darwin files Mach-O (`cffaedfe` little-endian for arm64 and amd64); and all six must differ pairwise.
- `build.yml`: test (gofmt, vet, `go test`) then build; only GitHub's own actions, each pinned to a commit SHA; `permissions: contents: read`; no secrets. A tag `v*` builds the release assets and the `SHA256SUMS`; publishing the GitHub Release is a manual owner step, as for the installer.
- Unsigned for now: the README "Code signing" note says so and points to `SHA256SUMS`. macOS may need `xattr -d com.apple.quarantine` or a right-click Open; the README says so. No signing service is mentioned.
- Optional later, not in v0.1: Homebrew tap, winget manifest, `go install`. All on hold under the no-spend rule only if they cost money; none do, but each is a separate listing and needs the owner's yes.

## 7. Tests (what the build step delivers)
- Hashing: known vectors (empty file, a 1-byte file, a 100 MB streamed file through a pipe).
- Fake API (`httptest`) covering: found, not found, mixed batch, 100+ hashes chunked, 401, 404, 422, 429 with and without `Retry-After`, 5xx retry, bad JSON, timeout.
- Exit-code table test, plain and JSON output golden files, `--key` vs env precedence, key never in output.
- Windows runner smoke test (`go test` on windows-latest) like the installer's.
- One manual live check against fileion.com before the first release.

## 8. Connected (each: change needed? and why)

| Surface | Change? | Notes |
|---|---|---|
| developers.fileion.com `/integrations` row (`config/developers.php`) | **Yes, at release** | Add "Fileion CLI" with `links` to the repo and releases; status `review` until published. Owner decides the public wording. |
| developers `/changelog` | **Yes, at release** | One entry on the day it ships (owner decides wording). |
| API docs page (`developers.api`) | **Yes, at release** | A short CLI example next to the curl ones (`check`, `latest`). Owner decides wording. |
| Root `llms.txt` (`LlmsController`) | **Yes, at release** | Add a "Fileion CLI" link line under developers. Owner decides wording. |
| README "Code signing" note | **Yes, in this PR** | Written: unsigned for now, `SHA256SUMS`. |
| Privacy policy | **No** | The CLI only makes the documented public API calls, sends hashes (not files, not paths) and stores nothing. The API's request handling is already covered by the existing API/privacy text. Telemetry would change this; there is none. Owner can still decide to add one line. |
| Security & trust page (`security-trust-center.blade.php`) | **Owner decides** | Its console animation prints `$ fileion check <file>` with lines "virustotal ..... uploading sha-256", "hands-on", "editor" and "published · Clean". The real CLI does none of that: it only asks the API, uploads nothing to VirusTotal and prints no verdict. The demo is a picture of Fileion's listing process, not of this CLI. Recommendation: rename the prompt (e.g. `$ fileion listing-check <file>`, or "Fileion's listing process") so nobody expects the CLI to behave that way, and drop "Clean" from the last line. Owner decides. |
| fileion-installer repo | **No (now)** | Different job. No shared code in v0.1: a shared module is not worth coupling two small public repos. If the installer later wants hash lookups it can copy `internal/api`. |
| check-action (step D) | **Yes, at step D** | The action downloads the pinned CLI release (SHA-256 checked against `SHA256SUMS`) and maps the exit codes. The exit codes, `--json` shape and `--allow-unknown` are the contract the action needs: this note freezes them. |
| Raycast, browser extension, MCP | **No** | Each already calls the same API directly (the extension uses the same hash lookup). The CLI adds a new place to use it, not a change to theirs. |
| Software pages / Installer page | **No** | |
| Conditional #9 (create repo) | Done | Repo exists. |

## 9. Proposals needing a server change (none required for v0.1)
1. A `GET /api/v1/software/{slug}` field `latest_version` per platform already exists as `latest`; no change.
2. Optional: an `ETag`/`304` is already sent (`cache.headers:public;max_age=300;etag`). The CLI could send `If-None-Match`, but it keeps no cache, so skip.
3. Optional: a `GET /api/v1/files/{hash}` `HEAD` form for cheap existence checks. Not needed; `POST /files/lookup` is cheap.
4. Wording: the API step text "Clean installer" (item 5 of `TrustChain::STEPS`) conflicts with the never-"clean" rule for Fileion copy. Owner decides whether to rename it; the CLI avoids it for now.

## 10. Estimates
- Build (code + workflow + tests + README), Sonnet: about 0.7% (about 700 lines of Go, tests included; the installer's build.sh and workflow are reused).
- QA: about 0.2% (run the six builds' type check, exit-code table, fake API, one live call, wording grep for "safe/clean/virus-free", key never printed).
- Release publishing and the Connected edits above: separate small PRs after the owner's yes, about 0.1% each.
