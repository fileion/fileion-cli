# fileion (command-line)

A small command-line program for the Fileion catalogue. It will check a file's SHA-256 against what Fileion lists, and look up a title and its latest version.

**Status: design only.** No code or release yet. See [docs/DESIGN.md](docs/DESIGN.md).

- Reads only the public Fileion API (`https://fileion.com/api/v1`). Your file never leaves your computer; only its hash is sent.
- No telemetry. The only requests are the API calls above, with the header `User-Agent: fileion-cli/<version>`.
- MIT licensed, provided as is.

## Code signing

Unsigned for now. Windows SmartScreen or macOS Gatekeeper may warn on first run. Each release lists a `SHA256SUMS` file; compare it with the file you downloaded.
