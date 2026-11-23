#!/bin/sh
# Writes the Homebrew formula and the Scoop manifest for a release, from that release's own SHA256SUMS (the same six files
# build.sh makes; nothing is rebuilt or repackaged, so the hashes are the ones on the release page).
# Usage: packaging/render.sh <tag, e.g. v0.1.0> <SHA256SUMS file> <formula output> <manifest output>
set -eu
TAG="$1"; SUMS="$2"; FORMULA="$3"; MANIFEST="$4"
V="${TAG#v}"
BASE="https://github.com/fileion/fileion-cli/releases/download/$TAG"
sum() { s=$(awk -v f="$1" '$2 == f { print $1 }' "$SUMS"); [ "${#s}" = 64 ] || { echo "no SHA-256 for $1 in $SUMS" >&2; exit 1; }; printf '%s' "$s"; }
cat > "$FORMULA" <<RB
class Fileion < Formula
  desc "Check files against the Fileion catalogue"
  homepage "https://github.com/fileion/fileion-cli"
  version "$V"
  license "MIT"

  on_macos do
    if Hardware::CPU.arm?
      url "$BASE/fileion-darwin-arm64"
      sha256 "$(sum fileion-darwin-arm64)"
    else
      url "$BASE/fileion-darwin-amd64"
      sha256 "$(sum fileion-darwin-amd64)"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "$BASE/fileion-linux-arm64"
      sha256 "$(sum fileion-linux-arm64)"
    else
      url "$BASE/fileion-linux-amd64"
      sha256 "$(sum fileion-linux-amd64)"
    end
  end

  def install
    bin.install Dir["fileion-*"].first => "fileion"
  end

  test do
    assert_match "v#{version}", shell_output("#{bin}/fileion version")
  end
end
RB
cat > "$MANIFEST" <<JSON
{
    "version": "$V",
    "description": "Check files against the Fileion catalogue",
    "homepage": "https://github.com/fileion/fileion-cli",
    "license": "MIT",
    "architecture": {
        "64bit": {
            "url": "$BASE/fileion-windows-amd64.exe#/fileion.exe",
            "hash": "$(sum fileion-windows-amd64.exe)"
        },
        "arm64": {
            "url": "$BASE/fileion-windows-arm64.exe#/fileion.exe",
            "hash": "$(sum fileion-windows-arm64.exe)"
        }
    },
    "bin": "fileion.exe",
    "checkver": "github",
    "autoupdate": {
        "architecture": {
            "64bit": { "url": "https://github.com/fileion/fileion-cli/releases/download/v\$version/fileion-windows-amd64.exe#/fileion.exe" },
            "arm64": { "url": "https://github.com/fileion/fileion-cli/releases/download/v\$version/fileion-windows-arm64.exe#/fileion.exe" }
        },
        "hash": { "url": "https://github.com/fileion/fileion-cli/releases/download/v\$version/SHA256SUMS", "regex": "\$sha256\\\\s+\$basename" }
    }
}
JSON
