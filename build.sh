#!/bin/sh
# Reproducible build of the six release files. The same source and Go version give the same bytes.
# Usage: ./build.sh [version]   Output: dist/fileion-<os>-<arch>[.exe] and dist/SHA256SUMS
set -eu
cd "$(dirname "$0")"
VERSION="${1:-dev}"
export CGO_ENABLED=0
rm -rf dist && mkdir -p dist
FLAGS="-trimpath -buildvcs=false -ldflags=-s\ -w\ -buildid=\ -X\ main.version=${VERSION}"
for os in windows darwin linux; do
  for arch in amd64 arm64; do
    ext=""; [ "$os" = windows ] && ext=".exe"
    # exported in a subshell: a GOOS=… prefix on `eval` is not passed on to `go` by dash (the CI shell)
    ( export GOOS=$os GOARCH=$arch; eval go build $FLAGS -o "dist/fileion-$os-$arch$ext" . )
  done
done
if command -v sha256sum > /dev/null; then SUM="sha256sum"; else SUM="shasum -a 256"; fi
( cd dist && $SUM fileion-* > SHA256SUMS )
cat dist/SHA256SUMS
