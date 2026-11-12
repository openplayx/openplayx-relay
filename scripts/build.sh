#!/usr/bin/env bash
# Build static release binaries (no cgo) with the pinned sing-box and frp
# modules from src/go.mod. Usage: scripts/build.sh [os/arch ...]
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root/src"
name="$(basename "$(go list -m)")"
version="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
targets=("$@")
[ ${#targets[@]} -gt 0 ] || targets=(linux/amd64 linux/arm64)
mkdir -p "$root/dist"
for target in "${targets[@]}"; do
  os="${target%/*}" arch="${target#*/}"
  output="$root/dist/${name}-${os}-${arch}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
    -ldflags "-s -w -X main.version=${version}" -o "$output" .
  echo "dist/${name}-${os}-${arch}"
done
(cd "$root/dist" && shasum -a 256 "${name}"-* > SHA256SUMS)
