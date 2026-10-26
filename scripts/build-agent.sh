#!/bin/sh
# Cross-compiles the static agent; works on macOS and Linux with only rustup:
#   scripts/build-agent.sh [aarch64|armv7|x86_64 ...]   (default: aarch64)
# Output: dist/out/warren-linux-<arch>. Needs `rustup target add <triple>` once.
set -eu
cd "$(dirname "$0")/.."
mkdir -p dist/out
for arch in "${@:-aarch64}"; do
  case "$arch" in
    aarch64 | arm64) triple=aarch64-unknown-linux-musl arch=aarch64 ;;
    armv7) triple=armv7-unknown-linux-musleabihf ;;
    x86_64 | amd64) triple=x86_64-unknown-linux-musl arch=x86_64 ;;
    *) echo "unknown architecture: $arch" >&2; exit 2 ;;
  esac
  rustup target list --installed | grep -qx "$triple" || rustup target add "$triple"
  cargo build --locked -p warren-agent --profile agent --target "$triple"
  cp "target/$triple/agent/warren" "dist/out/warren-linux-$arch"
  ls -l "dist/out/warren-linux-$arch"
done
