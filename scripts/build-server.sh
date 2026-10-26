#!/bin/sh
# Builds a static warren-server for Linux: scripts/build-server.sh [amd64|arm64]
# (default: the Docker host's architecture). Output: dist/out/warren-server-linux-<arch>.
# Uses Docker so it works from macOS; the other architecture runs emulated.
set -eu
cd "$(dirname "$0")/.."
arch="${1:-$(docker version -f '{{.Server.Arch}}')}"
case "$arch" in
  amd64 | x86_64) arch=amd64 triple=x86_64-unknown-linux-musl ;;
  arm64 | aarch64) arch=arm64 triple=aarch64-unknown-linux-musl ;;
  *) echo "unknown architecture: $arch" >&2; exit 2 ;;
esac
image="warren-release-$arch"
docker build -q --platform "linux/$arch" -t "$image" -f dist/docker/release.Dockerfile dist/docker >/dev/null
mkdir -p dist/out
docker run --rm --platform "linux/$arch" \
  -v "$PWD":/src -w /src \
  -v warren-cargo-registry:/usr/local/cargo/registry \
  -v "warren-target-release-$arch":/src/target \
  -e "CC_$(echo "$triple" | tr - _)=musl-gcc" \
  "$image" sh -c "cargo build --release --locked -p warren-server --target $triple \
    && cp target/$triple/release/warren-server dist/out/warren-server-linux-$arch"
ls -l "dist/out/warren-server-linux-$arch"
