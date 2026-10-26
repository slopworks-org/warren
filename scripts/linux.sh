#!/bin/sh
# Runs a command in a privileged Linux container with the repository mounted,
# e.g. `scripts/linux.sh cargo test --workspace`. Needed on macOS for the
# Linux-only parts (netlink, TUN, the end-to-end test).
set -eu
cd "$(dirname "$0")/.."
docker build -q -t warren-dev -f dist/docker/dev.Dockerfile dist/docker >/dev/null
exec docker run --rm --privileged \
  -v "$PWD":/src -w /src \
  -v warren-cargo-registry:/usr/local/cargo/registry \
  -v warren-target-linux:/src/target \
  -e CARGO_TERM_COLOR=never \
  warren-dev "$@"
