#!/bin/sh
# Builds everything and runs the end-to-end test (both tunnel backends) in a
# privileged Linux container.
set -eu
cd "$(dirname "$0")/.."
exec scripts/linux.sh sh -c 'cargo build --workspace && cargo test -p warren-server --test e2e -- --ignored --nocapture --test-threads=1 "$@"' e2e "$@"
