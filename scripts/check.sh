#!/bin/bash
# The whole gate, as CI and the pre-commit hook run it: scripts/check.sh
# One step: scripts/check.sh clippy. Linux-only code (netlink, TUN) is linted
# and tested only on Linux, so on macOS run it through scripts/linux.sh too.
set -euo pipefail
cd "$(dirname "$0")/.."

step_format() { cargo fmt --all --check; }
step_clippy() { cargo clippy --workspace --all-targets --locked -- -D warnings; }
step_test() { cargo test --workspace --locked; }

steps=("$@")
[ ${#steps[@]} -eq 0 ] && steps=(format clippy test)
for step in "${steps[@]}"; do
    echo "==> $step"
    "step_$step"
done
