# Short names for scripts/. CI and the pre-commit hook call scripts/check.sh
# directly, so they don't need just.

[private]
default:
    @just --list

# The gate: format, clippy, test (or only the steps named)
check *steps:
    scripts/check.sh {{ steps }}

# The gate on Linux, in a privileged container (for netlink and TUN code on macOS)
check-linux:
    scripts/linux.sh scripts/check.sh

# Format the code
fmt:
    cargo fmt --all

# End-to-end test of both tunnel backends, in Docker
e2e *args:
    scripts/e2e.sh {{ args }}

# Run a command in the Linux dev container
linux +cmd:
    scripts/linux.sh {{ cmd }}

# Static agent: aarch64 (default), armv7, x86_64; output in dist/out/
agent *arches:
    scripts/build-agent.sh {{ arches }}

# Static server for amd64 or arm64 (default: the Docker host's); output in dist/out/
server *arch:
    scripts/build-server.sh {{ arch }}

# OpenWrt .ipk of the aarch64 agent (default arch: aarch64_cortex-a53)
ipk *arch:
    scripts/build-ipk.sh {{ arch }}
