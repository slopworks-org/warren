# Toolchain for static (musl) server builds; used by scripts/build-server.sh.
FROM rust:1.99-trixie
RUN apt-get update \
 && apt-get install -y --no-install-recommends musl-tools \
 && rm -rf /var/lib/apt/lists/* \
 && rustup target add "$(uname -m)-unknown-linux-musl"
