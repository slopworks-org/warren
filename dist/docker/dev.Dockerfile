# Linux build and test environment (used by scripts/linux.sh).
FROM rust:1.99-trixie
RUN apt-get update \
 && apt-get install -y --no-install-recommends iproute2 nftables iptables curl procps wireguard-tools \
 && rm -rf /var/lib/apt/lists/* \
 && rustup component add clippy rustfmt
