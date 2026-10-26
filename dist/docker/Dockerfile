# Optional container image. Build the binary first: scripts/build-server.sh
#   docker build -f dist/docker/Dockerfile -t warren-server --build-arg ARCH=arm64 .
# Run with --network host --cap-add NET_ADMIN --device /dev/net/tun -v warren:/var/lib/warren
FROM alpine:3.22
ARG ARCH=amd64
RUN apk add --no-cache nftables iptables
COPY dist/out/warren-server-linux-${ARCH} /usr/local/bin/warren-server
COPY dist/server.toml /etc/warren/server.toml
VOLUME /var/lib/warren
ENTRYPOINT ["/usr/local/bin/warren-server", "--config", "/etc/warren/server.toml"]
