#!/bin/bash
# Real agents and kernel WireGuard: asymmetric loss, hub source validation,
# retry with fresh sessions, and recovery. Run: just linux bash scripts/test-lan-fallback.sh
set -euo pipefail
umask 077
cargo build -p warren-agent
work=$(mktemp -d)
prefix="wl$$"
pids=()
cleanup() {
    for pid in "${pids[@]}"; do kill -CONT "$pid" 2>/dev/null || true; kill "$pid" 2>/dev/null || true; done
    for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null || true; done
    for n in a b h; do ip netns del "$prefix$n" 2>/dev/null || true; done
    ip link del "$prefix" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT
ns() { local n=$1; shift; ip netns exec "$prefix$n" "$@"; }
ip link add "$prefix" type bridge
ip link set "$prefix" up
for n in a b h; do
    case $n in a) id=2;; b) id=3;; h) id=1;; esac
    ip netns add "$prefix$n"
    ip link add "$prefix$n" type veth peer name eth0 netns "$prefix$n"
    ip link set "$prefix$n" master "$prefix"
    ip link set "$prefix$n" up
    ns "$n" ip link set lo up
    ns "$n" ip addr add "192.0.2.$id/24" dev eth0
    ns "$n" ip link set eth0 up
    mkdir "$work/$n"
    wg genkey > "$work/$n/private.key"
    chmod 600 "$work/$n/private.key"
    wg pubkey < "$work/$n/private.key" > "$work/$n/public"
    ns "$n" ip link add wg0 type wireguard
    ns "$n" wg set wg0 private-key "$work/$n/private.key" listen-port 51820
    ns "$n" ip addr add "10.77.0.$id/16" dev wg0
    ns "$n" ip link set wg0 up
done
ns h sysctl -qw net.ipv4.ip_forward=1
for n in a b; do
    if [ "$n" = a ]; then id=2; other=b; remote=3; else id=3; other=a; remote=2; fi
    ns h wg set wg0 peer "$(cat "$work/$n/public")" allowed-ips "10.77.0.$id/32" endpoint "192.0.2.$id:51820"
    cat > "$work/$n/agent.conf" <<EOF
server=http://192.0.2.1
interface=wg0
version=1
device_id=$id
name=$n
address=10.77.0.$id/16
control=10.77.0.1:7180
peer=$(cat "$work/h/public") 192.0.2.1:51820 10.77.0.0/16 1
lan_peer=$(cat "$work/$other/public") 192.0.2.$remote:51820 10.77.0.$remote/32 1
EOF
    ip netns exec "$prefix$n" "$(pwd)/target/debug/warren" run --config-dir "$work/$n" --run-dir "$work/$n/run" > "$work/$n/log" 2>&1 &
    pids+=("$!")
done
routes() { ns "$1" wg show wg0 allowed-ips | awk -v key="$(cat "$work/$2/public")" '$1==key {print $2}'; }
wait_route() {
    local n=$1 other=$2 want=$3 limit=$4
    for ((i=0; i<limit; i++)); do
        [ "$(routes "$n" "$other")" = "$want" ] && return
        sleep 1
    done
    cat "$work/a/log" "$work/b/log"
    echo "route timeout: $n -> $other expected $want" >&2; exit 1
}
wait_route a b 10.77.0.3/32 30
wait_route b a 10.77.0.2/32 30
# Count decrypted packets reaching B's INPUT chain. A hub-forwarded packet
# would fail WireGuard source validation if B still assigned A's /32 directly.
ns b iptables -A INPUT -s 10.77.0.2 -p tcp --dport 80 -j ACCEPT
received() { ns b iptables -nvxL INPUT | awk '/10.77.0.2/ {print $1}'; }
probe() { ns a curl -s --max-time 1 http://10.77.0.3/ >/dev/null 2>&1 || true; }
# Reproduce the review finding with real source validation before testing the
# watcher fix: only A falls back, while B retains direct ownership of A's /32.
kill -STOP "${pids[@]}"
ns a wg set wg0 peer "$(cat "$work/b/public")" allowed-ips ''
probe; [ "$(received)" -eq 0 ]
ns a wg set wg0 peer "$(cat "$work/b/public")" allowed-ips 10.77.0.3/32
probe; [ "$(received)" -gt 0 ]
ns b iptables -Z INPUT
kill -CONT "${pids[@]}"
# Drop only B -> A encrypted LAN traffic; both hub paths remain intact.
ns a iptables -A INPUT -s 192.0.2.3 -p udp --dport 51820 -j DROP
wait_route a b '' 30
wait_route b a '' 30
probe
[ "$(received)" -gt 0 ]
# Allow multiple retries with the fault present. Old session keys must not
# re-promote a peer, and traffic via the hub must continue to arrive.
for ((i=0; i<65; i++)); do
    [ "$(routes a b)" != 10.77.0.3/32 ]
    [ "$(routes b a)" != 10.77.0.2/32 ]
    sleep 1
done
before=$(received); probe; [ "$(received)" -gt "$before" ]
ns a iptables -D INPUT -s 192.0.2.3 -p udp --dport 51820 -j DROP
wait_route a b 10.77.0.3/32 40
wait_route b a 10.77.0.2/32 40
echo 'PASS: asymmetric LAN failure falls back through hub, stays usable across retries, and recovers'
