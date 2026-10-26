#!/bin/sh
# Installs or upgrades Warren from the GitHub release, on a VPS or a device:
#   curl -fsSL https://github.com/slopworks-org/warren/releases/latest/download/install.sh \
#     | sudo sh -s -- server --domain warren.example.com --email you@example.com
#   curl -fsSL …/install.sh | sudo sh -s -- agent --server https://warren.example.com --token wrt_…
# On macOS the agent needs wireguard-go: brew install wireguard-go.
# On OpenWrt, which has no curl by default: wget -qO- …/install.sh | sh -s -- agent …
# Run it again to upgrade; the config and the registration are kept.
# WARREN_VERSION=v0.2.0 (or --version) pins a release instead of the latest;
# WARREN_BASE_URL takes the files from elsewhere, e.g. a mirror or a test server.
set -eu

repo=slopworks-org/warren
usage="usage: install.sh server --domain <domain> --email <email> [--version <tag>]
       install.sh agent [--server <url> --token <token> [--name <name>]] [--version <tag>]"

die() { echo "warren install: $*" >&2; exit 1; }
say() { echo "==> $*"; }

mode=${1:-}
[ $# -gt 0 ] && shift
version=${WARREN_VERSION:-latest}
domain='' email='' server='' token='' name=''
while [ $# -gt 0 ]; do
  [ $# -ge 2 ] || die "$1 needs a value"
  case "$1" in
    --domain) domain=$2 ;;
    --email) email=$2 ;;
    --server) server=$2 ;;
    --token) token=$2 ;;
    --name) name=$2 ;;
    --version) version=$2 ;;
    *) die "unknown option $1
$usage" ;;
  esac
  shift 2
done
case "$mode" in
  server | agent) ;;
  *) die "$usage" ;;
esac
os=$(uname -s)
case "$os-$mode" in
  Linux-* | Darwin-agent) ;;
  Darwin-*) die "the server runs on Linux only" ;;
  *) die "Warren runs on Linux and macOS only" ;;
esac
[ "$(id -u)" -eq 0 ] || die "run as root (pipe to 'sudo sh -s -- …')"

if [ -n "${WARREN_BASE_URL:-}" ]; then
  base=$WARREN_BASE_URL
elif [ "$version" = latest ]; then
  base="https://github.com/$repo/releases/latest/download"
else
  base="https://github.com/$repo/releases/download/$version"
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # <url> <file>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$2" "$1"
  else
    die "need curl or wget"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

# Downloads release assets into $work and checks them against SHA256SUMS.
download() {
  [ -f "$work/SHA256SUMS" ] || fetch "$base/SHA256SUMS" "$work/SHA256SUMS" ||
    die "no release $version at github.com/$repo"
  for f in "$@"; do
    fetch "$base/$f" "$work/$f" || die "cannot download $f"
    want=$(awk -v f="$f" '$2 == f || $2 == "*" f { print $1 }' "$work/SHA256SUMS")
    [ -n "$want" ] && [ "$(sha256 "$work/$f")" = "$want" ] || die "checksum mismatch for $f"
  done
}

# install(1) without the coreutils one, which OpenWrt's busybox lacks.
put() { # <mode> <from> <to>
  mkdir -p "$(dirname "$3")" && cp "$2" "$3.new" && chmod "$1" "$3.new" && mv -f "$3.new" "$3"
}

has_systemd() { [ -d /run/systemd/system ]; }

install_server() {
  case "$(uname -m)" in
    x86_64 | amd64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    *) die "no server build for $(uname -m)" ;;
  esac
  has_systemd || die "the server installer needs systemd"
  upgrade=''
  [ -f /etc/warren/server.toml ] && upgrade=1
  if [ -z "$upgrade" ] && { [ -z "$domain" ] || [ -z "$email" ]; }; then
    die "a first install needs --domain and --email"
  fi

  say "Downloading warren-server ($version, $arch)"
  download "warren-server-linux-$arch" warren-server.service
  put 0755 "$work/warren-server-linux-$arch" /usr/local/bin/warren-server
  put 0644 "$work/warren-server.service" /etc/systemd/system/warren-server.service
  if [ -z "$upgrade" ]; then
    mkdir -p /etc/warren
    printf 'domain = "%s"\nacme_email = "%s"\n' "$domain" "$email" > /etc/warren/server.toml
    say "Wrote /etc/warren/server.toml; more options: https://github.com/$repo/blob/main/dist/server.toml"
  fi
  systemctl daemon-reload
  systemctl enable warren-server >/dev/null 2>&1
  systemctl restart warren-server
  say "$(/usr/local/bin/warren-server --version) is running"
  if [ -z "$upgrade" ]; then
    echo "Open the one-time setup link to create the admin account:"
    echo "  journalctl -u warren-server | grep setup"
    echo "Open ports 80/tcp, 443/tcp and 51820/udp if a firewall is in front of this server."
  fi
}

has_wireguard_go() {
  command -v wireguard-go >/dev/null 2>&1 ||
    [ -x /opt/homebrew/bin/wireguard-go ] || [ -x /usr/local/bin/wireguard-go ]
}

install_agent() {
  case "$(uname -m)" in
    x86_64 | amd64) arch=x86_64 ;;
    aarch64 | arm64) arch=aarch64 ;;
    armv7*) arch=armv7 ;;
    *) die "no agent build for $(uname -m)" ;;
  esac
  asset=warren-linux-$arch
  plist=/Library/LaunchDaemons/org.slopworks.warren.plist
  if [ "$os" = Darwin ]; then
    [ "$arch" = armv7 ] && die "no agent build for $(uname -m)"
    # Homebrew refuses to run as root, so the installer cannot do this itself.
    has_wireguard_go || die "the agent needs wireguard-go; install it first: brew install wireguard-go"
    bin=/usr/local/bin/warren asset=warren-macos-$arch
    say "Downloading the agent ($version, macOS $arch)"
    download "$asset" org.slopworks.warren.plist
    put 0644 "$work/org.slopworks.warren.plist" "$plist"
  elif [ -f /etc/openwrt_release ]; then
    bin=/usr/bin/warren
    say "Installing kmod-wireguard"
    if command -v apk >/dev/null 2>&1; then
      apk info -e kmod-wireguard >/dev/null || { apk update >/dev/null && apk add kmod-wireguard; }
    elif ! opkg list-installed | grep -q '^kmod-wireguard '; then
      opkg update >/dev/null && opkg install kmod-wireguard
    fi
    say "Downloading the agent ($version, $arch)"
    download "$asset" warren.init warren.uci-defaults
    put 0755 "$work/warren.init" /etc/init.d/warren
    # The firewall zone for the tunnel; the script does nothing if it exists.
    sh "$work/warren.uci-defaults"
  else
    bin=/usr/local/bin/warren
    modprobe wireguard 2>/dev/null ||
      echo "warning: cannot load the wireguard kernel module; the agent needs it" >&2
    say "Downloading the agent ($version, $arch)"
    download "$asset" warren.service
    if has_systemd; then
      put 0644 "$work/warren.service" /etc/systemd/system/warren.service
      systemctl daemon-reload
    fi
  fi
  put 0755 "$work/$asset" "$bin"
  say "Installed $("$bin" version) to $bin"

  if [ -n "$token" ]; then
    [ -n "$server" ] || die "--token needs --server"
    set -- up --server "$server" --token "$token"
    [ -n "$name" ] && set -- "$@" --name "$name"
    "$bin" "$@"
  fi
  if [ ! -f /etc/warren/agent.conf ]; then
    echo "Not registered yet. Create a token in the admin (Devices → Add device), then:"
    echo "  $bin up --server https://warren.example.com --token wrt_…"
    echo "and run this installer again, or start the service yourself."
    return
  fi
  if [ "$os" = Darwin ]; then
    launchctl bootout system/org.slopworks.warren 2>/dev/null || true
    launchctl bootstrap system "$plist"
  elif [ -f /etc/openwrt_release ]; then
    /etc/init.d/warren enable
    /etc/init.d/warren restart
  elif has_systemd; then
    systemctl enable warren >/dev/null 2>&1
    systemctl restart warren
  else
    echo "No systemd: run '$bin run' under your init system."
    return
  fi
  say "The agent is running; check it with: warren status"
}

"install_$mode"
