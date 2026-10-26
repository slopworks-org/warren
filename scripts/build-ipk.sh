#!/bin/sh
# Packages the aarch64 agent as an OpenWrt .ipk (opkg, OpenWrt ≤ 24.10):
#   scripts/build-ipk.sh [opkg-architecture]   (default: aarch64_cortex-a53)
# Check your router's architecture with `opkg print-architecture`.
set -eu
cd "$(dirname "$0")/.."
pkg_arch="${1:-aarch64_cortex-a53}"
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
scripts/build-agent.sh aarch64 >/dev/null
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/data/usr/bin" "$work/data/etc/init.d" "$work/data/etc/uci-defaults" "$work/control"
install -m 0755 dist/out/warren-linux-aarch64 "$work/data/usr/bin/warren"
install -m 0755 dist/openwrt/warren.init "$work/data/etc/init.d/warren"
install -m 0755 dist/openwrt/warren.uci-defaults "$work/data/etc/uci-defaults/90-warren"
size=$(du -sk "$work/data" | cut -f1)
cat > "$work/control/control" <<CTRL
Package: warren
Version: $version
Depends: kmod-wireguard
Architecture: $pkg_arch
Installed-Size: $((size * 1024))
Maintainer: Warren
Description: Warren agent: keeps this router connected to a Warren server over WireGuard.
CTRL
cat > "$work/control/postinst" <<'POST'
#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
[ -x /etc/uci-defaults/90-warren ] && /etc/uci-defaults/90-warren && rm -f /etc/uci-defaults/90-warren
/etc/init.d/warren enable
exit 0
POST
cat > "$work/control/prerm" <<'PRERM'
#!/bin/sh
[ -n "$IPKG_INSTROOT" ] && exit 0
/etc/init.d/warren stop
/etc/init.d/warren disable
exit 0
PRERM
chmod 0755 "$work/control/postinst" "$work/control/prerm"
echo "2.0" > "$work/debian-binary"
tarx() { tar --uid 0 --gid 0 --format ustar -czf "$@"; }
(cd "$work/control" && tarx ../control.tar.gz ./control ./postinst ./prerm)
(cd "$work/data" && tarx ../data.tar.gz ./usr ./etc)
out="dist/out/warren_${version}_${pkg_arch}.ipk"
(cd "$work" && tarx pkg.tar.gz ./debian-binary ./control.tar.gz ./data.tar.gz)
mv "$work/pkg.tar.gz" "$out"
ls -l "$out"
