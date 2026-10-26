# Warren

Warren puts the web apps on your router, NAS or home server on the internet
at an HTTPS address. You do not open any ports at home.

It is like Tailscale plus Cloudflare Tunnel, but you host it on one cheap VPS.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/architecture-dark.svg">
  <img alt="Browser → proxy on a VPS → WireGuard tunnel → agent on your device → your app" src="docs/architecture-light.svg">
</picture>

- Your device connects out to the VPS, so Warren works behind NAT and CGNAT.
  Nothing listens on the device.
- The server is one binary of about 9 MB. It has the WireGuard hub, the
  reverse proxy, Let's Encrypt certificates, the web admin, an API and SQLite.
- The agent for OpenWrt routers and Linux boxes is about 470 KB.
- You publish a service with one form, then open
  `https://app.warren.example.com`.
- Each service is public, or it asks for a Warren login, Basic auth or a PIN.
- Phones and laptops connect with the usual WireGuard app and a QR code.

## Get started

You need:

- a Linux VPS with 512 MB of RAM or more;
- a domain, with `warren.example.com` and `*.warren.example.com` pointed at
  the VPS;
- ports 80/tcp, 443/tcp and 51820/udp open on the VPS.

1. Build the binaries on your computer. There are no releases yet. You need
   [just](https://github.com/casey/just) and Rust 1.92 or later, and Docker for
   the server build. The files go to `dist/out/`.
   ```sh
   just server amd64      # or arm64
   just agent aarch64     # or armv7, x86_64
   just ipk               # OpenWrt package
   ```
2. Install the server on the VPS:
   ```sh
   sudo install -m 0755 warren-server-linux-amd64 /usr/local/bin/warren-server
   sudo mkdir -p /etc/warren
   printf 'domain = "warren.example.com"\nacme_email = "you@example.com"\n' | sudo tee /etc/warren/server.toml
   sudo cp dist/systemd/warren-server.service /etc/systemd/system/
   sudo systemctl enable --now warren-server
   ```
   Only `domain` and `acme_email` are required. All other options are in
   [`dist/server.toml`](dist/server.toml).
3. Create the admin account. Open the one-time setup link from the log:
   `journalctl -u warren-server | grep setup`. Or run
   `sudo warren-server create-admin admin`, which prints a password.
4. Add a device. In the admin, go to Devices → Add device → With the agent →
   Create token. Run the `warren up --server … --token wrt_…` command that it
   shows on the device. Then start the agent service (see below).
5. Publish a service. Go to Resources → Publish service. Set the address, the
   device and the port.

<details>
<summary><b>Agent on OpenWrt</b></summary>

```sh
scp -O dist/out/warren_0.1.0_aarch64_cortex-a53.ipk root@192.168.1.1:/tmp/
# on the router
opkg update && opkg install kmod-wireguard /tmp/warren_0.1.0_aarch64_cortex-a53.ipk
warren up --server https://warren.example.com --token wrt_…
/etc/init.d/warren enable && /etc/init.d/warren start
warren status
```

The package holds the aarch64 agent. If `opkg print-architecture` shows a
different aarch64 name, build with `just ipk <arch>`. OpenWrt 25.x
uses apk, so you must install the agent by hand there. Ask your coding agent
how.
</details>

<details>
<summary><b>Agent on plain Linux</b></summary>

```sh
sudo install -m 0755 warren-linux-x86_64 /usr/local/bin/warren
sudo warren up --server https://warren.example.com --token wrt_…
sudo cp dist/systemd/warren.service /etc/systemd/system/ && sudo systemctl enable --now warren
```
</details>

## Also included

Users and roles, two-factor login (TOTP), device ACLs, an audit log, and an
HTTP API for all admin actions.

## Limits

- No DNS-01, so no automatic wildcard certificates. To use your own
  certificate, set `mode = "files"` in the `[tls]` section.
- Only IPv4 inside the tunnel.
- The agent needs kernel WireGuard.
- No mesh between devices, no OIDC, no raw TCP/UDP forwarding, no multiple
  servers.

## Change the code

To learn how Warren works inside, ask your coding agent.
[CLAUDE.md](CLAUDE.md) gives it the map. Run `just check` before you
send a change.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
