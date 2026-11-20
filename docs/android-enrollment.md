# Warren Android enrollment

In the admin, open **Devices → Add device → Warren Android app → Create QR
code**. The creator can set the name, owner when permitted, and expiration
using the same rules as **With the agent**. The QR is returned with the
authenticated creation response. Create another code if the first was used
or expired.

## Client contract

The QR contains `warren://enroll?v=1&server=<encoded-origin>&token=<encoded-token>`.
Percent-decode the query values once. `server` is the configured admin HTTPS
origin, including its public HTTPS port when nonstandard. `token` is the
existing `wrt_` token. Keep it out of logs and telemetry.

1. Generate the WireGuard key pair on the device and keep the private key
   there. Parse the token with the format in
   [`warren_proto::register`](../crates/proto/src/register.rs).
2. Send `POST /agent/v1/register` as `text/plain` over HTTP to the hostname
   from `server` on **TCP 80**. The HTTPS port identifies the admin site.
   Use the ordered `key=value` lines from [`warren up`](../crates/agent/src/up.rs),
   including `token_id`, `pubkey`, and a fresh `nonce`. Report `os=android`
   or an Android platform variant. Sign the request using `sign_request`.
   Send the public token ID and HMAC. Keep the token secret local.
3. On HTTP 200, verify the reply HMAC with `verify_reply` using the same
   nonce before applying the returned `AgentConfig`. HTTP 403 with
   `invalid, used or expired token` means the app should offer a rescan with
   a fresh code. A successful registration consumes the code.
4. Configure WireGuard from the authenticated reply. Fetch configuration
   over the tunnel with `GET /agent/v1/config` at the returned `control`
   address and port (default TCP 7180). Use the UDP peer endpoint in the
   reply (default UDP 51820). The control port is internal to the tunnel.

## Emulator lab

1. Run the server from this branch on isolated Linux with network administration
   privileges. Use kernel WireGuard with `nft`, or the userspace backend with
   `/dev/net/tun`. Use a lab admin hostname resolvable from the emulator and a
   certificate trusted by the admin browser. Make TCP 80 reach Warren's
   plain `listen_http` listener, plus the configured HTTPS admin port and
   WireGuard UDP endpoint. Preserve `/agent/v1/register` on the plain
   listener if a lab proxy maps ports. The v1 QR has no registration port
   override. Disable release checks with `[update]` and `check = false`.
2. Sign in as a lab user, create a QR, and scan it in the emulator. Confirm
   that an agent device appears under the selected owner, establishes a
   WireGuard handshake, and can fetch its in-tunnel configuration.
3. From a clean app profile, scan the same code again and expect HTTP 403 and
   no second device. Create a fresh QR with the shortest lifetime, let it
   expire, and expect the same result. Generate another code and confirm
   registration succeeds. Use **With the agent** and **WireGuard config** to
   check the two existing add-device flows.
