//! `warren up`: one-time registration with a token.

use crate::cli::Args;
use crate::error::{Error, Result};
use crate::state::{self, DEFAULT_MTU, Saved};
use crate::{http, tunnel};
use std::time::Duration;
use warren_proto::register::{self, RegToken};
use warren_proto::{AgentConfig, Kv, REGISTER_PATH, codec};

/// Splits a `--server` value into the address to connect to and the Host
/// header. Registration is plain HTTP: port 80 unless an `http://` URL names
/// another port (an `https://` port is the TLS port and is ignored).
pub fn register_target(server: &str) -> Result<(String, String)> {
    let bad = || Error::Usage(format!("cannot parse server address {server:?}"));
    let (plain_http, rest) = match server.split_once("://") {
        Some(("http", r)) => (true, r),
        Some(("https", r)) => (false, r),
        Some(_) => return Err(bad()),
        None => (false, server),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']').ok_or_else(bad)?;
        (format!("[{h}]"), after.strip_prefix(':'))
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), Some(p)),
            None => (authority.to_string(), None),
        }
    };
    if host.is_empty() || host.contains('@') {
        return Err(bad());
    }
    let port = match port {
        Some(p) if plain_http => p.parse::<u16>().map_err(|_| bad())?,
        Some(p) => {
            p.parse::<u16>().map_err(|_| bad())?;
            80
        }
        None => 80,
    };
    let host_header = if port == 80 { host.clone() } else { format!("{host}:{port}") };
    Ok((format!("{host}:{port}"), host_header))
}

pub fn hostname() -> String {
    let mut buf = [0u8; 256];
    // SAFETY: gethostname writes at most `buf.len()` bytes into `buf`.
    let r = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), buf.len()) };
    let len = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..len]).trim().to_string())
        .filter(|s| r == 0 && !s.is_empty())
        .unwrap_or_else(|| "device".to_string())
}

pub fn os_tag() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

fn server_error(r: &http::Response) -> Error {
    let message = Kv::parse(&r.body)
        .ok()
        .and_then(|kv| kv.get("error").map(str::to_string))
        .unwrap_or_else(|| r.body.chars().take(200).collect());
    Error::Server { status: r.status, message }
}

pub fn run(args: &Args) -> Result<()> {
    let (Some(server), Some(token)) = (&args.server, &args.token) else {
        return Err(Error::Usage("`warren up` needs --server and --token".into()));
    };
    let token = RegToken::parse(token).ok_or_else(|| Error::Usage("malformed token".into()))?;
    let paths = &args.paths;
    if paths.config().exists() && !args.force {
        return Err(Error::Usage(format!(
            "already registered ({} exists); pass --force to register again",
            paths.config().display()
        )));
    }
    let (addr, host) = register_target(server)?;

    let (private, public) = state::generate_keypair()?;
    let nonce = codec::hex_encode(&state::random_bytes::<16>()?);
    let mut req = Kv::new();
    req.push("token_id", token.id_hex());
    req.push("pubkey", codec::encode_key(&public));
    req.push("name", args.name.clone().unwrap_or_else(hostname));
    req.push("hostname", hostname());
    req.push("os", os_tag());
    req.push("version", warren_proto::VERSION);
    req.push("nonce", &nonce);
    register::sign_request(&token.secret, &mut req);

    crate::log!(Info, "registering", server = addr, token = token.id_hex());
    let resp = http::request(&addr, &host, "POST", REGISTER_PATH, Some(&req.encode()), Duration::from_secs(30))
        .map_err(Error::io(format!("contacting {addr}")))?;
    if resp.status != 200 {
        return Err(server_error(&resp));
    }
    let reply = Kv::parse(&resp.body).map_err(|source| Error::Format { what: "registration reply", source })?;
    if !register::verify_reply(&token.secret, &nonce, &reply) {
        return Err(Error::BadReply("registration reply failed authentication"));
    }
    let tunnel_cfg =
        AgentConfig::from_kv(&reply).map_err(|source| Error::Format { what: "registration reply", source })?;

    let saved =
        Saved { server: server.clone(), interface: args.interface.clone(), mtu: DEFAULT_MTU, tunnel: tunnel_cfg };
    state::store_key(&paths.key(), &private)?;
    saved.store(&paths.config())?;
    println!("Registered as {:?} with address {}.", saved.tunnel.name, saved.tunnel.address);

    match tunnel::apply(&saved, &private) {
        Ok(()) => println!("Interface {} is configured.", saved.interface),
        Err(e) => println!("Could not configure the interface yet: {e}"),
    }
    println!(
        "Keep the tunnel up by running the service:\n  \
         OpenWrt: /etc/init.d/warren enable && /etc/init.d/warren start\n  \
         systemd: systemctl enable --now warren\n  \
         macOS:   launchctl bootstrap system /Library/LaunchDaemons/org.slopworks.warren.plist\n  \
         other:   warren run"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_targets() {
        let t = |s| register_target(s).unwrap();
        assert_eq!(t("https://vpn.example.com"), ("vpn.example.com:80".into(), "vpn.example.com".into()));
        assert_eq!(t("https://vpn.example.com:8443/x"), ("vpn.example.com:80".into(), "vpn.example.com".into()));
        assert_eq!(t("http://10.0.0.1:8080"), ("10.0.0.1:8080".into(), "10.0.0.1:8080".into()));
        assert_eq!(t("vpn.example.com"), ("vpn.example.com:80".into(), "vpn.example.com".into()));
        assert_eq!(t("http://[fd00::1]:81/"), ("[fd00::1]:81".into(), "[fd00::1]:81".into()));
        assert!(register_target("ftp://x").is_err());
        assert!(register_target("http://").is_err());
        assert!(register_target("http://x:notaport").is_err());
        assert!(register_target("http://user@x").is_err());
    }
}
