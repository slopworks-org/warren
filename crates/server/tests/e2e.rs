//! End-to-end test: agent → tunnel → reverse proxy → HTTP service on the device.
//!
//! Runs the real binaries. The "device" lives in its own network namespace,
//! connected to the host by a veth pair, and serves HTTP (and a WebSocket
//! echo) on a port that is only reachable through the tunnel. A second
//! namespace plays an agentless device configured from the generated
//! `wg-quick` file. Needs Linux, root and `ip`, `wg`, `curl`; run it with
//! `scripts/e2e.sh`, which builds everything in a privileged container.

#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

const DOMAIN: &str = "test.warren";

fn run(args: &[&str]) -> std::process::Output {
    Command::new(args[0]).args(&args[1..]).output().unwrap_or_else(|e| panic!("{args:?}: {e}"))
}

fn must(args: &[&str]) -> String {
    let out = run(args);
    assert!(out.status.success(), "{args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn wait_for(what: &str, timeout: Duration, mut f: impl FnMut() -> bool) {
    let start = Instant::now();
    while !f() {
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        thread::sleep(Duration::from_millis(250));
    }
}

/// A network namespace joined to the host by a veth pair; removed on drop.
struct Netns {
    name: String,
    host_if: String,
}

impl Netns {
    fn new(name: &str, subnet: &str) -> Netns {
        let _ = run(&["ip", "netns", "del", name]);
        let host_if = format!("{name}h");
        let dev_if = format!("{name}d");
        let _ = run(&["ip", "link", "del", &host_if]);
        must(&["ip", "netns", "add", name]);
        must(&["ip", "link", "add", &host_if, "type", "veth", "peer", "name", &dev_if]);
        must(&["ip", "link", "set", &dev_if, "netns", name]);
        must(&["ip", "addr", "add", &format!("{subnet}.1/24"), "dev", &host_if]);
        must(&["ip", "link", "set", &host_if, "up"]);
        must(&["ip", "netns", "exec", name, "ip", "addr", "add", &format!("{subnet}.2/24"), "dev", &dev_if]);
        must(&["ip", "netns", "exec", name, "ip", "link", "set", &dev_if, "up"]);
        must(&["ip", "netns", "exec", name, "ip", "link", "set", "lo", "up"]);
        must(&["ip", "netns", "exec", name, "ip", "route", "add", "default", "via", &format!("{subnet}.1")]);
        Netns { name: name.to_string(), host_if }
    }

    /// A namespace behind `router`, joined to it by a veth pair. The router
    /// gets `{subnet}.1` and is the default route.
    fn behind(name: &str, router: &Netns, subnet: &str) -> Netns {
        let _ = run(&["ip", "netns", "del", name]);
        let (router_if, dev_if) = (format!("{name}r"), format!("{name}d"));
        must(&["ip", "netns", "add", name]);
        must(&["ip", "link", "add", &router_if, "type", "veth", "peer", "name", &dev_if]);
        must(&["ip", "link", "set", &router_if, "netns", &router.name]);
        must(&["ip", "link", "set", &dev_if, "netns", name]);
        router.must(&["ip", "addr", "add", &format!("{subnet}.1/24"), "dev", &router_if]);
        router.must(&["ip", "link", "set", &router_if, "up"]);
        let ns = Netns { name: name.to_string(), host_if: router_if };
        ns.must(&["ip", "addr", "add", &format!("{subnet}.2/24"), "dev", &dev_if]);
        ns.must(&["ip", "link", "set", &dev_if, "up"]);
        ns.must(&["ip", "link", "set", "lo", "up"]);
        ns.must(&["ip", "route", "add", "default", "via", &format!("{subnet}.1")]);
        ns
    }

    fn must(&self, args: &[&str]) {
        let out = self.exec(args);
        assert!(out.status.success(), "{args:?} in {}: {}", self.name, String::from_utf8_lossy(&out.stderr));
    }

    fn exec(&self, args: &[&str]) -> std::process::Output {
        let mut full = vec!["ip", "netns", "exec", &self.name];
        full.extend_from_slice(args);
        run(&full)
    }

    fn spawn(&self, args: &[&str], log: &Path) -> Guard {
        let f = fs::File::create(log).unwrap();
        let child = Command::new("ip")
            .args(["netns", "exec", &self.name])
            .args(args)
            .stdout(Stdio::from(f.try_clone().unwrap()))
            .stderr(Stdio::from(f))
            .spawn()
            .unwrap();
        Guard(Some(child))
    }

    /// Serves HTTP and a WebSocket echo on `port` inside the namespace.
    fn serve(&self, port: u16) {
        let ns = fs::File::open(format!("/run/netns/{}", self.name)).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            // SAFETY: setns on this thread only; the fd is a valid netns handle.
            assert_eq!(unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) }, 0);
            let listener = TcpListener::bind(("0.0.0.0", port)).unwrap();
            tx.send(()).unwrap();
            for conn in listener.incoming().flatten() {
                thread::spawn(move || device_service(conn));
            }
        });
        rx.recv().unwrap();
    }
}

impl Drop for Netns {
    fn drop(&mut self) {
        let _ = run(&["ip", "netns", "del", &self.name]);
        let _ = run(&["ip", "link", "del", &self.host_if]);
    }
}

/// Kills a child process on drop.
struct Guard(Option<Child>);

impl Guard {
    fn terminate(&mut self) {
        if let Some(mut c) = self.0.take() {
            // SAFETY: plain kill(2) on our own child.
            unsafe { libc::kill(i32::try_from(c.id()).unwrap(), libc::SIGTERM) };
            let deadline = Instant::now() + Duration::from_secs(10);
            while c.try_wait().unwrap().is_none() {
                if Instant::now() > deadline {
                    let _ = c.kill();
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

fn ws_accept(key: &str) -> String {
    use sha1::{Digest, Sha1};
    let digest = Sha1::digest(format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC11B85").as_bytes());
    warren_proto::codec::b64_encode(&digest)
}

/// The HTTP service on the device: echoes request headers, or upgrades to a
/// WebSocket that echoes text frames.
fn device_service(mut conn: TcpStream) {
    let mut reader = BufReader::new(conn.try_clone().unwrap());
    let mut head = Vec::new();
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
            break;
        }
        head.push(line.trim_end().to_string());
    }
    let header = |name: &str| {
        head.iter().find_map(|l| {
            l.split_once(':').filter(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.trim().to_string())
        })
    };
    if let Some(key) = header("sec-websocket-key") {
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            ws_accept(&key)
        );
        conn.write_all(resp.as_bytes()).unwrap();
        while let Some(text) = read_frame(&mut reader) {
            conn.write_all(&frame(&text, None)).unwrap();
        }
        return;
    }
    let body = format!("hello from device\n{}\n", head.join("\n").to_lowercase());
    let resp = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
    let _ = conn.write_all(resp.as_bytes());
}

fn frame(text: &str, mask: Option<[u8; 4]>) -> Vec<u8> {
    let data = text.as_bytes();
    // Test frames are short, so the 7-bit length form suffices.
    let len = u8::try_from(data.len()).ok().filter(|l| *l < 126).unwrap();
    let mut f = vec![0x81, len | if mask.is_some() { 0x80 } else { 0 }];
    match mask {
        Some(m) => {
            f.extend_from_slice(&m);
            f.extend(data.iter().enumerate().map(|(i, b)| b ^ m[i % 4]));
        }
        None => f.extend_from_slice(data),
    }
    f
}

fn read_frame(r: &mut impl Read) -> Option<String> {
    let mut h = [0u8; 2];
    r.read_exact(&mut h).ok()?;
    let len = usize::from(h[1] & 0x7f);
    let mask = if h[1] & 0x80 != 0 {
        let mut m = [0u8; 4];
        r.read_exact(&mut m).ok()?;
        Some(m)
    } else {
        None
    };
    let mut data = vec![0u8; len];
    r.read_exact(&mut data).ok()?;
    if let Some(m) = mask {
        data.iter_mut().enumerate().for_each(|(i, b)| *b ^= m[i % 4]);
    }
    String::from_utf8(data).ok()
}

#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _: &rustls::pki_types::CertificateDer<'_>,
        _: &[rustls::pki_types::CertificateDer<'_>],
        _: &rustls::pki_types::ServerName<'_>,
        _: &[u8],
        _: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &rustls::pki_types::CertificateDer<'_>,
        d: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Opens a WebSocket through the proxy, sends a text frame and returns the echo.
fn websocket_echo(port: u16, host: &str, text: &str) -> String {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
        .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
    let conn = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
    let tcp = TcpStream::connect(("127.0.0.1", port)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let mut tls = rustls::StreamOwned::new(conn, tcp);
    let req = format!(
        "GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    tls.write_all(req.as_bytes()).unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        tls.read_exact(&mut byte).unwrap();
        head.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&head);
    assert!(head.starts_with("HTTP/1.1 101"), "websocket handshake failed: {head}");
    assert!(head.contains(&ws_accept("dGhlIHNhbXBsZSBub25jZQ==")));
    tls.write_all(&frame(text, Some([1, 2, 3, 4]))).unwrap();
    read_frame(&mut tls).unwrap()
}

struct Resp {
    status: u16,
    body: String,
    headers: String,
}

impl Resp {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|e| panic!("bad JSON ({e}): {}", self.body))
    }
}

/// A curl-based HTTPS client with a cookie jar.
struct Client {
    port: u16,
    jar: PathBuf,
    csrf: String,
    dir: PathBuf,
}

impl Client {
    fn new(dir: &Path, name: &str, port: u16) -> Client {
        Client { port, jar: dir.join(format!("{name}.jar")), csrf: String::new(), dir: dir.to_owned() }
    }

    /// Raw request; `None` status means the connection or TLS failed.
    fn try_request(&self, method: &str, url: &str, body: Option<&str>, extra: &[&str]) -> Option<Resp> {
        let headers_file = self.dir.join("headers.txt");
        // Every name the test uses, so redirects between hosts resolve too.
        let resolves: Vec<String> = ["", "app.", "pin.", "basic.", "private.", "down.", "nope."]
            .iter()
            .map(|p| format!("{p}{DOMAIN}:{}:127.0.0.1", self.port))
            .collect();
        let csrf = format!("X-CSRF-Token: {}", self.csrf);
        let jar = self.jar.to_str().unwrap();
        let mut args = vec![
            "-sk",
            "--max-time",
            "15",
            "-X",
            method,
            "-b",
            jar,
            "-c",
            jar,
            "-D",
            headers_file.to_str().unwrap(),
            "-H",
            &csrf,
            "-w",
            "\n%{http_code}",
        ];
        for r in &resolves {
            args.extend_from_slice(&["--resolve", r]);
        }
        if let Some(b) = body {
            args.extend_from_slice(&["-H", "Content-Type: application/json", "--data-binary", b]);
        }
        args.extend_from_slice(extra);
        args.push(url);
        let out = Command::new("curl").args(&args).output().unwrap();
        if !out.status.success() {
            return None;
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let (body, code) = text.rsplit_once('\n').unwrap();
        Some(Resp {
            status: code.parse().unwrap(),
            body: body.to_string(),
            headers: fs::read_to_string(&headers_file).unwrap_or_default(),
        })
    }

    fn request(&self, method: &str, url: &str, body: Option<&str>, extra: &[&str]) -> Resp {
        self.try_request(method, url, body, extra).unwrap_or_else(|| panic!("{method} {url}: connection failed"))
    }

    fn admin_url(&self, path: &str) -> String {
        format!("https://{DOMAIN}:{}{path}", self.port)
    }

    fn api(&self, method: &str, path: &str, body: Option<Value>) -> Resp {
        let body = body.map(|b| b.to_string());
        self.request(method, &self.admin_url(&format!("/api/v1{path}")), body.as_deref(), &[])
    }

    fn ok(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let r = self.api(method, path, body);
        assert!(r.status == 200, "{method} {path} → {}: {}", r.status, r.body);
        r.json()
    }

    fn login(&mut self, user: &str, password: &str) -> Value {
        let r = self.api("POST", "/auth/login", Some(json!({ "username": user, "password": password })));
        assert_eq!(r.status, 200, "login: {}", r.body);
        let v = r.json();
        if v["mfa_required"] == json!(false) {
            self.csrf = self.ok("GET", "/me", None)["csrf"].as_str().unwrap().to_string();
        }
        v
    }

    fn get(&self, url: &str) -> Resp {
        self.request("GET", url, None, &[])
    }
}

struct Scenario {
    tag: &'static str,
    backend: &'static str,
    subnet: &'static str,
    manual_subnet: &'static str,
    lan_subnet: &'static str,
    network: &'static str,
    http_port: u16,
    https_port: u16,
    wg_port: u16,
}

fn scenario(s: &Scenario) {
    // SAFETY: getuid has no preconditions.
    assert_eq!(unsafe { libc::getuid() }, 0, "the end-to-end test needs root; run scripts/e2e.sh");
    let server_bin = PathBuf::from(env!("CARGO_BIN_EXE_warren-server"));
    let agent_bin = server_bin.with_file_name("warren");
    assert!(agent_bin.exists(), "build the agent first (cargo build --workspace)");
    let server_bin = server_bin.to_str().unwrap();

    // /run can be mounted noexec and paths under /tmp are not protected.
    let dir = PathBuf::from(must(&["mktemp", "-d", &format!("/var/lib/warren-e2e-{}-XXXXXX", s.tag)]).trim());
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    // Each container owns its service locks even when Cargo artifacts are shared.
    let test_agent_bin = dir.join("warren");
    fs::copy(agent_bin, &test_agent_bin).unwrap();
    let agent_bin = test_agent_bin.to_str().unwrap();
    let dev = Netns::new(&format!("wd{}", s.tag), s.subnet);
    let hub_ip = format!("{}.1", s.subnet);
    let server_iface = format!("wrs{}", s.tag);

    let config = dir.join("server.toml");
    fs::write(
        &config,
        format!(
            "domain = \"{DOMAIN}\"\ndata_dir = \"{}\"\nlisten_http = \"0.0.0.0:{}\"\nlisten_https = \"0.0.0.0:{}\"\n\
             [tls]\nmode = \"self-signed\"\n[wireguard]\nbackend = \"{}\"\ninterface = \"{server_iface}\"\nport = {}\n\
             network = \"{}\"\nendpoint = \"{hub_ip}:{}\"\n[log]\nlevel = \"debug\"\n",
            dir.join("data").display(),
            s.http_port,
            s.https_port,
            s.backend,
            s.wg_port,
            s.network,
            s.wg_port
        ),
    )
    .unwrap();
    let cfg = config.to_str().unwrap();

    // First administrator from the CLI.
    let mut create = Command::new(server_bin)
        .args(["--config", cfg, "create-admin", "admin", "--password-stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();
    create.stdin.take().unwrap().write_all(b"admin-password-1\n").unwrap();
    assert!(create.wait().unwrap().success());

    let log = fs::File::create(dir.join("server.log")).unwrap();
    let mut server = Guard(Some(
        Command::new(server_bin)
            .args(["--config", cfg])
            .stdout(Stdio::from(log.try_clone().unwrap()))
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap(),
    ));
    let mut admin = Client::new(&dir, "admin", s.https_port);
    wait_for("the server", Duration::from_secs(20), || {
        admin.try_request("GET", &admin.admin_url("/api/v1/auth/status"), None, &[]).is_some_and(|r| r.status == 200)
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        flows(s, &dir, &dev, &mut admin, agent_bin);
    }));
    if let Err(panic) = result {
        eprintln!("---- server log ----\n{}", fs::read_to_string(dir.join("server.log")).unwrap_or_default());
        for f in ["agent.log", "agent2.log", "nas.log"] {
            eprintln!("---- {f} ----\n{}", fs::read_to_string(dir.join(f)).unwrap_or_default());
        }
        std::panic::resume_unwind(panic);
    }

    // A clean shutdown removes the hub interface.
    server.terminate();
    assert!(warren_wgctl::link_index(&server_iface).is_none(), "hub interface left behind");
    fs::remove_dir_all(dir).unwrap();
}

/// The agent under test: its daemon process and how to restart it.
struct Agent {
    daemon: Guard,
    run_args: Vec<String>,
    iface: String,
    id: i64,
    addr: String,
}

fn agent_args<'a>(base: &'a [String], extra: &[&'a str]) -> Vec<&'a str> {
    let mut v: Vec<&str> = extra.to_vec();
    v.extend(base.iter().map(String::as_str));
    v
}

fn flows(s: &Scenario, dir: &Path, dev: &Netns, admin: &mut Client, agent_bin: &str) {
    admin.login("admin", "admin-password-1");
    assert_eq!(admin.ok("GET", "/me", None)["user"]["role"], "admin");
    let mut agent = register_agent(s, dir, dev, admin, agent_bin);
    check_public_proxy(s, admin, &agent);
    check_local_consent(s, dev, admin, &agent);
    let visitor = Client::new(dir, "visitor", s.https_port);
    check_pin_and_basic(s, admin, &visitor, agent.id);
    let (bob, bob_id) = check_users_mode(s, dir, admin, &visitor, agent.id);
    let bob = check_two_factor(bob);
    check_mandatory_2fa(dir, admin, s.https_port);
    check_api_token(dir, admin, s.https_port);
    check_agentless_and_acl(s, dir, admin, &bob, bob_id, &agent);
    check_lan_peers(s, dir, dev, admin, agent_bin, &agent);
    check_failures_restart_revoke(s, dir, dev, admin, &visitor, &mut agent);
    check_audit(admin, &bob);
}

/// Registers over plain HTTP with a token, then runs the daemon.
fn register_agent(s: &Scenario, dir: &Path, dev: &Netns, admin: &Client, agent_bin: &str) -> Agent {
    let token = admin.ok("POST", "/devices/tokens", Some(json!({ "name": "router" })));
    let token = token["token"].as_str().unwrap();
    let agent_dir = dir.join("agent");
    let cfg_dir = agent_dir.join("etc");
    let iface = format!("wra{}", s.tag);
    let common: Vec<String> = [
        "--config-dir",
        cfg_dir.to_str().unwrap(),
        "--run-dir",
        agent_dir.join("runtime/run").to_str().unwrap(),
        "--interface",
        &iface,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    let server_url = format!("http://{}.1:{}", s.subnet, s.http_port);
    let up = agent_args(&common, &[agent_bin, "up", "--server", &server_url, "--token", token]);
    let out = dev.exec(&up);
    let output = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "warren up: {output}");
    assert!(!dev.exec(&up).status.success(), "a second `up` without --force must fail");
    let key_mode = fs::metadata(cfg_dir.join("private.key")).unwrap();
    assert_eq!(key_mode.permissions().mode() & 0o777, 0o600);

    let installed = agent_dir.join("warren");
    fs::copy(agent_bin, &installed).unwrap();
    let previous = fs::metadata(&installed).unwrap().ino();
    let (failed_trial, _) = stage_agent_update(&installed, &cfg_dir, "9.0.0", |candidate| {
        fs::write(candidate, "#!/bin/sh\nif [ \"$1\" = version ]; then echo warren 9.0.0; else exit 77; fi\n").unwrap();
    });
    let run_args: Vec<String> =
        agent_args(&common, &[installed.to_str().unwrap(), "run"]).into_iter().map(ToString::to_string).collect();
    let log = dir.join("agent.log");
    let mut restrictive = vec!["sh", "-c", r#"umask 077; exec "$@""#, "sh"];
    restrictive.extend(run_args.iter().map(String::as_str));
    let daemon = dev.spawn(&restrictive, &log);
    dev.serve(8000);
    dev.must(&agent_args(&common, &[agent_bin, "expose", "app", "8000"]));
    dev.must(&agent_args(&common, &[agent_bin, "expose", "down", "9"]));

    let device = || admin.ok("GET", "/devices", None)[0].clone();
    wait_for("the device to come online", Duration::from_secs(30), || device()["online"] == json!(true));
    wait_for("service advertisement", Duration::from_secs(10), || device()["services"]["app"] == "http");
    assert!(!failed_trial.exists());
    assert_eq!(fs::metadata(&installed).unwrap().ino(), previous);
    assert!(fs::read_to_string(&log).unwrap().contains("exit status: 77"));
    let (id, addr) = (device()["id"].as_i64().unwrap(), device()["address"].as_str().unwrap().to_string());
    assert_eq!(device()["name"], "router");
    let status = dev.exec(&agent_args(&common, &[agent_bin, "status"]));
    let status = String::from_utf8_lossy(&status.stdout);
    assert!(status.contains(&addr) && status.contains("Handshake:"), "status output: {status}");
    assert!(status.contains("Control:    connected"), "first poll is immediate: {status}");
    assert_eq!(fs::metadata(agent_dir.join("runtime")).unwrap().permissions().mode() & 0o777, 0o755);
    assert_status_permissions(&agent_dir.join("runtime/run"), 0o755);
    let unprivileged = ["setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", agent_bin, "status"];
    let status = dev.exec(&agent_args(&common, &unprivileged));
    assert!(status.status.success(), "unprivileged status: {}", String::from_utf8_lossy(&status.stderr));
    let status = String::from_utf8_lossy(&status.stdout);
    assert!(status.contains("Version:    v") && status.contains("Control:    connected, last contact"), "{status}");
    assert!(status.contains("(config v") && !status.contains("Handshake:"), "{status}");
    check_live_updates(dev, agent_bin, &installed, &cfg_dir, &daemon, &log);
    Agent { daemon, run_args, iface, id, addr }
}

/// Publishes the verified-download handoff without depending on GitHub in e2e.
fn stage_agent_update(
    installed: &Path,
    config: &Path,
    version: &str,
    write_candidate: impl FnOnce(&Path),
) -> (PathBuf, u64) {
    publish_agent_update(installed, config, version, None, write_candidate)
}

fn publish_agent_update(
    installed: &Path,
    config: &Path,
    version: &str,
    consent: Option<&str>,
    write_candidate: impl FnOnce(&Path),
) -> (PathBuf, u64) {
    let lock_path = executable_lock(installed, "update");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(lock_path.parent().unwrap()).unwrap();
    let update_lock =
        fs::OpenOptions::new().read(true).write(true).create(true).truncate(false).open(lock_path).unwrap();
    update_lock.lock().unwrap();
    let key = fs::read_to_string(config.join("private.key")).unwrap();
    let tag = warren_proto::asset_sha256(&warren_proto::codec::decode_key(key.trim()).unwrap());
    let candidate = installed.with_extension(format!("{tag}.update-candidate"));
    let request = installed.with_extension(format!("{tag}.update-request"));
    let tmp = request.with_extension("tmp");
    write_candidate(&candidate);
    fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755)).unwrap();
    let (old, new) = (fs::metadata(installed).unwrap(), fs::metadata(&candidate).unwrap());
    let mut kv = warren_proto::Kv::new();
    kv.push("installed_dev", old.dev().to_string());
    kv.push("installed_ino", old.ino().to_string());
    kv.push("installed_sha256", warren_proto::asset_sha256(&fs::read(installed).unwrap()));
    kv.push("candidate_dev", new.dev().to_string());
    kv.push("candidate_ino", new.ino().to_string());
    kv.push("candidate_sha256", warren_proto::asset_sha256(&fs::read(&candidate).unwrap()));
    kv.push("version", version);
    kv.push("remote", if consent.is_some() { "on" } else { "off" });
    if let Some(consent) = consent {
        kv.push("consent", consent);
    }
    kv.push("registration", &tag);
    fs::write(&tmp, kv.encode()).unwrap();
    fs::rename(tmp, &request).unwrap();
    (request, new.ino())
}

fn executable_lock(installed: &Path, role: &str) -> PathBuf {
    let directory = fs::metadata(installed.parent().unwrap()).unwrap();
    let name = warren_proto::asset_sha256(installed.file_name().unwrap().as_encoded_bytes());
    Path::new("/run/warren-locks").join(format!("{}-{}-{name}.{role}", directory.dev(), directory.ino()))
}

fn assert_status_permissions(run: &Path, expected_dir: u32) {
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(run), expected_dir);
    assert_eq!(mode(&run.join("status")), 0o644);
}

fn service_child(pid: u32) -> Option<u32> {
    fs::read_to_string(format!("/proc/{pid}/task/{pid}/children")).ok()?.trim().parse().ok()
}

fn check_live_updates(dev: &Netns, agent_bin: &str, installed: &Path, config: &Path, daemon: &Guard, log: &Path) {
    let pid = daemon.0.as_ref().unwrap().id();
    let status = config.with_file_name("runtime").join("run/status");
    let activation = installed.with_extension("update-activation");
    let connected = || fs::read_to_string(&status).is_ok_and(|state| state.contains("state=connected"));
    let other_config = config.with_file_name("second");
    fs::create_dir(&other_config).unwrap();
    let other = dev.exec(&[installed.to_str().unwrap(), "run", "--config-dir", other_config.to_str().unwrap()]);
    assert!(!other.status.success());
    assert!(String::from_utf8_lossy(&other.stderr).contains("another Warren service is using this executable"));

    let previous = fs::metadata(installed).unwrap().ino();
    let previous_worker = service_child(pid).unwrap();
    let (failed, _) = stage_agent_update(installed, config, "9.0.0", |path| {
        fs::write(
            path,
            format!(
                r#"#!/bin/sh
if [ "$1" = version ]; then echo warren 9.0.0
elif [ -n "${{WARREN_DAEMON_BINARY:-}}${{WARREN_SUPERVISED_EXECUTABLE:-}}" ]; then exec '{agent_bin}' "$@"
else exit 77
fi
"#
            ),
        )
        .unwrap();
    });
    wait_for("the previous worker to recover after a failed supervisor trial", Duration::from_secs(20), || {
        !failed.exists() && connected() && service_child(pid).is_some_and(|worker| worker != previous_worker)
    });
    assert_eq!(fs::metadata(installed).unwrap().ino(), previous);
    let log = fs::read_to_string(log).unwrap();
    assert!(log.contains("confirm supervisor activation (exit status: 77)"), "{log}");

    let staged_from = config.with_file_name("staging-alias");
    fs::create_dir(&staged_from).unwrap();
    let _binding = BindMount::new(config, &staged_from);
    for _ in 0..2 {
        let previous = fs::metadata(installed).unwrap().ino();
        let (request, candidate) = stage_agent_update(installed, &staged_from, warren_proto::VERSION, |path| {
            fs::copy(agent_bin, path).unwrap();
        });
        assert_ne!(candidate, previous);
        wait_for("the updated supervisor to acknowledge activation", Duration::from_secs(20), || {
            !request.exists()
                && !activation.exists()
                && fs::metadata(installed).is_ok_and(|meta| meta.ino() == candidate)
                && fs::metadata(format!("/proc/{pid}/exe")).is_ok_and(|meta| meta.ino() == candidate)
                && service_child(pid).is_some_and(|worker| {
                    fs::metadata(format!("/proc/{worker}/exe")).is_ok_and(|meta| meta.ino() == candidate)
                })
                && connected()
        });
        assert_eq!(fs::metadata(installed).unwrap().ino(), candidate);
    }
}

/// A public resource: HTTP and WebSocket through the tunnel, redirects, and
/// no certificate for unknown names.
fn check_public_proxy(s: &Scenario, admin: &Client, agent: &Agent) {
    let res = admin.ok("POST", "/resources", Some(json!({ "host": "app", "device_id": agent.id, "service": "app" })));
    assert_eq!(res["host"], format!("app.{DOMAIN}"));
    let app = format!("https://app.{DOMAIN}:{}", s.https_port);
    let r = admin.request("GET", &format!("{app}/hello"), None, &["-H", "Cookie: theirs=1; __Host-warren_auth=leak"]);
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.starts_with("hello from device"));
    assert!(r.body.contains("get /hello http/1.1"));
    assert!(r.body.contains("x-forwarded-proto: https"));
    assert!(r.body.contains("x-forwarded-for: 127.0.0.1"));
    assert!(r.body.contains(&format!("x-forwarded-host: app.{DOMAIN}")));
    assert!(r.body.contains("cookie: theirs=1") && !r.body.contains("leak"), "gate cookie must not reach the device");
    let echo = websocket_echo(s.https_port, &format!("app.{DOMAIN}"), "ping through the tunnel");
    assert_eq!(echo, "ping through the tunnel");
    let resolve = format!("app.{DOMAIN}:{}:127.0.0.1", s.http_port);
    let plain =
        admin.request("GET", &format!("http://app.{DOMAIN}:{}/x?y=1", s.http_port), None, &["--resolve", &resolve]);
    assert_eq!(plain.status, 308);
    assert!(plain.headers.to_lowercase().contains(&format!("location: https://app.{DOMAIN}:{}/x?y=1", s.https_port)));

    assert!(admin.try_request("GET", &format!("https://nope.{DOMAIN}:{}/", s.https_port), None, &[]).is_none());
    let by_ip = Command::new("curl")
        .args(["-sk", "--max-time", "5", &format!("https://127.0.0.1:{}/", s.https_port)])
        .status()
        .unwrap();
    assert!(!by_ip.success(), "HTTPS by IP address must fail");
}

fn check_local_consent(s: &Scenario, dev: &Netns, admin: &Client, agent: &Agent) {
    let request = json!({ "host": "unknown", "device_id": agent.id, "service": "missing" });
    assert_eq!(admin.api("POST", "/resources", Some(request)).status, 400);
    let old = json!({ "host": "legacy", "device_id": agent.id, "port": 8000 });
    assert!(admin.api("POST", "/resources", Some(old)).status >= 400);
    let url = format!("https://app.{DOMAIN}:{}/", s.https_port);
    let common = &agent.run_args[2..];
    let bin = agent.run_args[0].as_str();
    dev.must(&agent_args(common, &[bin, "unexpose", "app"]));
    assert_eq!(admin.get(&url).status, 502);
    dev.must(&agent_args(common, &[bin, "expose", "app", "http://127.0.0.1:8000"]));
    wait_for("the service to be republished live", Duration::from_secs(10), || admin.get(&url).status == 200);
    wait_for("the public status to include the published URL", Duration::from_secs(10), || {
        let result = dev.exec(&agent_args(common, &[bin, "expose", "--list"]));
        String::from_utf8_lossy(&result.stdout).contains(url.trim_end_matches('/'))
    });
}

fn check_pin_and_basic(s: &Scenario, admin: &Client, visitor: &Client, dev_id: i64) {
    let pin = admin.ok(
        "POST",
        "/resources",
        Some(json!({ "host": "pin", "device_id": dev_id, "service": "app", "access": "pin", "secret": "4321" })),
    );
    let pin_url = format!("https://pin.{DOMAIN}:{}", s.https_port);
    let r = visitor.get(&format!("{pin_url}/secret"));
    assert_eq!(r.status, 401);
    assert!(r.body.contains("PIN required") && !r.body.contains("hello from device"));
    let bad = visitor.request("POST", &format!("{pin_url}/.warren/pin"), None, &["--data", "pin=0000&next=/secret"]);
    assert_eq!(bad.status, 401);
    let good = visitor.request("POST", &format!("{pin_url}/.warren/pin"), None, &["--data", "pin=4321&next=/secret"]);
    assert_eq!(good.status, 303, "{}", good.body);
    assert_eq!(visitor.get(&format!("{pin_url}/secret")).status, 200);
    // Changing the resource signs PIN visitors out.
    admin.ok("PATCH", &format!("/resources/{}", pin["id"]), Some(json!({ "secret": "9999" })));
    assert_eq!(visitor.get(&format!("{pin_url}/secret")).status, 401);

    let basic = json!({ "host": "basic", "device_id": dev_id, "service": "app", "access": "basic", "basic_user": "u", "secret": "basic-pass" });
    admin.ok("POST", "/resources", Some(basic));
    let basic_url = format!("https://basic.{DOMAIN}:{}/", s.https_port);
    assert_eq!(visitor.get(&basic_url).status, 401);
    assert_eq!(visitor.request("GET", &basic_url, None, &["-u", "u:wrong-pass"]).status, 401);
    let ok = visitor.request("GET", &basic_url, None, &["-u", "u:basic-pass"]);
    assert_eq!(ok.status, 200);
    assert!(!ok.body.contains("authorization:"), "Basic credentials must not reach the device");
}

/// Users mode, a second user and isolation; returns bob's client and id.
fn check_users_mode(s: &Scenario, dir: &Path, admin: &Client, visitor: &Client, dev_id: i64) -> (Client, i64) {
    let users_res = admin.ok(
        "POST",
        "/resources",
        Some(json!({ "host": "private", "device_id": dev_id, "service": "app", "access": "users" })),
    );
    let private = format!("https://private.{DOMAIN}:{}", s.https_port);
    let r = visitor.get(&format!("{private}/inner?a=b"));
    assert_eq!(r.status, 303);
    assert!(r.headers.contains(&format!("https://{DOMAIN}:{}/auth/resource?rid={}", s.https_port, users_res["id"])));
    // The administrator follows the sign-in hop and gets in.
    let signed_in = admin.request("GET", &format!("{private}/inner?a=b"), None, &["-L"]);
    assert_eq!(signed_in.status, 200, "{}", signed_in.body);
    assert!(signed_in.body.contains("get /inner?a=b") && signed_in.body.contains("x-warren-user: admin"));

    let created = admin.ok("POST", "/users", Some(json!({ "username": "bob", "password": "bob-password-1" })));
    let bob_id = created["user"]["id"].as_i64().unwrap();
    let mut bob = Client::new(dir, "bob", s.https_port);
    bob.login("bob", "bob-password-1");
    assert_eq!(bob.ok("GET", "/devices", None), json!([]));
    assert_eq!(bob.ok("GET", "/resources", None), json!([]));
    assert_eq!(bob.api("GET", &format!("/devices/{dev_id}"), None).status, 404);
    assert_eq!(bob.api("DELETE", &format!("/devices/{dev_id}"), None).status, 404);
    assert_eq!(bob.api("GET", "/users", None).status, 403);
    let denied = bob.request("GET", &format!("{private}/"), None, &["-L"]);
    assert_eq!(denied.status, 403, "{}", denied.body);
    // CSRF: a cookie session without the right header cannot change anything.
    let mut no_csrf = Client::new(dir, "bob", s.https_port);
    no_csrf.csrf = "wrong".into();
    assert_eq!(no_csrf.api("POST", "/me/tokens", Some(json!({ "name": "x" }))).status, 403);
    // Granting bob opens it.
    let grants = json!({ "grants": [format!("user:{bob_id}")] });
    admin.ok("PATCH", &format!("/resources/{}", users_res["id"]), Some(grants));
    assert_eq!(bob.request("GET", &format!("{private}/"), None, &["-L"]).status, 200);
    (bob, bob_id)
}

/// Enrols bob in TOTP and signs in again with a code.
fn check_two_factor(mut bob: Client) -> Client {
    let setup = bob.ok("POST", "/me/totp/setup", None);
    let secret = warren_server::util::base32_decode(setup["secret"].as_str().unwrap()).unwrap();
    let step = |offset: i64| u64::try_from(warren_server::util::now() / 30 + offset).unwrap();
    let code = format!("{:06}", warren_server::auth::totp_code(&secret, step(0)));
    bob.ok("POST", "/me/totp/enable", Some(json!({ "code": code })));
    bob.ok("POST", "/auth/logout", None);
    assert_eq!(bob.login("bob", "bob-password-1")["mfa_required"], json!(true));
    assert_eq!(bob.api("GET", "/me", None).status, 401, "password alone is not enough");
    assert_eq!(bob.api("POST", "/auth/totp", Some(json!({ "code": code }))).status, 401, "codes cannot be replayed");
    let next = format!("{:06}", warren_server::auth::totp_code(&secret, step(1)));
    assert_eq!(bob.api("POST", "/auth/totp", Some(json!({ "code": next }))).status, 200);
    bob.csrf = bob.ok("GET", "/me", None)["csrf"].as_str().unwrap().to_string();
    bob
}

fn totp_now(secret_b32: &str) -> String {
    let secret = warren_server::util::base32_decode(secret_b32).unwrap();
    let step = u64::try_from(warren_server::util::now() / 30).unwrap();
    format!("{:06}", warren_server::auth::totp_code(&secret, step))
}

/// Mandatory 2FA: only an administrator who has it may require it, and users
/// without it can still reach the enrolment endpoints (and nothing else).
fn check_mandatory_2fa(dir: &Path, admin: &Client, port: u16) {
    let settings = admin.ok("GET", "/settings", None);
    let mut required = settings.clone();
    required["require_2fa"] = json!(true);
    assert_eq!(
        admin.api("PUT", "/settings", Some(required.clone())).status,
        409,
        "admin without 2FA cannot require it"
    );
    let setup = admin.ok("POST", "/me/totp/setup", None);
    admin.ok("POST", "/me/totp/enable", Some(json!({ "code": totp_now(setup["secret"].as_str().unwrap()) })));
    admin.ok("PUT", "/settings", Some(required));

    admin.ok("POST", "/users", Some(json!({ "username": "carol", "password": "carol-password-1" })));
    let mut carol = Client::new(dir, "carol", port);
    carol.login("carol", "carol-password-1");
    assert_eq!(carol.ok("GET", "/me", None)["must_setup_2fa"], json!(true));
    let r = carol.api("GET", "/devices", None);
    assert_eq!((r.status, r.json()["error"].clone()), (403, json!("2fa_required")));
    let enrol = carol.ok("POST", "/me/totp/setup", None);
    carol.ok("POST", "/me/totp/enable", Some(json!({ "code": totp_now(enrol["secret"].as_str().unwrap()) })));
    assert_eq!(carol.api("GET", "/devices", None).status, 200, "enrolled users get full access");
    admin.ok("PUT", "/settings", Some(settings));
}

/// API tokens work without cookies or CSRF.
fn check_api_token(dir: &Path, admin: &Client, port: u16) {
    let tok = admin.ok("POST", "/me/tokens", Some(json!({ "name": "ci" })))["secret"].as_str().unwrap().to_string();
    let anon = Client::new(dir, "anon", port);
    let auth = format!("Authorization: Bearer {tok}");
    assert_eq!(anon.request("GET", &anon.admin_url("/api/v1/devices"), None, &["-H", &auth]).status, 200);
}

/// An agentless device from the generated config reaches the agent's
/// service; another user's device does not, until an ACL rule allows it.
fn check_agentless_and_acl(s: &Scenario, dir: &Path, admin: &Client, bob: &Client, bob_id: i64, agent: &Agent) {
    let manual_ns = Netns::new(&format!("wm{}", s.tag), s.manual_subnet);
    let manual = admin.ok("POST", "/devices", Some(json!({ "name": "phone" })));
    assert!(manual["qr_svg"].as_str().unwrap().contains("<svg"));
    let manual_ip = manual["device"]["address"].as_str().unwrap().to_string();
    let wg_if = "wgm";
    let bring_up = |conf: &str| {
        let wg_conf: String = conf
            .lines()
            .filter(|l| !l.starts_with("Address") && !l.starts_with('#'))
            .fold(String::new(), |acc, l| acc + l + "\n");
        let path = dir.join("manual.conf");
        fs::write(&path, wg_conf).unwrap();
        let addr = conf.lines().find_map(|l| l.strip_prefix("Address = ")).unwrap().to_string();
        let _ = manual_ns.exec(&["ip", "link", "del", wg_if]);
        assert!(manual_ns.exec(&["ip", "link", "add", wg_if, "type", "wireguard"]).status.success());
        let set = manual_ns.exec(&["wg", "setconf", wg_if, path.to_str().unwrap()]);
        assert!(set.status.success(), "wg setconf: {}", String::from_utf8_lossy(&set.stderr));
        assert!(manual_ns.exec(&["ip", "addr", "add", &addr, "dev", wg_if]).status.success());
        assert!(manual_ns.exec(&["ip", "link", "set", wg_if, "up"]).status.success());
    };
    bring_up(manual["config"].as_str().unwrap());
    let reach_agent = || {
        let out = manual_ns.exec(&["curl", "-s", "--max-time", "3", &format!("http://{}:8000/direct", agent.addr)]);
        String::from_utf8_lossy(&out.stdout).contains("hello from device")
    };
    // Same owner: device to device through the hub.
    assert!(!reach_agent(), "direct TCP requires a client-granted ingress stream");
    let phone = || {
        let devices = admin.ok("GET", "/devices", None);
        devices.as_array().unwrap().iter().find(|d| d["address"] == json!(manual_ip)).unwrap().clone()
    };
    wait_for("the agentless device to show as online", Duration::from_secs(15), || phone()["online"] == json!(true));
    assert_eq!(phone()["kind"], "manual");

    let bobs = admin.ok("POST", "/devices", Some(json!({ "name": "bob-laptop", "user_id": bob_id })));
    bring_up(bobs["config"].as_str().unwrap());
    wait_for("bob's device handshake", Duration::from_secs(20), || {
        bob.ok("GET", "/devices", None)[0]["online"] == json!(true)
    });
    assert!(!reach_agent(), "devices of different users must not see each other");
    let rule = json!({ "src": format!("user:{bob_id}"), "dst": format!("device:{}", agent.id), "ports": "tcp:8000" });
    admin.ok("POST", "/acl", Some(rule));
    assert!(!reach_agent(), "hub ACLs cannot grant local service access");
    let other_port = manual_ns.exec(&["curl", "-s", "--max-time", "3", &format!("http://{}:8001/", agent.addr)]);
    assert!(other_port.stdout.is_empty(), "only the allowed port is open");
}

/// A second agent behind the first one, which acts as a NAT router, talks
/// to it directly over their LAN, and through the hub once that path breaks.
fn check_lan_peers(s: &Scenario, dir: &Path, router: &Netns, admin: &Client, agent_bin: &str, agent: &Agent) {
    let nas = Netns::behind(&format!("wl{}", s.tag), router, s.lan_subnet);
    router.must(&["sysctl", "-qw", "net.ipv4.ip_forward=1"]);
    let nat = format!(
        "add table ip lan; add chain ip lan post {{ type nat hook postrouting priority 100; }}; \
         add rule ip lan post oifname \"wd{}d\" masquerade",
        s.tag
    );
    router.must(&["nft", &nat]);

    let token = admin.ok("POST", "/devices/tokens", Some(json!({ "name": "nas" })));
    let nas_dir = dir.join("nas");
    let iface = format!("wrn{}", s.tag);
    let (cfg_dir, run_dir) = (nas_dir.join("etc"), nas_dir.join("run"));
    let common =
        ["--config-dir", cfg_dir.to_str().unwrap(), "--run-dir", run_dir.to_str().unwrap(), "--interface", &iface];
    let server_url = format!("http://{}.1:{}", s.subnet, s.http_port);
    let mut up = vec![agent_bin, "up", "--server", &server_url, "--token", token["token"].as_str().unwrap()];
    up.extend(common);
    nas.must(&up);
    let mut run_args = vec![agent_bin, "run"];
    run_args.extend(common);
    let mut daemon = nas.spawn(&run_args, &dir.join("nas.log"));
    nas.serve(8000);
    let device = || {
        let devices = admin.ok("GET", "/devices", None);
        devices.as_array().unwrap().iter().find(|d| d["name"] == "nas").unwrap().clone()
    };
    wait_for("the NAS to come online", Duration::from_secs(30), || device()["online"] == json!(true));
    let (nas_id, nas_addr) = (device()["id"].as_i64().unwrap(), device()["address"].as_str().unwrap().to_string());

    let has_route = |ns: &Netns, iface: &str, addr: &str| {
        let out = ns.exec(&["ip", "route", "get", addr]);
        let route = String::from_utf8_lossy(&out.stdout);
        !route.contains(&format!("dev {iface} ")) && route.contains("dev wm")
    };
    let reach_nas = || {
        let out = router.exec(&["curl", "-s", "--max-time", "3", &format!("http://{nas_addr}:8000/lan")]);
        String::from_utf8_lossy(&out.stdout).contains("hello from device")
    };
    wait_for("a direct path between the router and the NAS", Duration::from_secs(90), || {
        has_route(router, &agent.iface, &nas_addr) && has_route(&nas, &iface, &agent.addr)
    });
    assert!(!reach_nas(), "direct mesh cannot bypass the local service policy");

    // Idle sessions must remain direct across the former 25-second expiry.
    let idle = std::env::var("WARREN_MESH_IDLE_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(35);
    thread::sleep(Duration::from_secs(idle));
    assert!(has_route(router, &agent.iface, &nas_addr));
    assert!(has_route(&nas, &iface, &agent.addr));
    assert!(!reach_nas());
    let ping_both = || {
        router.must(&["ping", "-q", "-c", "3", "-W", "2", &nas_addr]);
        nas.must(&["ping", "-q", "-c", "3", "-W", "2", &agent.addr]);
    };
    let direct_iface = |ns: &Netns, addr: &str| {
        let out = ns.exec(&["ip", "route", "get", addr]);
        let text = String::from_utf8(out.stdout).unwrap();
        let words: Vec<_> = text.split_whitespace().collect();
        words[words.iter().position(|word| *word == "dev").unwrap() + 1].to_string()
    };
    let router_direct = direct_iface(router, &nas_addr);
    let nas_direct = direct_iface(&nas, &agent.addr);
    // Hold opposite route choices while probes continue. Both interfaces
    // must accept authenticated application sources throughout each mismatch.
    router.must(&["ip", "route", "del", &format!("{nas_addr}/32"), "dev", &router_direct]);
    ping_both();
    restore_mesh_route(router, &router_direct, &nas_addr, &agent.addr);
    nas.must(&["ip", "route", "del", &format!("{}/32", agent.addr), "dev", &nas_direct]);
    ping_both();
    restore_mesh_route(&nas, &nas_direct, &agent.addr, &nas_addr);

    // Drop only one underlay direction. Neither receiving requests nor
    // receiving unrelated WireGuard traffic may keep an unusable route alive.
    let lan_ip = format!("{}.1", s.lan_subnet);
    let block = format!(
        "add table ip block; add chain ip block out {{ type filter hook output priority 0; }}; \
         add rule ip block out ip daddr {lan_ip} meta l4proto udp drop"
    );
    nas.must(&["nft", &block]);
    wait_for("both peers to fall back after one-way LAN loss", Duration::from_secs(20), || {
        !has_route(router, &agent.iface, &nas_addr) && !has_route(&nas, &iface, &agent.addr)
    });
    ping_both();
    assert!(!reach_nas());
    nas.must(&["nft", "delete table ip block"]);
    wait_for("direct paths to recover", Duration::from_secs(20), || {
        has_route(router, &agent.iface, &nas_addr) && has_route(&nas, &iface, &agent.addr)
    });
    ping_both();

    daemon.terminate();
    admin.ok("DELETE", &format!("/devices/{nas_id}"), None);
}

fn restore_mesh_route(ns: &Netns, iface: &str, destination: &str, source: &str) {
    // Match the ownership metadata of routes installed by the real watcher.
    ns.must(&["ip", "route", "replace", &format!("{destination}/32"), "dev", iface, "src", source, "proto", "static"]);
}

/// Error pages, an agent restart ("reboot") and revocation.
fn check_failures_restart_revoke(
    s: &Scenario,
    dir: &Path,
    dev: &Netns,
    admin: &Client,
    visitor: &Client,
    agent: &mut Agent,
) {
    let app = format!("https://app.{DOMAIN}:{}", s.https_port);
    admin.ok("POST", "/resources", Some(json!({ "host": "down", "device_id": agent.id, "service": "down" })));
    let r = visitor.get(&format!("https://down.{DOMAIN}:{}/", s.https_port));
    assert_eq!(r.status, 502);
    assert!(r.body.contains("Service unreachable"));
    assert!(!r.body.contains("router") && !r.body.contains(&agent.addr), "error pages name no device");
    admin.ok("PATCH", &format!("/devices/{}", agent.id), Some(json!({ "enabled": false })));
    let r = visitor.get(&format!("{app}/"));
    assert_eq!(r.status, 503);
    assert!(r.body.contains("Site offline") && !r.body.contains("router"));
    admin.ok("PATCH", &format!("/devices/{}", agent.id), Some(json!({ "enabled": true })));

    // The daemon stops (removing its interface) and starts again.
    agent.daemon.terminate();
    assert!(!dev.exec(&["ip", "link", "show", &agent.iface]).status.success(), "agent removes its interface on stop");
    let mut args: Vec<&str> = agent.run_args.iter().map(String::as_str).collect();
    let installed = Path::new(args[0]);
    let config = dir.join("agent/etc");
    // Interrupt A's activation on disk before starting registration B.
    let previous = interrupt_activation(installed, &config);
    let second = config.with_file_name("second");
    for file in ["agent.conf", "private.key"] {
        fs::copy(config.join(file), second.join(file)).unwrap();
    }
    fs::create_dir_all(second.join("services")).unwrap();
    fs::copy(config.join("services/app"), second.join("services/app")).unwrap();
    let config_index = args.iter().position(|&arg| arg == "--config-dir").unwrap() + 1;
    args[config_index] = second.to_str().unwrap();
    let run = dir.join("agent/runtime/run");
    fs::write(run.join("status"), "state=stale\n").unwrap();
    fs::set_permissions(run.join("status"), fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
    agent.daemon = dev.spawn(&args, &dir.join("agent2.log"));
    let reachable = || visitor.try_request("GET", &format!("{app}/again"), None, &[]).is_some_and(|r| r.status == 200);
    wait_for("the published service after a different registration starts", Duration::from_secs(30), || {
        !installed.with_extension("update-activation").exists() && reachable()
    });
    let pid = agent.daemon.0.as_ref().unwrap().id();
    let worker = service_child(pid).unwrap();
    assert_eq!(fs::metadata(format!("/proc/{pid}/exe")).unwrap().ino(), previous);
    assert_eq!(fs::metadata(format!("/proc/{worker}/exe")).unwrap().ino(), previous);
    assert_eq!(fs::metadata(installed).unwrap().ino(), previous);
    assert!(!installed.with_extension("update-backup").exists());
    assert_status_permissions(&run, 0o700);

    let run_index = args.iter().position(|&arg| arg == "--run-dir").unwrap() + 1;
    let next_run = dir.join("agent/next-run");
    args[config_index] = config.to_str().unwrap();
    args[run_index] = next_run.to_str().unwrap();
    check_orphaned_worker(dev, &mut agent.daemon, &args, &next_run, &dir.join("agent2.log"));
    wait_for("the service after orphan teardown", Duration::from_secs(30), reachable);

    agent.daemon.terminate();
    for phase in ["version", "run"] {
        check_trial_interruption(dev, &args, installed, &config, reachable, phase).terminate();
    }
    check_competing_alias_during_exec(dev, dir, installed, &second);
    check_read_only_lock_storage(dev, dir, installed, &config, reachable);
    check_read_only_startup(dev, dir, installed, &config, &second, reachable);
    check_revoked_read_only_startup(dev, dir, installed, &config, reachable);

    let previous = interrupt_activation(installed, &config);
    let direct = Path::new("/tmp").join(dir.file_name().unwrap());
    std::os::unix::fs::symlink(&config, &direct).unwrap();
    args[config_index] = direct.to_str().unwrap();
    agent.daemon = dev.spawn(&args, &dir.join("agent2.log"));
    wait_for("the restored agent running without supervision", Duration::from_secs(30), || {
        !installed.with_extension("update-activation").exists() && reachable()
    });
    let pid = agent.daemon.0.as_ref().unwrap().id();
    assert_eq!(fs::metadata(format!("/proc/{pid}/exe")).unwrap().ino(), previous);
    assert!(service_child(pid).is_none());
    assert!(!installed.with_extension("update-backup").exists());
    fs::remove_file(direct).unwrap();

    // Revoking removes the device and its resources.
    admin.ok("DELETE", &format!("/devices/{}", agent.id), None);
    let resources = admin.ok("GET", "/resources", None);
    assert!(resources.as_array().unwrap().iter().all(|r| r["device_id"] != json!(agent.id)));
    assert!(visitor.try_request("GET", &format!("{app}/"), None, &[]).is_none(), "its hosts are no longer served");
    agent.daemon.terminate();
}

fn check_trial_interruption(
    dev: &Netns,
    args: &[&str],
    installed: &Path,
    config: &Path,
    reachable: impl Fn() -> bool,
    phase: &str,
) -> Guard {
    let previous = fs::metadata(installed).unwrap().ino();
    let invocations = config.join(format!("{phase}-invocations"));
    let processes = config.join(format!("{phase}-processes"));
    let (_, candidate) = stage_agent_update(installed, config, "9.0.0", |path| {
        fs::write(
            path,
            format!(
                r#"#!/bin/sh
echo "$1" >> '{}'
if [ "$1" = '{}' ]; then
    trap '' TERM
    sleep 300 &
    echo "$$ $!" > '{}'
    wait
elif [ "$1" = version ]; then
    echo warren 9.0.0
fi
"#,
                invocations.display(),
                phase,
                processes.display()
            ),
        )
        .unwrap();
    });
    let log = config.join(format!("crash-{phase}.log"));
    let mut trial = dev.spawn(args, &log);
    wait_for("the candidate to stall", Duration::from_secs(10), || {
        fs::read_to_string(&processes).is_ok_and(|pids| pids.split_whitespace().count() == 2)
    });
    let pids = fs::read_to_string(&processes).unwrap();
    let candidate_pid = pids.split_whitespace().next().unwrap();
    let lock = executable_lock(installed, "update");
    assert!(
        fs::read_dir(format!("/proc/{candidate_pid}/fd"))
            .unwrap()
            .flatten()
            .all(|fd| { fs::read_link(fd.path()).is_ok_and(|path| path != lock) })
    );
    let activation = installed.with_extension("update-activation");
    assert!(activation.exists(), "the marker must be durable before {phase}");
    let installed_during_trial = fs::metadata(installed).unwrap().ino();
    let mut coordinator = trial.0.take().unwrap();
    coordinator.kill().unwrap();
    coordinator.wait().unwrap();
    assert_eq!(installed_during_trial, previous);

    let daemon = dev.spawn(args, &config.join(format!("recovery-{phase}.log")));
    wait_for("the previous agent to start after coordinator death", Duration::from_secs(25), reachable);
    assert_recovered_worker(&daemon, previous);
    assert_ne!(fs::metadata(installed).unwrap().ino(), candidate);
    assert!(!activation.exists());
    assert_eq!(
        fs::read_to_string(invocations).unwrap(),
        if phase == "version" { "version\n" } else { "version\nrun\n" }
    );
    wait_for("the stalled candidate and its descendant to exit", Duration::from_secs(5), || {
        pids.split_whitespace().all(|pid| {
            let stat = fs::read_to_string(format!("/proc/{pid}/stat"));
            stat.is_err()
                || stat.is_ok_and(|stat| stat.rsplit_once(") ").is_some_and(|(_, fields)| fields.starts_with('Z')))
        })
    });
    daemon
}

fn assert_recovered_worker(daemon: &Guard, previous: u64) {
    let pid = daemon.0.as_ref().unwrap().id();
    let worker = service_child(pid).unwrap();
    assert_eq!(fs::metadata(format!("/proc/{pid}/exe")).unwrap().ino(), previous);
    assert_eq!(fs::metadata(format!("/proc/{worker}/exe")).unwrap().ino(), previous);
    let env = fs::read(format!("/proc/{worker}/environ")).unwrap();
    assert!(env.split(|&byte| byte == 0).any(|entry| entry == b"WARREN_DAEMON_UPDATE_COOLDOWN=9.0.0"));
}

struct BindMount<'a>(&'a str);

impl<'a> BindMount<'a> {
    fn new(source: &Path, target: &'a Path) -> Self {
        let target = target.to_str().unwrap();
        must(&["mount", "--bind", source.to_str().unwrap(), target]);
        Self(target)
    }

    fn read_only(dir: &'a Path) -> Self {
        let mount = Self::new(dir, dir);
        must(&["mount", "-o", "remount,bind,ro", mount.0]);
        mount
    }
}

impl Drop for BindMount<'_> {
    fn drop(&mut self) {
        must(&["umount", self.0]);
    }
}

fn check_competing_alias_during_exec(dev: &Netns, dir: &Path, installed: &Path, other_config: &Path) {
    let unprotected = dir.join("unprotected");
    fs::create_dir(&unprotected).unwrap();
    fs::set_permissions(&unprotected, fs::Permissions::from_mode(0o777)).unwrap();
    let alias = unprotected.join("alias");
    fs::create_dir(&alias).unwrap();
    let _mount = BindMount::new(installed.parent().unwrap(), &alias);
    let exe = alias.join(installed.file_name().unwrap());
    let update = fs::File::open(executable_lock(installed, "update")).unwrap();
    update.lock().unwrap();
    let log = dir.join("competing-alias.log");
    let mut competitor =
        dev.spawn(&[exe.to_str().unwrap(), "run", "--config-dir", other_config.to_str().unwrap()], &log);
    let child = competitor.0.as_mut().unwrap();
    let wait_channel = format!("/proc/{}/wchan", child.id());
    wait_for("the aliased startup to wait for the update lock", Duration::from_secs(10), || {
        assert!(child.try_wait().unwrap().is_none());
        fs::read_to_string(&wait_channel).is_ok_and(|channel| channel.contains("lock_inode_wait"))
    });
    // The update lock is inherited across exec. The replacement must be able
    // to reclaim the service lock before releasing the update lock.
    let service = fs::File::open(executable_lock(installed, "service")).unwrap();
    service.try_lock().unwrap();
    drop(update);
    wait_for("the aliased startup to reject the claimed service", Duration::from_secs(10), || {
        child.try_wait().unwrap().is_some_and(|status| !status.success())
    });
    assert!(fs::read_to_string(log).unwrap().contains("another Warren service is using this executable"));
}

fn check_read_only_lock_storage(
    dev: &Netns,
    dir: &Path,
    installed: &Path,
    config: &Path,
    reachable: impl Fn() -> bool,
) {
    let runtime = must(&["mktemp", "-d", "/run/warren-e2e-ro-XXXXXX"]);
    let runtime = runtime.trim();
    let mut daemon = dev.spawn(
        &[
            "unshare",
            "--mount",
            "sh",
            "-ec",
            "mount --bind /var/lib /var/lib; mount -o remount,bind,ro /var/lib; exec \"$@\"",
            "warren-test",
            installed.to_str().unwrap(),
            "run",
            "--config-dir",
            config.to_str().unwrap(),
            "--run-dir",
            runtime,
        ],
        &dir.join("read-only-var-lib.log"),
    );
    let status = Path::new(runtime).join("status");
    wait_for("an opt-out tunnel with read-only /var/lib", Duration::from_secs(30), || {
        fs::read_to_string(&status).is_ok_and(|status| status.contains("state=connected")) && reachable()
    });
    daemon.terminate();
    fs::remove_dir_all(runtime).unwrap();
}

fn check_read_only_startup(
    dev: &Netns,
    dir: &Path,
    installed: &Path,
    config: &Path,
    second: &Path,
    reachable: impl Fn() -> bool,
) {
    let bin_dir = dir.join("read-only-bin");
    fs::create_dir(&bin_dir).unwrap();
    let exe = bin_dir.join("warren");
    fs::copy(installed, &exe).unwrap();
    let previous = fs::metadata(&exe).unwrap().ino();
    let (request, _) = stage_agent_update(&exe, config, "9.0.0", |candidate| {
        fs::write(candidate, "#!/bin/sh\nexit 77\n").unwrap();
    });
    let activation = exe.with_extension("update-activation");
    let candidate = request.with_extension("update-candidate");
    fs::rename(request, &activation).unwrap();
    let _bin_mount = BindMount::read_only(&bin_dir);
    let _config_mount = BindMount::read_only(config);
    let bin_alias = dir.join("read-only-bin-alias");
    fs::create_dir(&bin_alias).unwrap();
    let _alias_mount = BindMount::new(&bin_dir, &bin_alias);
    let aliased_exe = bin_alias.join("warren");
    let exe = exe.to_str().unwrap();
    let private = dir.join("private-runtime");
    let alias = dir.join("runtime-alias");
    fs::create_dir(&private).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&private, &alias).unwrap();
    let mut daemon = dev.spawn(
        &[exe, "run", "--config-dir", config.to_str().unwrap(), "--run-dir", alias.to_str().unwrap()],
        &dir.join("read-only.log"),
    );
    wait_for("a tunnel with read-only executable and registration directories", Duration::from_secs(30), || {
        reachable() && fs::read_to_string(private.join("status")).is_ok_and(|status| status.contains("state=connected"))
    });
    assert_status_permissions(&private, 0o700);
    assert_recovered_worker(&daemon, previous);
    assert!(activation.exists());
    assert!(candidate.exists());
    assert_eq!(executable_lock(Path::new(exe), "worker"), executable_lock(&aliased_exe, "worker"));
    let worker_lock = fs::File::open(executable_lock(Path::new(exe), "worker")).unwrap();
    assert!(matches!(worker_lock.try_lock(), Err(fs::TryLockError::WouldBlock)));
    let output =
        dev.exec(&["timeout", "10", aliased_exe.to_str().unwrap(), "run", "--config-dir", second.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("another Warren service is using this executable"));
    let output =
        dev.exec(&["timeout", "10", installed.to_str().unwrap(), "run", "--config-dir", config.to_str().unwrap()]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("agent already running"));
    assert!(reachable());
    let redirected = dir.join("redirected-runtime");
    fs::create_dir(&redirected).unwrap();
    fs::write(redirected.join("status"), "unrelated").unwrap();
    fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&redirected, &alias).unwrap();
    // ip netns exec gives the agent its own mount namespace.
    let pid = daemon.0.as_ref().unwrap().id();
    must(&[
        "nsenter",
        &format!("--mount=/proc/{pid}/ns/mnt"),
        "mount",
        "-o",
        "remount,bind,rw",
        bin_dir.to_str().unwrap(),
    ]);
    wait_for("deferred activation cleanup", Duration::from_secs(10), || !activation.exists() && !candidate.exists());
    daemon.terminate();
    assert!(!private.join("status").exists());
    assert_eq!(fs::read_to_string(redirected.join("status")).unwrap(), "unrelated");
    worker_lock.try_lock().unwrap();
}

fn check_revoked_read_only_startup(
    dev: &Netns,
    dir: &Path,
    installed: &Path,
    config: &Path,
    reachable: impl Fn() -> bool,
) {
    let bin_dir = dir.join("revoked-bin");
    fs::create_dir(&bin_dir).unwrap();
    let exe = bin_dir.join("warren");
    fs::copy(installed, &exe).unwrap();
    let previous = fs::metadata(&exe).unwrap().ino();
    let invoked = config.join("revoked-invoked");
    let policy = config.join("remote-updates");
    let generation = "11111111111111111111111111111111:1";
    fs::write(&policy, format!("on {generation}\n")).unwrap();
    let (request, _) = publish_agent_update(&exe, config, "9.0.0", Some(generation), |candidate| {
        fs::write(candidate, format!("#!/bin/sh\ntouch '{}'\nexit 77\n", invoked.display())).unwrap();
    });
    dev.must(&[exe.to_str().unwrap(), "update", "--config-dir", config.to_str().unwrap(), "--remote", "off"]);
    assert_eq!(fs::read_to_string(&policy).unwrap(), "off 11111111111111111111111111111111:2\n");
    let candidate = request.with_extension("update-candidate");
    let mount = BindMount::read_only(&bin_dir);
    let run = dir.join("revoked-run");
    let args =
        [exe.to_str().unwrap(), "run", "--config-dir", config.to_str().unwrap(), "--run-dir", run.to_str().unwrap()];
    let connected =
        || fs::read_to_string(run.join("status")).is_ok_and(|status| status.contains("state=connected")) && reachable();
    let mut daemon = dev.spawn(&args, &dir.join("revoked.log"));
    wait_for("the installed tunnel with a revoked update on read-only storage", Duration::from_secs(30), connected);
    let pid = daemon.0.as_ref().unwrap().id();
    assert_eq!(fs::metadata(format!("/proc/{pid}/exe")).unwrap().ino(), previous);
    assert!(request.exists() && candidate.exists());
    assert!(!invoked.exists());

    daemon.terminate();
    assert!(!run.join("status").exists());
    drop(mount);
    // Re-enable with the successor generation without consulting GitHub.
    fs::write(policy, "on 11111111111111111111111111111111:3\n").unwrap();
    let mut daemon = dev.spawn(&args, &dir.join("revoked-restart.log"));
    wait_for("revoked update cleanup after a restart", Duration::from_secs(10), || {
        !request.exists() && !candidate.exists()
    });
    wait_for("the installed tunnel after re-enabling remote updates", Duration::from_secs(30), connected);
    assert!(!invoked.exists());
    daemon.terminate();
    assert!(!run.join("status").exists());
}

fn interrupt_activation(installed: &Path, config: &Path) -> u64 {
    let previous = fs::metadata(installed).unwrap().ino();
    let (request, candidate) = stage_agent_update(installed, config, warren_proto::VERSION, |path| {
        fs::copy(installed, path).unwrap();
        fs::OpenOptions::new().append(true).open(path).unwrap().write_all(b"interrupted activation").unwrap();
    });
    fs::rename(&request, installed.with_extension("update-activation")).unwrap();
    fs::hard_link(installed, installed.with_extension("update-backup")).unwrap();
    fs::rename(request.with_extension("update-candidate"), installed).unwrap();
    assert_eq!(fs::metadata(installed).unwrap().ino(), candidate);
    previous
}

struct FrozenWorker(u32);

impl Drop for FrozenWorker {
    fn drop(&mut self) {
        // SAFETY: the worker is stopped and retains its PID.
        unsafe { libc::kill(i32::try_from(self.0).unwrap(), libc::SIGCONT) };
    }
}

fn check_orphaned_worker(dev: &Netns, daemon: &mut Guard, args: &[&str], run: &Path, log: &Path) {
    let mut supervisor = daemon.0.take().unwrap();
    let worker = service_child(supervisor.id()).unwrap();
    must(&["kill", "-STOP", &worker.to_string()]);
    let frozen = FrozenWorker(worker);
    wait_for("the worker to stop", Duration::from_secs(5), || {
        fs::read_to_string(format!("/proc/{worker}/status")).unwrap().contains("State:\tT")
    });
    supervisor.kill().unwrap();
    supervisor.wait().unwrap();

    *daemon = dev.spawn(args, log);
    let pid = daemon.0.as_ref().unwrap().id();
    let worker_lock = executable_lock(Path::new(args[0]), "worker");
    let status = run.join("status");
    wait_for("the next worker to reach startup", Duration::from_secs(5), || {
        status.exists()
            || service_child(pid).is_some_and(|worker| {
                fs::read_dir(format!("/proc/{worker}/fd")).is_ok_and(|fds| {
                    fds.flatten().any(|fd| fs::read_link(fd.path()).is_ok_and(|path| path == worker_lock))
                })
            })
    });
    assert!(!status.exists(), "the second worker started before the orphan could tear down");
    drop(frozen);
    wait_for("the next worker to connect after orphan teardown", Duration::from_secs(20), || {
        fs::read_to_string(&status).is_ok_and(|value| value.contains("state=connected"))
    });
}

fn check_audit(admin: &Client, bob: &Client) {
    let audit = admin.ok("GET", "/audit?limit=500", None);
    let actions: Vec<&str> = audit.as_array().unwrap().iter().filter_map(|e| e["action"].as_str()).collect();
    let expected = [
        "auth.login",
        "device.register",
        "resource.create",
        "device.revoke",
        "user.create",
        "acl.create",
        "user.2fa_enable",
    ];
    for a in expected {
        assert!(actions.contains(&a), "audit log lacks {a}: {actions:?}");
    }
    let own = bob.ok("GET", "/audit", None);
    assert!(own.as_array().unwrap().iter().all(|e| e["actor"] == "bob"), "users see only their own entries");
}

#[test]
#[ignore = "needs Linux and root; run scripts/e2e.sh"]
fn kernel_backend() {
    scenario(&Scenario {
        tag: "k",
        backend: "kernel",
        subnet: "192.168.77",
        manual_subnet: "192.168.177",
        lan_subnet: "172.20.77",
        network: "10.88.0.0/16",
        http_port: 18080,
        https_port: 18443,
        wg_port: 51830,
    });
}

#[test]
#[ignore = "needs Linux and root; run scripts/e2e.sh"]
fn userspace_backend() {
    scenario(&Scenario {
        tag: "u",
        backend: "userspace",
        subnet: "192.168.78",
        manual_subnet: "192.168.178",
        lan_subnet: "172.20.78",
        network: "10.89.0.0/16",
        http_port: 28080,
        https_port: 28443,
        wg_port: 51831,
    });
}
