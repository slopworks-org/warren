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
    let (server_bin, agent_bin) = (server_bin.to_str().unwrap(), agent_bin.to_str().unwrap());

    let dir = std::env::temp_dir().join(format!("warren-e2e-{}", s.tag));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
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
        for f in ["agent.log", "agent2.log"] {
            eprintln!("---- {f} ----\n{}", fs::read_to_string(dir.join(f)).unwrap_or_default());
        }
        std::panic::resume_unwind(panic);
    }

    // A clean shutdown removes the hub interface.
    server.terminate();
    assert!(warren_wgctl::link_index(&server_iface).is_none(), "hub interface left behind");
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
    let visitor = Client::new(dir, "visitor", s.https_port);
    check_pin_and_basic(s, admin, &visitor, agent.id);
    let (bob, bob_id) = check_users_mode(s, dir, admin, &visitor, agent.id);
    let bob = check_two_factor(bob);
    check_mandatory_2fa(dir, admin, s.https_port);
    check_api_token(dir, admin, s.https_port);
    check_agentless_and_acl(s, dir, admin, &bob, bob_id, &agent);
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
        agent_dir.join("run").to_str().unwrap(),
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
    assert_eq!(std::os::unix::fs::PermissionsExt::mode(&key_mode.permissions()) & 0o777, 0o600);

    let run_args: Vec<String> = agent_args(&common, &[agent_bin, "run"]).into_iter().map(ToString::to_string).collect();
    let daemon = dev.spawn(&run_args.iter().map(String::as_str).collect::<Vec<_>>(), &dir.join("agent.log"));
    dev.serve(8000);

    let device = || admin.ok("GET", "/devices", None)[0].clone();
    wait_for("the device to come online", Duration::from_secs(30), || device()["online"] == json!(true));
    let (id, addr) = (device()["id"].as_i64().unwrap(), device()["address"].as_str().unwrap().to_string());
    assert_eq!(device()["name"], "router");
    let status = dev.exec(&agent_args(&common, &[agent_bin, "status"]));
    let status = String::from_utf8_lossy(&status.stdout);
    assert!(status.contains(&addr) && status.contains("Handshake:"), "status output: {status}");
    assert!(status.contains("Control:    connected"), "first poll is immediate: {status}");
    Agent { daemon, run_args, iface, id, addr }
}

/// A public resource: HTTP and WebSocket through the tunnel, redirects, and
/// no certificate for unknown names.
fn check_public_proxy(s: &Scenario, admin: &Client, agent: &Agent) {
    let res = admin.ok("POST", "/resources", Some(json!({ "host": "app", "device_id": agent.id, "port": 8000 })));
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

fn check_pin_and_basic(s: &Scenario, admin: &Client, visitor: &Client, dev_id: i64) {
    let pin = admin.ok(
        "POST",
        "/resources",
        Some(json!({ "host": "pin", "device_id": dev_id, "port": 8000, "access": "pin", "secret": "4321" })),
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

    let basic = json!({ "host": "basic", "device_id": dev_id, "port": 8000, "access": "basic", "basic_user": "u", "secret": "basic-pass" });
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
        Some(json!({ "host": "private", "device_id": dev_id, "port": 8000, "access": "users" })),
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
    wait_for("the agentless device to reach the agent's service", Duration::from_secs(20), reach_agent);
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
    wait_for("the ACL rule to apply", Duration::from_secs(10), reach_agent);
    let other_port = manual_ns.exec(&["curl", "-s", "--max-time", "3", &format!("http://{}:8001/", agent.addr)]);
    assert!(other_port.stdout.is_empty(), "only the allowed port is open");
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
    admin.ok("POST", "/resources", Some(json!({ "host": "down", "device_id": agent.id, "port": 9 })));
    let r = visitor.get(&format!("https://down.{DOMAIN}:{}/", s.https_port));
    assert_eq!(r.status, 502);
    assert!(r.body.contains("Service unreachable"));
    admin.ok("PATCH", &format!("/devices/{}", agent.id), Some(json!({ "enabled": false })));
    let r = visitor.get(&format!("{app}/"));
    assert_eq!(r.status, 503);
    assert!(r.body.contains("Device offline"));
    admin.ok("PATCH", &format!("/devices/{}", agent.id), Some(json!({ "enabled": true })));

    // The daemon stops (removing its interface) and starts again.
    agent.daemon.terminate();
    assert!(!dev.exec(&["ip", "link", "show", &agent.iface]).status.success(), "agent removes its interface on stop");
    let args: Vec<&str> = agent.run_args.iter().map(String::as_str).collect();
    agent.daemon = dev.spawn(&args, &dir.join("agent2.log"));
    wait_for("the published service after an agent restart", Duration::from_secs(30), || {
        visitor.try_request("GET", &format!("{app}/again"), None, &[]).is_some_and(|r| r.status == 200)
    });

    // Revoking removes the device and its resources.
    admin.ok("DELETE", &format!("/devices/{}", agent.id), None);
    let resources = admin.ok("GET", "/resources", None);
    assert!(resources.as_array().unwrap().iter().all(|r| r["device_id"] != json!(agent.id)));
    assert!(visitor.try_request("GET", &format!("{app}/"), None, &[]).is_none(), "its hosts are no longer served");
    agent.daemon.terminate();
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
        network: "10.89.0.0/16",
        http_port: 28080,
        https_port: 28443,
        wg_port: 51831,
    });
}
