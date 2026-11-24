//! The hub requests a service label. Only a locally opened grant supplies a destination.
use crate::expose::{Service, services};
use crate::state::{Paths, Saved, StatusFile};
use crate::{http, stopping};
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::thread;
use std::time::Duration;
use warren_proto::Kv;

const CONNECT: Duration = Duration::from_secs(5);
const TICK: Duration = Duration::from_millis(250);

pub fn spawn(paths: &Paths) {
    let config = paths.config();
    let dir = paths.config_dir.join("services");
    let mut status = StatusFile::named(&paths.run_dir, c"service-status").ok();
    thread::spawn(move || {
        let mut last = None;
        let mut workers: Vec<thread::JoinHandle<()>> = Vec::new();
        while !stopping() {
            workers.retain(|w| !w.is_finished());
            let result = poll(&config, &dir, &mut workers);
            let summary = match result {
                Ok(summary) => summary,
                Err(e) => {
                    crate::log!(Debug, "service control unavailable", error = e);
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            if last.as_ref() != Some(&summary)
                && let Some(file) = &mut status
                && file.write_public(summary.as_bytes()).is_ok()
            {
                last = Some(summary);
            }
        }
    });
}

fn poll(config: &Path, dir: &Path, workers: &mut Vec<thread::JoinHandle<()>>) -> io::Result<String> {
    let saved = Saved::load(config).map_err(io::Error::other)?;
    let control = saved.control()?;
    let services = services(dir).map_err(io::Error::other)?;
    let mut report = Kv::new();
    for (name, service) in &services {
        report.push("service", format!("{name} {}", service.scheme));
    }
    let addr = control.to_string();
    let reply = http::request(&addr, &addr, "POST", "/agent/v1/services", Some(&report.encode()), CONNECT)?;
    if reply.status != 200 {
        return Err(io::Error::other(format!("service report returned {}", reply.status)));
    }
    let reply = Kv::parse(&reply.body).map_err(io::Error::other)?;
    for job in reply.get_all("open").take(64usize.saturating_sub(workers.len())) {
        let fields: Vec<_> = job.split_whitespace().collect();
        let [ticket, name, scheme] = fields.as_slice() else { continue };
        let Ok(ticket) = ticket.parse::<u64>() else { continue };
        if services.get(*name).is_none_or(|s| s.scheme != *scheme) {
            continue;
        }
        let path = dir.join(name);
        let scheme = (*scheme).to_owned();
        workers.push(thread::spawn(move || {
            if let Err(e) = forward(control, ticket, &path, &scheme) {
                crate::log!(Debug, "service stream closed", error = e);
            }
        }));
    }
    let mut summary = Kv::new();
    for (name, service) in &services {
        summary.push("grant", format!("{name} {}://{}", service.scheme, service.target));
    }
    for row in reply.get_all("published") {
        if let Some((name, url)) = row.split_once(' ')
            && services.contains_key(name)
            && url.starts_with("https://")
            && !url.chars().any(char::is_control)
        {
            summary.push("published", row);
        }
    }
    Ok(summary.encode())
}

// Hold the original inode open so deleting or replacing a grant invalidates
// a stream even when a local backup has a hard link to its former contents.
struct Grant<'a> {
    file: File,
    path: &'a Path,
}

impl Grant<'_> {
    fn active(&self) -> bool {
        !stopping()
            && self
                .file
                .metadata()
                .ok()
                .zip(std::fs::metadata(self.path).ok())
                .is_some_and(|(original, current)| original.dev() == current.dev() && original.ino() == current.ino())
    }
}

fn forward(control: SocketAddr, ticket: u64, path: &Path, scheme: &str) -> io::Result<()> {
    let mut grant = Grant { file: File::open(path)?, path };
    let mut text = String::new();
    grant.file.read_to_string(&mut text)?;
    let service = Service::parse(text.trim(), None).map_err(io::Error::other)?;
    if scheme != service.scheme || !grant.active() {
        return Ok(());
    }
    let mut hub = TcpStream::connect_timeout(&control, CONNECT)?;
    hub.set_read_timeout(Some(CONNECT))?;
    hub.set_write_timeout(Some(CONNECT))?;
    write!(
        hub,
        "GET /agent/v1/streams/{ticket} HTTP/1.1\r\nHost: {control}\r\nConnection: Upgrade\r\nUpgrade: warren-stream\r\n\r\n"
    )?;
    // Read exactly the HTTP head. Bytes after it already belong to the proxied protocol.
    let mut head = Vec::new();
    while head.len() < 4096 && !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0; 1];
        hub.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    if !head.starts_with(b"HTTP/1.1 101 ") || !head.ends_with(b"\r\n\r\n") || !grant.active() {
        return Err(io::Error::other("service stream declined"));
    }
    let mut local = Err(io::Error::other("service target did not resolve"));
    for addr in service.target.to_socket_addrs()? {
        if !grant.active() {
            return Ok(());
        }
        local = TcpStream::connect_timeout(&addr, CONNECT);
        if local.is_ok() {
            break;
        }
    }
    let local = local?;
    for s in [&hub, &local] {
        s.set_nodelay(true)?;
        s.set_read_timeout(Some(TICK))?;
        s.set_write_timeout(Some(CONNECT))?;
    }
    thread::scope(|scope| {
        let back = scope.spawn(|| relay(&local, &hub, &grant));
        relay(&hub, &local, &grant);
        let _ = back.join();
    });
    Ok(())
}

fn relay(mut from: &TcpStream, mut to: &TcpStream, grant: &Grant<'_>) {
    let mut buf = [0; 16 * 1024];
    while grant.active() {
        match from.read(&mut buf) {
            Ok(0) => {
                let _ = to.shutdown(Shutdown::Write);
                return;
            }
            Ok(n) if grant.active() && to.write_all(&buf[..n]).is_ok() => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut | io::ErrorKind::Interrupted
                ) => {}
            _ => break,
        }
    }
    let _ = from.shutdown(Shutdown::Both);
    let _ = to.shutdown(Shutdown::Both);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (client, listener.accept().unwrap().0)
    }

    #[test]
    fn withdrawing_a_grant_closes_an_already_connected_stream() {
        let nonce = warren_proto::codec::hex_encode(&crate::state::random_bytes::<8>().unwrap());
        let dir = std::env::temp_dir().join(format!("warren-grant-{nonce}"));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("grafana");
        let grant = Grant { file: File::create(&path).unwrap(), path: &path };
        std::fs::hard_link(&path, dir.join("backup")).unwrap();
        let (mut client, from) = pair();
        let (to, mut backend) = pair();
        from.set_read_timeout(Some(TICK)).unwrap();
        backend.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        thread::scope(|scope| {
            scope.spawn(|| relay(&from, &to, &grant));
            client.write_all(b"ok").unwrap();
            let mut buf = [0; 2];
            backend.read_exact(&mut buf).unwrap();
            assert_eq!(&buf, b"ok");
            std::fs::remove_file(&path).unwrap();
            let _ = client.write_all(b"no");
            assert_eq!(backend.read(&mut buf).unwrap(), 0);
        });
        std::fs::remove_dir_all(dir).unwrap();
    }
}
