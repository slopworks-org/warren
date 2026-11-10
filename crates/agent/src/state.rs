//! On-disk agent state: one small config file plus a private key file.
//!
//! Both live in the config directory (`/etc/warren`) and are written rarely;
//! the frequently updated runtime status goes to the run directory
//! (`/var/run/warren`, tmpfs on OpenWrt) to spare router flash.

use crate::error::{Error, Result};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use warren_proto::{AgentConfig, Kv, codec};

pub const DEFAULT_CONFIG_DIR: &str = "/etc/warren";
pub const DEFAULT_RUN_DIR: &str = "/var/run/warren";
pub const DEFAULT_INTERFACE: &str = "warren0";
pub const DEFAULT_MTU: u32 = 1420;

/// Where the agent keeps its files.
#[derive(Debug)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub run_dir: PathBuf,
}

impl Paths {
    pub fn config(&self) -> PathBuf {
        self.config_dir.join("agent.conf")
    }

    pub fn key(&self) -> PathBuf {
        self.config_dir.join("private.key")
    }

    pub fn status(&self) -> PathBuf {
        self.run_dir.join("status")
    }
}

/// Everything the agent persists besides its key.
#[derive(Clone)]
pub struct Saved {
    /// Server URL as given to `warren up`.
    pub server: String,
    pub interface: String,
    pub mtu: u32,
    pub tunnel: AgentConfig,
}

fn format_err(what: &'static str) -> impl FnOnce(warren_proto::Error) -> Error {
    move |source| Error::Format { what, source }
}

impl Saved {
    pub fn load(path: &Path) -> Result<Saved> {
        let text = match fs::read_to_string(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::NotRegistered),
            r => r.map_err(Error::io(format!("reading {}", path.display())))?,
        };
        let kv = Kv::parse(&text).map_err(format_err("agent.conf"))?;
        Ok(Saved {
            server: kv.req("server").map_err(format_err("agent.conf"))?.to_string(),
            interface: kv.get("interface").unwrap_or(DEFAULT_INTERFACE).to_string(),
            mtu: kv.get("mtu").and_then(|m| m.parse().ok()).unwrap_or(DEFAULT_MTU),
            tunnel: AgentConfig::from_kv(&kv).map_err(format_err("agent.conf"))?,
        })
    }

    pub fn store(&self, path: &Path) -> Result<()> {
        let mut kv = Kv::new();
        kv.push("server", &self.server);
        kv.push("interface", &self.interface);
        kv.push("mtu", self.mtu.to_string());
        self.tunnel.write_kv(&mut kv);
        let text = format!("# Managed by warren.\n{}", kv.encode());
        write_private(path, text.as_bytes())
    }
}

/// Atomically writes a file readable only by its owner.
pub fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let ctx = || format!("writing {}", path.display());
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(Error::io(ctx()))?;
    }
    let tmp = path.with_extension("tmp");
    let write = || -> io::Result<()> {
        let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
        // `mode` only applies on creation; tighten a pre-existing file too.
        f.set_permissions(fs::Permissions::from_mode(0o600))?;
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        // Make the rename itself durable: routers lose power.
        if let Some(dir) = path.parent() {
            fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    };
    write().map_err(Error::io(ctx()))
}

/// Writes a small file that is not secret, creating its directory.
pub fn write_public(path: &Path, data: &[u8]) -> Result<()> {
    let ctx = || format!("writing {}", path.display());
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(Error::io(ctx()))?;
    }
    fs::write(path, data).map_err(Error::io(ctx()))
}

pub fn load_key(path: &Path) -> Result<[u8; 32]> {
    let ctx = || format!("reading {}", path.display());
    let meta = match fs::metadata(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::NotRegistered),
        r => r.map_err(Error::io(ctx()))?,
    };
    if meta.permissions().mode() & 0o077 != 0 {
        crate::log!(Warn, "private key is readable by others; fixing permissions", path = path.display());
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(Error::io(ctx()))?;
    }
    let text = fs::read_to_string(path).map_err(Error::io(ctx()))?;
    codec::decode_key(text.trim())
        .ok_or(Error::Format { what: "private key file", source: warren_proto::Error::BadField("private_key") })
}

pub fn store_key(path: &Path, key: &[u8; 32]) -> Result<()> {
    write_private(path, format!("{}\n", codec::encode_key(key)).as_bytes())
}

/// Fills a buffer from the kernel CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    // Requests of at most 256 bytes are served in full by both calls below.
    for chunk in buf.chunks_mut(256) {
        #[cfg(target_os = "linux")]
        // SAFETY: getrandom writes at most `chunk.len()` bytes into `chunk`.
        let ok = unsafe { libc::getrandom(chunk.as_mut_ptr().cast(), chunk.len(), 0) }
            == isize::try_from(chunk.len()).unwrap_or(-1);
        #[cfg(not(target_os = "linux"))]
        // SAFETY: getentropy writes exactly `chunk.len()` (≤ 256) bytes into `chunk`.
        let ok = unsafe { libc::getentropy(chunk.as_mut_ptr().cast(), chunk.len()) } == 0;
        if !ok {
            return Err(Error::Io { what: "reading random bytes".into(), source: io::Error::last_os_error() });
        }
    }
    Ok(buf)
}

/// Generates a WireGuard private key and its public key.
pub fn generate_keypair() -> Result<([u8; 32], [u8; 32])> {
    let mut sk = random_bytes::<32>()?;
    sk[0] &= 0xf8;
    sk[31] = (sk[31] & 0x7f) | 0x40;
    Ok((sk, public_key(&sk)))
}

pub fn public_key(sk: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::x25519(*sk, x25519_dalek::X25519_BASEPOINT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_x25519_public_key() {
        // RFC 7748 section 6.1, Alice's key pair.
        let sk: [u8; 32] = codec::hex_decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
            .unwrap()
            .try_into()
            .unwrap();
        let pk = codec::hex_encode(&public_key(&sk));
        assert_eq!(pk, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    }

    #[test]
    fn saved_roundtrip_and_permissions() {
        let dir = std::env::temp_dir().join(format!("warren-agent-test-{}", std::process::id()));
        let paths = Paths { config_dir: dir.clone(), run_dir: dir.clone() };
        assert!(matches!(Saved::load(&paths.config()), Err(Error::NotRegistered)));
        let saved = Saved {
            server: "https://vpn.example.com".into(),
            interface: "warren0".into(),
            mtu: 1420,
            tunnel: AgentConfig {
                version: 1,
                device_id: 2,
                name: "r".into(),
                address: "10.77.0.2/16".into(),
                control: "10.77.0.1:7180".into(),
                peers: vec![],
                lan_peers: vec![],
                update: String::new(),
            },
        };
        saved.store(&paths.config()).unwrap();
        let back = Saved::load(&paths.config()).unwrap();
        assert_eq!(back.tunnel, saved.tunnel);
        assert_eq!(back.server, saved.server);
        let (sk, _) = generate_keypair().unwrap();
        store_key(&paths.key(), &sk).unwrap();
        assert_eq!(fs::metadata(paths.key()).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load_key(&paths.key()).unwrap(), sk);
        fs::remove_dir_all(dir).unwrap();
    }
}
