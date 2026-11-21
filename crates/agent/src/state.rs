//! On-disk agent state: one small config file plus a private key file.
//!
//! Both live in the config directory (`/etc/warren`) and are written rarely;
//! the frequently updated status goes to the run directory, on tmpfs on OpenWrt.

use crate::error::{Error, Result};
use std::ffi::{CStr, CString, OsStr};
use std::fs;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use warren_proto::{AgentConfig, Kv, codec};

pub const DEFAULT_CONFIG_DIR: &str = "/etc/warren";
#[cfg(target_os = "linux")]
pub const DEFAULT_RUN_DIR: &str = "/var/run/warren";
#[cfg(target_os = "macos")]
pub const DEFAULT_RUN_DIR: &str = "/var/db/warren/run";
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

    #[cfg(all(test, target_os = "linux"))]
    pub fn update_policy(&self) -> PathBuf {
        self.config_dir.join("remote-updates")
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
        Self::read(path, fs::File::open(path))
    }

    pub fn load_at(dir: &fs::File, path: &Path) -> Result<Saved> {
        // SAFETY: the directory descriptor and C string remain live for openat.
        let fd = unsafe {
            libc::openat(dir.as_raw_fd(), c"agent.conf".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK)
        };
        let file = if fd < 0 {
            Err(io::Error::last_os_error())
        } else {
            // SAFETY: successful openat returns a descriptor owned by this call.
            Ok(unsafe { fs::File::from_raw_fd(fd) })
        };
        Self::read(path, file)
    }

    fn read(path: &Path, file: io::Result<fs::File>) -> Result<Saved> {
        let read = |e| Error::io(format!("reading {}", path.display()))(e);
        let mut file = match file {
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::NotRegistered),
            file => file.map_err(read)?,
        };
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(read)?;
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
    let tmp = path.with_extension(format!("tmp-{}", codec::hex_encode(&random_bytes::<8>()?)));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(Error::io(format!("creating {}", tmp.display())))?;
    let mut write = || -> io::Result<()> {
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        // Make private state changes durable: routers lose power.
        if let Some(dir) = path.parent() {
            fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    };
    let result = write();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result.map_err(Error::io(format!("writing {}", path.display())))
}

/// Keeps the status file in the directory resolved when the worker started.
pub struct StatusFile {
    dir: fs::File,
    published: bool,
    #[cfg(target_os = "macos")]
    boot_id: String,
}

impl StatusFile {
    pub fn open(run_dir: &Path) -> Result<Self> {
        let dir = create_public_dirs(run_dir).map_err(Error::io(format!("opening {}", run_dir.display())))?;
        Ok(Self {
            dir,
            published: false,
            #[cfg(target_os = "macos")]
            boot_id: boot_id().map_err(Error::io("reading the boot session ID"))?,
        })
    }

    #[cfg(target_os = "macos")]
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn write_public(&mut self, data: &[u8]) -> Result<()> {
        let failed = || Error::io("publishing the agent status");
        let temporary = format!(".status-{}", codec::hex_encode(&random_bytes::<8>()?));
        let temporary = CString::new(temporary).map_err(|e| failed()(e.into()))?;
        replace_at(&self.dir, c"status", &temporary, data, |file| {
            file.set_permissions(fs::Permissions::from_mode(0o644))
        })
        .map_err(failed())?;
        self.published = true;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
pub fn boot_id() -> io::Result<String> {
    let mut uuid = [0u8; 37];
    let mut size = uuid.len();
    // SAFETY: uuid and size are writable for the entire call, and there is no input value.
    if unsafe {
        libc::sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            uuid.as_mut_ptr().cast(),
            &raw mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    CStr::from_bytes_with_nul(&uuid)
        .ok()
        .and_then(|uuid| uuid.to_str().ok())
        .filter(|_| size == uuid.len())
        .map(str::to_owned)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid boot session ID"))
}

impl Drop for StatusFile {
    fn drop(&mut self) {
        if self.published {
            // SAFETY: the pinned directory remains live for unlinkat.
            unsafe { libc::unlinkat(self.dir.as_raw_fd(), c"status".as_ptr(), 0) };
        }
    }
}

pub fn open_at(dir: &fs::File, name: &CStr, flags: libc::c_int, mode: libc::c_uint) -> io::Result<fs::File> {
    // SAFETY: the directory descriptor and C string remain live for openat.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags | libc::O_CLOEXEC, mode) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful openat returns a descriptor owned by this call.
    Ok(unsafe { fs::File::from_raw_fd(fd) })
}

fn create_public_dirs(path: &Path) -> io::Result<fs::File> {
    let root = crate::update_files::open_dir(Path::new("/"))?;
    let mut dirs = vec![root];
    resolve_public_dirs(&mut dirs, &std::path::absolute(path)?, 40, true)?;
    let dir = dirs.pop().ok_or_else(untrusted_status_path)?;
    if dir.metadata()?.mode() & 0o022 != 0 {
        return Err(untrusted_status_path());
    }
    Ok(dir)
}

fn untrusted_status_path() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "untrusted status directory or symbolic link")
}

const STATUS_DIR_FLAGS: libc::c_int = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW;

fn resolve_public_dirs(dirs: &mut Vec<fs::File>, path: &Path, links: u8, create: bool) -> io::Result<()> {
    for part in path.components() {
        let name = match part {
            Component::RootDir => {
                dirs.truncate(1);
                continue;
            }
            Component::CurDir => continue,
            Component::ParentDir => {
                if dirs.len() > 1 {
                    dirs.pop();
                }
                continue;
            }
            part => CString::new(part.as_os_str().as_encoded_bytes())?,
        };
        let parent = dirs.last().ok_or_else(untrusted_status_path)?;
        if !crate::update_files::controls_children(parent)? {
            return Err(untrusted_status_path());
        }
        let dir = match open_at(parent, &name, STATUS_DIR_FLAGS, 0) {
            Err(e) if create && e.kind() == io::ErrorKind::NotFound => create_public_dir_at(parent, &name)?,
            Err(e) if matches!(e.raw_os_error(), Some(libc::ELOOP | libc::ENOTDIR)) && links > 0 => {
                let target = read_status_link(parent, &name)?;
                resolve_public_dirs(dirs, &target, links - 1, false)?;
                continue;
            }
            found => found?,
        };
        if !crate::update_files::controls_children(&dir)? {
            return Err(untrusted_status_path());
        }
        dirs.push(dir);
    }
    Ok(())
}

fn read_status_link(parent: &fs::File, name: &CStr) -> io::Result<PathBuf> {
    let fd = parent.as_raw_fd();
    let mut meta = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: meta points to writable storage and both inputs remain live.
    if unsafe { libc::fstatat(fd, name.as_ptr(), meta.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fstatat initialized meta; geteuid has no preconditions.
    let (meta, uid) = unsafe { (meta.assume_init(), libc::geteuid()) };
    if meta.st_mode & libc::S_IFMT != libc::S_IFLNK || (meta.st_uid != 0 && meta.st_uid != uid) {
        return Err(untrusted_status_path());
    }
    // The checked parent protects this trusted link from replacement.
    let mut target = [0_u8; 4096];
    // SAFETY: target is writable for the requested size and name remains live.
    let len = unsafe { libc::readlinkat(fd, name.as_ptr(), target.as_mut_ptr().cast(), target.len()) };
    let len = usize::try_from(len).map_err(|_| io::Error::last_os_error())?;
    if len == target.len() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "status symbolic link is too long"));
    }
    Ok(PathBuf::from(OsStr::from_bytes(&target[..len])))
}

fn create_public_dir_at(parent: &fs::File, name: &CStr) -> io::Result<fs::File> {
    // SAFETY: the directory descriptor and C string remain live for mkdirat.
    if unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o755) } != 0 {
        let error = io::Error::last_os_error();
        return if error.kind() == io::ErrorKind::AlreadyExists {
            open_at(parent, name, STATUS_DIR_FLAGS, 0)
        } else {
            Err(error)
        };
    }
    let dir = open_at(parent, name, STATUS_DIR_FLAGS, 0)?;
    dir.set_permissions(fs::Permissions::from_mode(0o755))?;
    Ok(dir)
}

pub fn write_private_at(dir: &fs::File, name: &CStr, data: &[u8]) -> Result<()> {
    let failed = || Error::io(format!("writing {}", name.to_string_lossy()));
    let temporary = format!(".warren-{}", codec::hex_encode(&random_bytes::<8>()?));
    let temporary = CString::new(temporary).map_err(|e| failed()(e.into()))?;
    replace_at(dir, name, &temporary, data, fs::File::sync_all).and_then(|()| dir.sync_all()).map_err(failed())
}

fn replace_at(
    dir: &fs::File,
    name: &CStr,
    temporary: &CStr,
    data: &[u8],
    finish: impl FnOnce(&fs::File) -> io::Result<()>,
) -> io::Result<()> {
    let flags = libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL;
    let mut file = open_at(dir, temporary, flags, 0o600)?;
    let fd = dir.as_raw_fd();
    let result = (|| {
        file.write_all(data)?;
        finish(&file)?;
        // SAFETY: both names and the pinned directory remain live for renameat.
        if unsafe { libc::renameat(fd, temporary.as_ptr(), fd, name.as_ptr()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    })();
    if result.is_err() {
        // SAFETY: both the name and the pinned directory remain live for unlinkat.
        unsafe { libc::unlinkat(fd, temporary.as_ptr(), 0) };
    }
    result
}

pub fn load_key(path: &Path) -> Result<[u8; 32]> {
    let ctx = || format!("reading {}", path.display());
    let file = match fs::OpenOptions::new().read(true).custom_flags(libc::O_NONBLOCK).open(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(Error::NotRegistered),
        r => r.map_err(Error::io(ctx()))?,
    };
    let meta = file.metadata().map_err(Error::io(ctx()))?;
    let key = parse_key(&file).map_err(Error::io(ctx()))?;
    if meta.permissions().mode() & 0o077 != 0 {
        crate::log!(Warn, "private key is readable by others; fixing permissions", path = path.display());
        file.set_permissions(fs::Permissions::from_mode(0o600)).map_err(Error::io(ctx()))?;
    }
    Ok(key)
}

pub fn parse_key(file: &fs::File) -> io::Result<[u8; 32]> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid private key file");
    if !file.metadata()?.is_file() {
        return Err(invalid());
    }
    // Read one byte beyond the limit so a valid prefix cannot hide extra data.
    let mut text = String::new();
    file.take(129).read_to_string(&mut text)?;
    if text.len() > 128 {
        return Err(invalid());
    }
    codec::decode_key(text.trim()).filter(|key| *key != [0; 32]).ok_or_else(invalid)
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

    #[cfg(target_os = "macos")]
    #[test]
    fn packaged_macos_service_and_status_share_a_protected_run_directory() {
        use crate::cli::Args;

        let plist = include_str!("../../../dist/macos/org.slopworks.warren.plist");
        assert!(plist.contains("<string>run</string>"));
        assert!(!plist.contains("--run-dir"));
        let run = Args::parse(["run".into()]).unwrap();
        let status = Args::parse(["status".into()]).unwrap();
        assert_eq!(status.paths.status(), run.paths.run_dir.join("status"));
        assert_eq!(run.paths.run_dir, Path::new("/var/db/warren/run"));

        let parent = create_public_dirs(Path::new("/var/db")).unwrap();
        crate::update_files::check_root_dir(&parent).unwrap();
        // Exercise the packaged directory itself when the test can create it.
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            let status = StatusFile::open(&run.paths.run_dir).unwrap();
            crate::update_files::check_root_dir(&status.dir).unwrap();
        }
    }

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
                update_generation: None,
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

    #[test]
    fn public_status_preserves_private_ancestors() {
        let suffix = codec::hex_encode(&random_bytes::<8>().unwrap());
        let dir = std::env::temp_dir().join(format!("warren-status-{suffix}"));
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        let run = dir.join("parent/run");
        let mut status = StatusFile::open(&run).unwrap();
        status.write_public(b"state=connected\n").unwrap();

        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&dir.join("parent")), 0o755);
        assert_eq!(mode(&run), 0o755);
        assert_eq!(mode(&run.join("status")), 0o644);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn public_status_follows_a_symlink_to_an_existing_private_directory() {
        let suffix = codec::hex_encode(&random_bytes::<8>().unwrap());
        let dir = std::env::temp_dir().join(format!("warren-status-{suffix}"));
        let private = dir.join("private");
        let alias = dir.join("alias");
        fs::create_dir_all(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&private, &alias).unwrap();

        let mut status = StatusFile::open(&alias).unwrap();
        status.write_public(b"state=connected\n").unwrap();
        assert_eq!(fs::read(private.join("status")).unwrap(), b"state=connected\n");
        assert_eq!(fs::metadata(&private).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(private.join("status")).unwrap().permissions().mode() & 0o777, 0o644);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn public_status_rejects_a_symlink_under_a_writable_ancestor() {
        let suffix = codec::hex_encode(&random_bytes::<8>().unwrap());
        let dir = std::env::temp_dir().join(format!("warren-status-{suffix}"));
        let target = dir.join("unrelated");
        let parent = dir.join("untrusted");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("status"), b"unrelated").unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o777)).unwrap();
        let alias = parent.join("alias");
        std::os::unix::fs::symlink(&target, &alias).unwrap();

        assert!(StatusFile::open(&alias).is_err());
        assert_eq!(fs::read(target.join("status")).unwrap(), b"unrelated");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn public_status_stays_in_the_open_directory_after_substitution() {
        let suffix = codec::hex_encode(&random_bytes::<8>().unwrap());
        let dir = std::env::temp_dir().join(format!("warren-status-{suffix}"));
        let run = dir.join("run");
        let mut status = StatusFile::open(&run).unwrap();
        status.write_public(b"state=starting\n").unwrap();
        let original = dir.join("original");
        fs::rename(&run, &original).unwrap();
        fs::create_dir(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(run.join("status"), b"unrelated").unwrap();

        status.write_public(b"state=connected\n").unwrap();
        assert_eq!(fs::read(original.join("status")).unwrap(), b"state=connected\n");
        drop(status);
        assert!(!original.join("status").exists());
        assert_eq!(fs::read(run.join("status")).unwrap(), b"unrelated");
        assert_eq!(fs::metadata(&run).unwrap().permissions().mode() & 0o777, 0o700);
        fs::remove_dir_all(dir).unwrap();
    }
}
