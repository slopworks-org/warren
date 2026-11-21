//! Paths and locks used for privileged updates.

use crate::error::{Error, Result};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

fn require_root_owned(metadata: &Metadata) -> io::Result<()> {
    if metadata.uid() != 0 || (!metadata.is_symlink() && metadata.mode() & 0o022 != 0) {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "must be root-owned and writable only by root"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
mod darwin {
    use std::ffi::{CString, c_char, c_int, c_void};
    use std::fs::File;
    use std::io;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;

    const ACL_TYPE_EXTENDED: c_int = 0x100;

    unsafe extern "C" {
        fn acl_get_link_np(path: *const c_char, acl_type: c_int) -> *mut c_void;
        fn acl_get_fd_np(fd: c_int, acl_type: c_int) -> *mut c_void;
        fn acl_free(acl: *mut c_void) -> c_int;
    }

    fn require_no_acl(acl: *mut c_void) -> io::Result<()> {
        if acl.is_null() {
            let error = io::Error::last_os_error();
            // Darwin also uses ENOENT for an existing object with no ACL.
            return if error.raw_os_error() == Some(libc::ENOENT) { Ok(()) } else { Err(error) };
        }
        // SAFETY: the ACL is owned by this call and was allocated by acl_get_*.
        unsafe { acl_free(acl) };
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "extended ACLs are unsupported for updates"))
    }

    pub fn check_path(path: &Path, metadata: &std::fs::Metadata) -> io::Result<()> {
        let name = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: name is a live C string. Inspect the link itself, then the
        // resolver separately checks every component of the link's target.
        require_no_acl(unsafe { acl_get_link_np(name.as_ptr(), ACL_TYPE_EXTENDED) })?;
        let after = std::fs::symlink_metadata(path)?;
        if (metadata.dev(), metadata.ino()) != (after.dev(), after.ino()) {
            return Err(io::Error::other("path changed while checking its ACL"));
        }
        Ok(())
    }

    pub fn check_file(file: &File) -> io::Result<()> {
        // SAFETY: file owns a live descriptor for the entire call.
        require_no_acl(unsafe { acl_get_fd_np(file.as_raw_fd(), ACL_TYPE_EXTENDED) })
    }

    #[cfg(test)]
    #[test]
    fn rejects_extended_acls_on_directories_and_files() {
        let suffix = warren_proto::codec::hex_encode(&crate::state::random_bytes::<8>().unwrap());
        let dir = std::env::temp_dir().join(format!("warren-acl-{suffix}"));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("candidate");
        let file = File::create(&path).unwrap();

        check_path(&dir, &std::fs::symlink_metadata(&dir).unwrap()).unwrap();
        check_file(&file).unwrap();
        for (target, grant) in [(&dir, "everyone allow delete_child"), (&path, "everyone allow write")] {
            assert!(
                std::process::Command::new("/bin/chmod").args(["+a", grant]).arg(target).status().unwrap().success()
            );
            let error = check_path(target, &std::fs::symlink_metadata(target).unwrap()).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
        assert_eq!(check_file(&file).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        std::fs::remove_dir_all(dir).unwrap();
    }
}

fn check_path(path: &Path, metadata: &Metadata) -> io::Result<()> {
    require_root_owned(metadata).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", path.display())))?;
    #[cfg(target_os = "macos")]
    darwin::check_path(path, metadata)?;
    Ok(())
}

/// Resolves links only from protected directories and checks every component
/// of the target, including the parents of any symlink target.
fn resolve(mut dir: PathBuf, path: &Path, links: u8, create: bool) -> io::Result<(PathBuf, Metadata)> {
    let mut metadata = fs::symlink_metadata(&dir)?;
    check_path(&dir, &metadata)?;
    for part in path.components() {
        if !metadata.is_dir() {
            return Err(io::Error::new(io::ErrorKind::NotADirectory, "expected a protected directory"));
        }
        match part {
            Component::RootDir => dir = PathBuf::from("/"),
            Component::CurDir => continue,
            Component::ParentDir => {
                dir.pop();
            }
            Component::Normal(name) => dir.push(name),
            Component::Prefix(_) => return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected a Unix path")),
        }
        metadata = match fs::symlink_metadata(&dir) {
            Err(e) if create && e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&dir)?;
                fs::symlink_metadata(&dir)?
            }
            result => result?,
        };
        check_path(&dir, &metadata)?;
        if metadata.is_symlink() {
            if links == 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many symbolic links"));
            }
            let target = fs::read_link(&dir)?;
            dir.pop();
            (dir, metadata) = resolve(dir, &target, links - 1, false)?;
        }
    }
    Ok((dir, metadata))
}

fn protected(path: &Path, create: bool, directory: bool) -> io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let (resolved, metadata) = resolve(PathBuf::from("/"), &absolute, 40, create)?;
    if if directory { metadata.is_dir() } else { metadata.is_file() } {
        Ok(resolved)
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidInput, "unexpected file type"))
    }
}

pub fn protected_dir(path: &Path, create: bool) -> Result<PathBuf> {
    protected(path, create, true).map_err(Error::io(format!("checking {}", path.display())))
}

pub fn protected_file(path: &Path) -> Result<PathBuf> {
    protected(path, false, false).map_err(Error::io(format!("checking {}", path.display())))
}

fn validate_lock(file: File) -> io::Result<File> {
    check_root_file(&file)?;
    Ok(file)
}

pub fn check_root_file(file: &File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "expected a regular file"));
    }
    require_root_owned(&metadata)?;
    #[cfg(target_os = "macos")]
    darwin::check_file(file)?;
    Ok(())
}

pub fn check_root_dir(dir: &File) -> io::Result<()> {
    require_root_owned(&dir.metadata()?)?;
    #[cfg(target_os = "macos")]
    darwin::check_file(dir)?;
    Ok(())
}

/// A sticky parent protects children owned by the parent owner, even when
/// other users can create their own entries there.
pub fn controls_children(dir: &File) -> io::Result<bool> {
    let meta = dir.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let owned = meta.uid() == 0 || meta.uid() == unsafe { libc::geteuid() };
    #[cfg(target_os = "macos")]
    if darwin::check_file(dir).is_err() {
        return Ok(false);
    }
    Ok(owned && (meta.mode() & 0o022 == 0 || meta.mode() & 0o1000 != 0))
}

pub fn runtime_dir() -> Result<PathBuf> {
    #[cfg(target_os = "macos")]
    let result = prepare_runtime_dir(Path::new("/var/db"));
    #[cfg(target_os = "linux")]
    let result = linux_runtime_dir();
    result.map_err(Error::io("preparing the Warren runtime lock directory"))
}

#[cfg(target_os = "linux")]
fn linux_runtime_dir() -> io::Result<PathBuf> {
    let primary_base = Path::new("/run");
    let primary = prepare_runtime_dir(primary_base);
    // OpenWrt's /var can point into /tmp. Its persistent fallback lives
    // under /etc, outside the user-writable temporary directory.
    let fallback_base = Path::new(if Path::new("/etc/openwrt_release").exists() { "/etc" } else { "/var/lib" });
    let fallback = match existing_runtime_dir(fallback_base) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if primary.is_ok() {
                return primary;
            }
            prepare_runtime_dir(fallback_base)?
        }
        result => result?,
    };
    let election = open_dir(&fallback)?;
    election.lock()?;
    let boot_id = fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    let marker = fallback.join("fallback-boot");
    match fs::read_to_string(&marker) {
        Ok(recorded) if recorded == boot_id => return Ok(fallback),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    // Recheck /run after opening the fallback. If another startup has
    // created the primary, it will also consult this election. A fallback
    // selected before /run became writable remains authoritative this boot.
    match primary.or_else(|_| existing_runtime_dir(primary_base)) {
        Ok(dir) => Ok(dir),
        Err(e) if matches!(e.kind(), io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied) => {
            fs::write(marker, boot_id)?;
            Ok(fallback)
        }
        Err(e) => Err(e),
    }
}

fn existing_runtime_dir(base: &Path) -> io::Result<PathBuf> {
    let dir = protected(base, false, true)?.join("warren-locks");
    check_runtime_dir(&open_dir(&dir)?)?;
    Ok(dir)
}

fn check_runtime_dir(dir: &File) -> io::Result<()> {
    check_root_dir(dir)?;
    if dir.metadata()?.mode() & 0o077 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, "the Warren lock directory must be private"));
    }
    Ok(())
}

fn prepare_runtime_dir(base: &Path) -> io::Result<PathBuf> {
    match existing_runtime_dir(base) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let dir = protected(base, false, true)?.join("warren-locks");
            match fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            check_runtime_dir(&open_dir(&dir)?)?;
            Ok(dir)
        }
        result => result,
    }
}

pub fn open_dir(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW).open(path)
}

pub fn open_lock(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .mode(0o600)
        .open(path)
        .and_then(validate_lock)
        .map_err(Error::io(format!("opening lock {}", path.display())))
}

pub fn lock(path: &Path) -> Result<File> {
    let file = open_lock(path)?;
    file.lock().map_err(Error::io(format!("locking {}", path.display())))?;
    Ok(file)
}

pub fn try_lock(path: &Path) -> Result<Option<File>> {
    let file = open_lock(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(e)) => Err(Error::io(format!("locking {}", path.display()))(e)),
    }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
#[ignore = "requires a privileged read-only bind mount"]
fn keeps_locks_when_run_becomes_writable() {
    use std::process::Command;

    const ISOLATED: &str = "WARREN_TEST_PRIVATE_RUN";
    if std::env::var_os(ISOLATED).is_none() {
        // Isolate /run so the remount cannot affect other privileged tests.
        let status = Command::new("unshare")
            .arg("--mount")
            .arg(std::env::current_exe().unwrap())
            .args(["--ignored", "--exact", "update_files::keeps_locks_when_run_becomes_writable"])
            .env(ISOLATED, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let mount = |args: &[&str]| assert!(Command::new("mount").args(args).status().unwrap().success());
    mount(&["-t", "tmpfs", "-o", "mode=1777", "tmpfs", "/tmp"]);
    assert!(Command::new("mkdir").arg("/tmp/warren-locks").status().unwrap().success());
    assert!(Command::new("chown").args(["65534:65534", "/tmp/warren-locks"]).status().unwrap().success());
    mount(&["-t", "tmpfs", "-o", "mode=755", "tmpfs", "/run"]);
    mount(&["-t", "tmpfs", "-o", "mode=755", "tmpfs", "/var/lib"]);
    mount(&["--bind", "/run", "/run"]);
    mount(&["-o", "remount,bind,ro", "/run"]);
    let name = format!("remount-{}.test", std::process::id());
    let first = runtime_dir().unwrap().join(&name);
    assert!(first.starts_with("/var/lib/warren-locks"));
    let locked = lock(&first).unwrap();
    mount(&["-o", "remount,bind,rw", "/run"]);
    let second = runtime_dir().unwrap().join(name);
    assert_eq!(first, second);
    assert!(try_lock(&second).unwrap().is_none());
    drop(locked);
    fs::remove_file(first).unwrap();
}
