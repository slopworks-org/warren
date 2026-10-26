//! Server secrets on disk, readable only by the server's user.

use crate::util::random;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use warren_proto::codec;

/// Atomically writes a file; `private` files get mode 0600.
///
/// # Errors
/// On any I/O failure.
pub fn write_file(path: &Path, data: &[u8], private: bool) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }
    let mode = if private { 0o600 } else { 0o644 };
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(&tmp)?;
    f.set_permissions(fs::Permissions::from_mode(mode))?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

/// Loads a 32-byte key stored as base64, creating it on first use.
/// Tightens permissions that are too open.
///
/// # Errors
/// On I/O failure or a corrupt key file.
pub fn load_or_create_key(path: &Path) -> io::Result<[u8; 32]> {
    match fs::read_to_string(path) {
        Ok(text) => {
            if fs::metadata(path)?.permissions().mode() & 0o077 != 0 {
                tracing::warn!(path = %path.display(), "secret was readable by others; fixing permissions");
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
            codec::decode_key(text.trim()).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("{} is not a valid key", path.display()))
            })
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            let mut key = random::<32>();
            // Clamp so the same file also works as an X25519 private key.
            key[0] &= 0xf8;
            key[31] = (key[31] & 0x7f) | 0x40;
            write_file(path, format!("{}\n", codec::encode_key(&key)).as_bytes(), true)?;
            Ok(key)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_is_created_once_with_private_mode() {
        let dir = std::env::temp_dir().join(format!("warren-secrets-{}", std::process::id()));
        let path = dir.join("k.key");
        let a = load_or_create_key(&path).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(load_or_create_key(&path).unwrap(), a);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        fs::remove_dir_all(dir).unwrap();
    }
}
