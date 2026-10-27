//! Replaces the agent binary when the server's config names a newer version.
//!
//! The new binary comes from the server over the control channel, which
//! WireGuard authenticates. It must run and print the expected version before
//! it replaces the current one. The agent then `exec`s it with the same
//! arguments, so the PID and the tunnel interface stay.

use crate::error::{Error, Result};
use crate::{http, log};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;
use warren_proto::BINARY_PATH;

/// Installs `version` from the server at `control` and execs it.
/// Returns only when that fails.
pub fn update(control: &str, version: &str) -> Error {
    let exe = match install(control, version) {
        Ok(exe) => exe,
        Err(e) => return e,
    };
    log!(Info, "updated; restarting", version = version);
    let e = Command::new(&exe).args(std::env::args_os().skip(1)).exec();
    Error::io(format!("starting {}", exe.display()))(e)
}

fn install(control: &str, version: &str) -> Result<PathBuf> {
    let file = warren_proto::agent_asset().ok_or(Error::BadReply("no agent build for this platform"))?;
    let (status, data) = http::download(control, &format!("{BINARY_PATH}?file={file}"), Duration::from_secs(300))
        .map_err(Error::io(format!("downloading {file}")))?;
    if status != 200 {
        let message = String::from_utf8_lossy(&data).trim().chars().take(200).collect();
        return Err(Error::Server { status, message });
    }
    let exe = std::env::current_exe().map_err(Error::io("finding the agent binary"))?;
    let new = exe.with_extension("new");
    write_executable(&new, &data).map_err(Error::io(format!("writing {}", new.display())))?;
    if reported_version(&new).as_deref() != Some(version) {
        let _ = std::fs::remove_file(&new);
        return Err(Error::BadReply("the downloaded agent does not run or has another version"));
    }
    std::fs::rename(&new, &exe).map_err(Error::io(format!("replacing {}", exe.display())))?;
    Ok(exe)
}

fn write_executable(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}

/// What `<bin> version` prints after `warren `.
fn reported_version(bin: &Path) -> Option<String> {
    let out = Command::new(bin).arg("version").output().ok().filter(|o| o.status.success())?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.trim().strip_prefix("warren ").map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_version_of_a_binary() {
        let dir = std::env::temp_dir().join(format!("warren-selfupdate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("warren");
        write_executable(&bin, b"#!/bin/sh\necho warren 9.8.7\n").unwrap();
        assert_eq!(reported_version(&bin).as_deref(), Some("9.8.7"));
        write_executable(&bin, b"#!/bin/sh\nexit 1\n").unwrap();
        assert_eq!(reported_version(&bin), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
