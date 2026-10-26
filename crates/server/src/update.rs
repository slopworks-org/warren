//! New releases: a daily look at the latest GitHub release, and installing it.
//!
//! The sandboxed server cannot write its own binary. It downloads the new
//! binary to `<data_dir>/update/warren-server` and exits with
//! [`RESTART_EXIT`]. The systemd unit then runs `warren-server apply-update`
//! with full privileges before the next start, which puts the binary in place.

use crate::state::AppState;
use http::header::{ACCEPT, LOCATION, USER_AGENT};
use http::{Request, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use thiserror::Error;

/// The GitHub repository releases come from.
pub const REPO: &str = "slopworks-org/warren";
const CHECK_INTERVAL: Duration = Duration::from_hours(24);
const RETRY_INTERVAL: Duration = Duration::from_hours(1);
const MAX_REDIRECTS: usize = 5;
const NOT_FOUND: &str = "HTTP 404 Not Found";
/// The exit code that asks systemd to restart the server into a staged update.
pub const RESTART_EXIT: u8 = 75;
/// Set to `1` by the systemd unit that runs `apply-update` before each start.
pub const SELF_UPDATE_ENV: &str = "WARREN_SELF_UPDATE";

/// Why a release could not be fetched.
#[derive(Debug, Error)]
pub enum UpdateError {
    /// No TLS roots could be loaded.
    #[error("loading TLS roots: {0}")]
    Roots(rustls::Error),
    /// The request failed or timed out.
    #[error("requesting {url}: {message}")]
    Http {
        /// The requested URL.
        url: String,
        /// What went wrong.
        message: String,
    },
    /// The URL answers 404, e.g. before the first release.
    #[error("{0} does not exist")]
    NotFound(String),
    /// The release data is not what GitHub sends.
    #[error("reading the release: {0}")]
    Release(String),
    /// The download does not match `SHA256SUMS`.
    #[error("{0} does not match SHA256SUMS")]
    Checksum(String),
    /// This server cannot replace its own binary.
    #[error("{0}")]
    Unsupported(String),
    /// The running version is the latest one.
    #[error("this server already runs the latest release")]
    UpToDate,
    /// Another update is in progress.
    #[error("an update is already in progress")]
    Busy,
    /// Storing the new binary failed.
    #[error("storing the new binary: {0}")]
    Store(std::io::Error),
}

/// The latest published release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Release {
    /// Version without the `v`, e.g. `0.2.0`.
    pub version: String,
    /// The git tag, e.g. `v0.2.0`.
    pub tag: String,
    /// The release page.
    pub url: String,
}

#[derive(Deserialize)]
struct GithubRelease {
    tag_name: String,
    html_url: String,
}

/// Parses `1.2.3` or `v1.2.3`; pre-release and build suffixes are refused.
#[must_use]
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let mut parts = s.strip_prefix('v').unwrap_or(s).split('.').map(|p| p.parse::<u64>().ok());
    let v = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(v)
}

/// Whether `candidate` is a later version than `current`.
#[must_use]
pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (parse_version(candidate), parse_version(current)) {
        (Some(c), Some(cur)) => c > cur,
        _ => false,
    }
}

/// HTTPS client for GitHub.
pub struct Fetcher {
    client: Client<HttpsConnector<HttpConnector>, Empty<Bytes>>,
}

impl Fetcher {
    /// Builds a client that trusts the system's certificate store.
    ///
    /// # Errors
    /// When the certificate store cannot be read.
    pub fn new() -> Result<Fetcher, UpdateError> {
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .try_with_platform_verifier()
            .map_err(UpdateError::Roots)?
            .https_only()
            .enable_http1()
            .build();
        Ok(Fetcher { client: Client::builder(TokioExecutor::new()).build(connector) })
    }

    /// GETs `url`, following redirects, and returns at most `limit` bytes of body.
    ///
    /// # Errors
    /// On network errors, a non-200 answer, a larger body or a timeout.
    pub async fn get(&self, url: &str, limit: usize, timeout: Duration) -> Result<Bytes, UpdateError> {
        let fail = |message: String| UpdateError::Http { url: url.to_string(), message };
        tokio::time::timeout(timeout, self.get_inner(url, limit))
            .await
            .map_err(|_| fail("timed out".into()))?
            .map_err(|e| if e == NOT_FOUND { UpdateError::NotFound(url.to_string()) } else { fail(e) })
    }

    async fn get_inner(&self, url: &str, limit: usize) -> Result<Bytes, String> {
        let mut uri: Uri = url.parse().map_err(|e| format!("{e}"))?;
        for _ in 0..=MAX_REDIRECTS {
            let req = Request::get(uri.clone())
                .header(USER_AGENT, concat!("warren-server/", env!("CARGO_PKG_VERSION")))
                .header(ACCEPT, "application/vnd.github+json, */*")
                .body(Empty::new())
                .map_err(|e| e.to_string())?;
            let resp = self.client.request(req).await.map_err(|e| e.to_string())?;
            let status = resp.status();
            if status.is_redirection() {
                let next =
                    resp.headers().get(LOCATION).and_then(|v| v.to_str().ok()).ok_or("redirect without Location")?;
                uri = resolve(&uri, next)?;
                continue;
            }
            if status == StatusCode::NOT_FOUND {
                return Err(NOT_FOUND.into());
            }
            if status != StatusCode::OK {
                return Err(format!("HTTP {status}"));
            }
            let body = Limited::new(resp.into_body(), limit).collect().await.map_err(|e| e.to_string())?;
            return Ok(body.to_bytes());
        }
        Err("too many redirects".into())
    }

    /// The latest release of [`REPO`].
    ///
    /// # Errors
    /// When GitHub cannot be reached or answers with something else.
    pub async fn latest(&self) -> Result<Release, UpdateError> {
        let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
        let body = self.get(&url, 1 << 20, Duration::from_secs(30)).await?;
        let r: GithubRelease = serde_json::from_slice(&body).map_err(|e| UpdateError::Release(e.to_string()))?;
        if parse_version(&r.tag_name).is_none() {
            return Err(UpdateError::Release(format!("tag {:?} is not a version", r.tag_name)));
        }
        let version = r.tag_name.strip_prefix('v').unwrap_or(&r.tag_name).to_string();
        Ok(Release { version, tag: r.tag_name, url: r.html_url })
    }
}

/// Resolves a `Location` value against the URL that returned it.
fn resolve(base: &Uri, location: &str) -> Result<Uri, String> {
    if location.starts_with("https://") {
        return location.parse().map_err(|e| format!("{e}"));
    }
    if !location.starts_with('/') {
        return Err(format!("unsupported redirect to {location:?}"));
    }
    let authority = base.authority().ok_or("redirect from a URL without a host")?;
    format!("https://{authority}{location}").parse().map_err(|e| format!("{e}"))
}

/// Whether the systemd unit installs a staged binary, see the module docs.
#[must_use]
pub fn self_update_supported() -> bool {
    cfg!(target_os = "linux") && std::env::var_os(SELF_UPDATE_ENV).is_some_and(|v| v == "1")
}

/// Why the server cannot update itself, if it cannot.
#[must_use]
pub fn self_update_blocker() -> Option<&'static str> {
    if server_asset().is_none() {
        Some("there is no server build for this platform")
    } else if !self_update_supported() {
        Some("the systemd unit does not support updates; upgrade once with install.sh")
    } else {
        None
    }
}

fn server_asset() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("warren-server-linux-amd64"),
        ("linux", "aarch64") => Some("warren-server-linux-arm64"),
        _ => None,
    }
}

/// The download URL of a release file.
#[must_use]
pub fn asset_url(tag: &str, file: &str) -> String {
    format!("https://github.com/{REPO}/releases/download/{tag}/{file}")
}

/// The SHA-256 of `file` in a `SHA256SUMS` listing.
#[must_use]
pub fn checksum<'a>(sums: &'a str, file: &str) -> Option<&'a str> {
    sums.lines().find_map(|l| {
        let (hash, name) = l.split_once(char::is_whitespace)?;
        let name = name.trim_start();
        (name.strip_prefix('*').unwrap_or(name) == file).then_some(hash)
    })
}

/// Where the downloaded binary waits for `apply-update`.
#[must_use]
pub fn staged_path(data_dir: &Path) -> PathBuf {
    data_dir.join("update").join("warren-server")
}

impl Fetcher {
    /// Downloads a release file and checks it against the release's `SHA256SUMS`.
    ///
    /// # Errors
    /// On download errors, a missing entry or a checksum mismatch.
    pub async fn release_file(&self, tag: &str, file: &str) -> Result<Bytes, UpdateError> {
        let sums = self.get(&asset_url(tag, "SHA256SUMS"), 64 * 1024, Duration::from_secs(30)).await?;
        let sums = String::from_utf8_lossy(&sums);
        let want = checksum(&sums, file).ok_or_else(|| UpdateError::Release(format!("SHA256SUMS lists no {file}")))?;
        let data = self.get(&asset_url(tag, file), 64 << 20, Duration::from_mins(5)).await?;
        if !crate::util::sha256_hex(&data).eq_ignore_ascii_case(want) {
            return Err(UpdateError::Checksum(file.into()));
        }
        Ok(data)
    }
}

fn store_executable(path: &Path, data: &[u8]) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o755).open(&tmp)?;
    f.set_permissions(std::fs::Permissions::from_mode(0o755))?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)
}

static UPDATING: AtomicBool = AtomicBool::new(false);

/// Downloads the latest release, stages it and asks the server to restart.
///
/// # Errors
/// When there is nothing to install, the server cannot update itself, or
/// the download fails.
pub async fn install(state: &AppState, fetcher: &Fetcher) -> Result<Release, UpdateError> {
    if let Some(why) = self_update_blocker() {
        return Err(UpdateError::Unsupported(why.into()));
    }
    let asset = server_asset().ok_or_else(|| UpdateError::Unsupported("no server build".into()))?;
    let release = state
        .latest_release
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .filter(|r| is_newer(&r.version, warren_proto::VERSION))
        .ok_or(UpdateError::UpToDate)?;
    if UPDATING.swap(true, Ordering::SeqCst) {
        return Err(UpdateError::Busy);
    }
    let result = async {
        let data = fetcher.release_file(&release.tag, asset).await?;
        store_executable(&staged_path(&state.config.data_dir), &data).map_err(UpdateError::Store)
    }
    .await;
    if let Err(e) = result {
        UPDATING.store(false, Ordering::SeqCst);
        return Err(e);
    }
    tracing::info!(version = %release.version, "update downloaded; restarting");
    state.restart.notify_one();
    Ok(release)
}

/// `apply-update`: moves a staged binary over the running one.
/// Returns the installed version, or `None` when nothing is staged.
///
/// # Errors
/// When the staged binary does not run or cannot be moved; it is removed then.
pub fn apply_staged(data_dir: &Path) -> std::io::Result<Option<String>> {
    let staged = staged_path(data_dir);
    if !staged.exists() {
        return Ok(None);
    }
    let result = replace_exe(&staged);
    let _ = std::fs::remove_file(&staged);
    result.map(Some)
}

fn replace_exe(staged: &Path) -> std::io::Result<String> {
    let out = std::process::Command::new(staged).arg("--version").output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let version = text.trim().strip_prefix("warren-server ").filter(|_| out.status.success());
    let Some(version) = version.map(str::to_string) else {
        return Err(std::io::Error::other("the downloaded binary does not run"));
    };
    let exe = std::env::current_exe()?;
    let tmp = exe.with_extension("new");
    std::fs::copy(staged, &tmp)?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755))?;
    std::fs::rename(&tmp, &exe)?;
    Ok(version)
}

/// Looks for a new release once a day while `[update] check` is on, and
/// installs it when `[update] auto` is on too.
pub async fn task(state: Arc<AppState>) {
    let fetcher = match Fetcher::new() {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error = %e, "cannot check for new releases");
            return;
        }
    };
    loop {
        let wait = match fetcher.latest().await {
            Ok(release) => {
                let newer = is_newer(&release.version, warren_proto::VERSION);
                if newer {
                    tracing::info!(version = %release.version, url = %release.url, "a new release is available");
                }
                *state.latest_release.write().unwrap_or_else(PoisonError::into_inner) = Some(release);
                if newer && state.config.update.auto {
                    match install(&state, &fetcher).await {
                        Ok(r) => state.audit(None, &"", "server.update", "server", &format!("to {}", r.version)),
                        Err(e) => tracing::warn!(error = %e, "installing the new release"),
                    }
                }
                CHECK_INTERVAL
            }
            Err(UpdateError::NotFound(_)) => {
                tracing::debug!("no release published yet");
                CHECK_INTERVAL
            }
            Err(e) => {
                tracing::warn!(error = %e, "checking for a new release");
                RETRY_INTERVAL
            }
        };
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v0.12.3"), Some((0, 12, 3)));
        assert_eq!(parse_version("1.0.0"), Some((1, 0, 0)));
        assert_eq!(parse_version("v1.0"), None);
        assert_eq!(parse_version("v1.0.0-rc1"), None);
        assert_eq!(parse_version("v1.0.0.1"), None);
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("v1.0.0", "0.99.0"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.0.9", "0.1.0"));
        assert!(!is_newer("garbage", "0.1.0"));
    }

    #[test]
    fn checksums() {
        let sums = "aa11  warren-server-linux-amd64\nbb22 *warren-linux-armv7\n";
        assert_eq!(checksum(sums, "warren-server-linux-amd64"), Some("aa11"));
        assert_eq!(checksum(sums, "warren-linux-armv7"), Some("bb22"));
        assert_eq!(checksum(sums, "warren-server"), None);
    }

    #[test]
    fn applies_a_staged_binary_only_if_it_runs() {
        let dir = std::env::temp_dir().join(format!("warren-update-{}", std::process::id()));
        assert_eq!(apply_staged(&dir).unwrap(), None);
        store_executable(&staged_path(&dir), b"#!/bin/sh\nexit 1\n").unwrap();
        assert!(apply_staged(&dir).is_err());
        assert!(!staged_path(&dir).exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn redirects() {
        let base: Uri = "https://github.com/a/b/releases/latest".parse().unwrap();
        assert_eq!(
            resolve(&base, "/a/b/releases/tag/v1.0.0").unwrap().to_string(),
            "https://github.com/a/b/releases/tag/v1.0.0"
        );
        assert_eq!(
            resolve(&base, "https://objects.example.com/x").unwrap().to_string(),
            "https://objects.example.com/x"
        );
        assert!(resolve(&base, "http://plain.example.com/x").is_err());
        assert!(resolve(&base, "relative").is_err());
    }
}
