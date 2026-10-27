//! New releases: a daily look at the latest GitHub release.
//!
//! The admin shows the result; nothing is installed from here.

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
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use thiserror::Error;

/// The GitHub repository releases come from.
pub const REPO: &str = "slopworks-org/warren";
const CHECK_INTERVAL: Duration = Duration::from_hours(24);
const RETRY_INTERVAL: Duration = Duration::from_hours(1);
const MAX_REDIRECTS: usize = 5;
const NOT_FOUND: &str = "HTTP 404 Not Found";

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

/// Looks for a new release once a day while `[update] check` is on.
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
                if is_newer(&release.version, warren_proto::VERSION) {
                    tracing::info!(version = %release.version, url = %release.url, "a new release is available");
                }
                *state.latest_release.write().unwrap_or_else(PoisonError::into_inner) = Some(release);
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
