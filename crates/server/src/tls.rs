//! Certificates and SNI-based selection.
//!
//! Only names the server actually serves get a certificate. A handshake for
//! an unknown name, or one without SNI (a bare IP address), fails, so a
//! protected resource cannot be reached by guessing hosts or by IP.

use crate::config::TlsMode;
use crate::util::now;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};
use thiserror::Error;

/// A certificate that cannot be loaded or created.
#[derive(Debug, Error)]
pub enum TlsError {
    /// Reading or writing a PEM file failed.
    #[error("{path}: {source}")]
    Io {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// A PEM file holds no usable certificate or key.
    #[error("{0}: no usable certificate or private key")]
    Pem(PathBuf),
    /// The key type is not supported by rustls.
    #[error("unsupported private key: {0}")]
    Key(#[from] rustls::Error),
    /// Generating a certificate failed.
    #[error("generating certificate: {0}")]
    Generate(#[from] rcgen::Error),
}

/// Renew ACME certificates this long after issuance (they last 90 days).
pub const RENEW_AFTER: i64 = 60 * 86_400;

/// All certificates the server can present.
pub struct CertStore {
    mode: TlsMode,
    dir: PathBuf,
    known: RwLock<HashSet<String>>,
    issued: RwLock<HashMap<String, (Arc<CertifiedKey>, i64)>>,
    generated: RwLock<HashMap<String, Arc<CertifiedKey>>>,
    file_cert: Option<Arc<CertifiedKey>>,
}

impl std::fmt::Debug for CertStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertStore").field("mode", &self.mode).field("dir", &self.dir).finish_non_exhaustive()
    }
}

fn read(path: &Path) -> Result<Vec<u8>, TlsError> {
    std::fs::read(path).map_err(|source| TlsError::Io { path: path.to_owned(), source })
}

/// Builds a rustls key from PEM chain and key bytes.
fn certified_key(chain_pem: &[u8], key_pem: &[u8], origin: &Path) -> Result<CertifiedKey, TlsError> {
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(chain_pem).filter_map(Result::ok).collect();
    let key = PrivateKeyDer::from_pem_slice(key_pem).map_err(|_| TlsError::Pem(origin.to_owned()))?;
    if chain.is_empty() {
        return Err(TlsError::Pem(origin.to_owned()));
    }
    Ok(CertifiedKey::new(chain, any_supported_type(&key)?))
}

/// Generates a self-signed certificate for `host`.
///
/// # Errors
/// When key generation fails.
pub fn self_signed(host: &str) -> Result<CertifiedKey, TlsError> {
    let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec![host.to_string()])?;
    let key = PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
    Ok(CertifiedKey::new(vec![cert.der().clone()], any_supported_type(&key)?))
}

impl CertStore {
    /// Creates the store, loading existing ACME certificates or the
    /// configured certificate files.
    ///
    /// # Errors
    /// When configured certificate files cannot be loaded.
    pub fn new(
        mode: TlsMode,
        dir: PathBuf,
        cert_file: Option<&Path>,
        key_file: Option<&Path>,
    ) -> Result<CertStore, TlsError> {
        let file_cert = match (mode, cert_file, key_file) {
            (TlsMode::Files, Some(c), Some(k)) => Some(Arc::new(certified_key(&read(c)?, &read(k)?, c)?)),
            _ => None,
        };
        let store = CertStore {
            mode,
            dir,
            known: RwLock::new(HashSet::new()),
            issued: RwLock::new(HashMap::new()),
            generated: RwLock::new(HashMap::new()),
            file_cert,
        };
        if mode == TlsMode::Acme {
            store.load_issued();
        }
        Ok(store)
    }

    fn paths(&self, host: &str) -> (PathBuf, PathBuf, PathBuf) {
        (
            self.dir.join(format!("{host}.pem")),
            self.dir.join(format!("{host}.key")),
            self.dir.join(format!("{host}.issued")),
        )
    }

    fn load_issued(&self) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else { return };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some(host) = name.strip_suffix(".pem") else { continue };
            let (pem, key, issued) = self.paths(host);
            let loaded = read(&pem).and_then(|c| read(&key).and_then(|k| certified_key(&c, &k, &pem)));
            match loaded {
                Ok(ck) => {
                    let at = std::fs::read_to_string(&issued).ok().and_then(|s| s.trim().parse().ok()).unwrap_or(0);
                    self.issued
                        .write()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(host.to_string(), (Arc::new(ck), at));
                }
                Err(e) => tracing::warn!(host, error = %e, "ignoring unreadable certificate"),
            }
        }
    }

    /// Replaces the set of host names the server answers for.
    pub fn set_known(&self, hosts: HashSet<String>) {
        *self.known.write().unwrap_or_else(PoisonError::into_inner) = hosts;
    }

    /// Whether `host` is served.
    #[must_use]
    pub fn is_known(&self, host: &str) -> bool {
        self.known.read().unwrap_or_else(PoisonError::into_inner).contains(host)
    }

    /// Hosts whose ACME certificate is missing or due for renewal.
    #[must_use]
    pub fn needing_certs(&self) -> Vec<String> {
        let issued = self.issued.read().unwrap_or_else(PoisonError::into_inner);
        let mut hosts: Vec<String> = self
            .known
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|h| issued.get(*h).is_none_or(|(_, at)| now() - at > RENEW_AFTER))
            .cloned()
            .collect();
        hosts.sort();
        hosts
    }

    /// Stores and activates a certificate obtained via ACME.
    ///
    /// # Errors
    /// When the PEM data is unusable or cannot be written.
    pub fn install(&self, host: &str, chain_pem: &str, key_pem: &str) -> Result<(), TlsError> {
        let (pem, key, issued) = self.paths(host);
        let ck = certified_key(chain_pem.as_bytes(), key_pem.as_bytes(), &pem)?;
        let write = |p: &Path, data: &[u8], private: bool| -> Result<(), TlsError> {
            crate::secrets::write_file(p, data, private).map_err(|source| TlsError::Io { path: p.to_owned(), source })
        };
        write(&key, key_pem.as_bytes(), true)?;
        write(&pem, chain_pem.as_bytes(), false)?;
        let at = now();
        write(&issued, at.to_string().as_bytes(), false)?;
        self.issued.write().unwrap_or_else(PoisonError::into_inner).insert(host.to_string(), (Arc::new(ck), at));
        self.generated.write().unwrap_or_else(PoisonError::into_inner).remove(host);
        Ok(())
    }

    fn generated_for(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(c) = self.generated.read().unwrap_or_else(PoisonError::into_inner).get(host) {
            return Some(Arc::clone(c));
        }
        let ck = Arc::new(self_signed(host).map_err(|e| tracing::warn!(host, error = %e, "self-signed")).ok()?);
        self.generated.write().unwrap_or_else(PoisonError::into_inner).insert(host.to_string(), Arc::clone(&ck));
        Some(ck)
    }

    /// The certificate to present for `host`, if it is served.
    #[must_use]
    pub fn lookup(&self, host: &str) -> Option<Arc<CertifiedKey>> {
        if !self.is_known(host) {
            return None;
        }
        match self.mode {
            TlsMode::Files => self.file_cert.clone(),
            TlsMode::SelfSigned => self.generated_for(host),
            // Until ACME succeeds, a temporary self-signed certificate keeps
            // the host reachable (with a browser warning).
            TlsMode::Acme => self
                .issued
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .get(host)
                .map(|(c, _)| Arc::clone(c))
                .or_else(|| self.generated_for(host)),
        }
    }
}

/// rustls adapter over [`CertStore`].
#[derive(Debug)]
pub struct Resolver(pub Arc<CertStore>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.0.lookup(&hello.server_name()?.to_ascii_lowercase())
    }
}

/// Makes ring the process-wide rustls crypto provider. Idempotent.
pub fn install_crypto_provider() {
    // Fails only if a provider is already installed, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// TLS settings for the HTTPS listener: HTTP/1.1 only (WebSocket upgrades work
/// without extended CONNECT).
#[must_use]
pub fn server_config(store: Arc<CertStore>) -> rustls::ServerConfig {
    install_crypto_provider();
    let mut cfg = rustls::ServerConfig::builder().with_no_client_auth().with_cert_resolver(Arc::new(Resolver(store)));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    cfg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_known_hosts_get_certificates() {
        let store = CertStore::new(TlsMode::SelfSigned, std::env::temp_dir(), None, None).unwrap();
        store.set_known(["a.example.com".to_string()].into());
        assert!(store.lookup("a.example.com").is_some());
        assert!(store.lookup("b.example.com").is_none());
        assert!(store.lookup("1.2.3.4").is_none());
    }

    #[test]
    fn acme_install_and_renewal() {
        let dir = std::env::temp_dir().join(format!("warren-tls-{}", std::process::id()));
        let store = CertStore::new(TlsMode::Acme, dir.clone(), None, None).unwrap();
        store.set_known(["a.example.com".to_string(), "b.example.com".to_string()].into());
        assert_eq!(store.needing_certs(), ["a.example.com", "b.example.com"]);
        let rcgen::CertifiedKey { cert, signing_key } =
            rcgen::generate_simple_self_signed(vec!["a.example.com".to_string()]).unwrap();
        store.install("a.example.com", &cert.pem(), &signing_key.serialize_pem()).unwrap();
        assert_eq!(store.needing_certs(), ["b.example.com"]);
        let reloaded = CertStore::new(TlsMode::Acme, dir.clone(), None, None).unwrap();
        reloaded.set_known(["a.example.com".to_string()].into());
        assert!(reloaded.needing_certs().is_empty(), "certificates persist");
        std::fs::remove_dir_all(dir).unwrap();
    }
}
