//! Certificates from Let's Encrypt (or another ACME CA) via HTTP-01.
//!
//! One certificate per host, issued sequentially. Failures back off per host
//! (1 h doubling to 24 h) to stay clear of the CA's rate limits; until a host
//! has a real certificate, TLS falls back to a self-signed one.

use crate::secrets::write_file;
use crate::state::AppState;
use crate::util::now;
use instant_acme::{
    Account, AccountCredentials, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, PoisonError};
use std::time::Duration;
use thiserror::Error;

/// Why a certificate could not be obtained.
#[derive(Debug, Error)]
pub enum AcmeError {
    /// The CA or the HTTP client reported an error.
    #[error(transparent)]
    Acme(#[from] instant_acme::Error),
    /// The order ended in an unexpected state.
    #[error("order for {host} ended as {status:?}")]
    Order {
        /// Host being certified.
        host: String,
        /// Final status.
        status: OrderStatus,
    },
    /// The CA offered no HTTP-01 challenge.
    #[error("no HTTP-01 challenge offered for {0}")]
    NoChallenge(String),
    /// Generating the key or CSR failed.
    #[error("generating key or CSR: {0}")]
    Csr(#[from] rcgen::Error),
    /// Storing the account or certificate failed.
    #[error("storing {what}: {source}")]
    Store {
        /// What was being stored.
        what: &'static str,
        /// The underlying error.
        source: std::io::Error,
    },
    /// Installing the certificate failed.
    #[error(transparent)]
    Tls(#[from] crate::tls::TlsError),
}

fn account_path(state: &AppState) -> PathBuf {
    state.config.data_dir.join("acme-account.json")
}

async fn account(state: &AppState) -> Result<Account, AcmeError> {
    let path = account_path(state);
    if let Ok(text) = std::fs::read_to_string(&path)
        && let Ok(creds) = serde_json::from_str::<AccountCredentials>(&text)
    {
        return Ok(Account::builder()?.from_credentials(creds).await?);
    }
    let contact = state.config.acme_email.as_deref().map(|e| format!("mailto:{e}"));
    let contact: Vec<&str> = contact.iter().map(String::as_str).collect();
    let (account, creds) = Account::builder()?
        .create(
            &NewAccount { contact: &contact, terms_of_service_agreed: true, only_return_existing: false },
            state.config.tls.acme_directory.clone(),
            None,
        )
        .await?;
    let json = serde_json::to_vec(&creds).map_err(|e| AcmeError::Store { what: "ACME account", source: e.into() })?;
    write_file(&path, &json, true).map_err(|source| AcmeError::Store { what: "ACME account", source })?;
    tracing::info!("created ACME account");
    Ok(account)
}

/// Runs one HTTP-01 order for `host` and installs the certificate.
async fn issue(state: &AppState, account: &Account, host: &str) -> Result<(), AcmeError> {
    let ids = [Identifier::Dns(host.to_string())];
    let mut order = account.new_order(&NewOrder::new(&ids)).await?;
    let mut tokens = Vec::new();
    let mut authzs = order.authorizations();
    while let Some(authz) = authzs.next().await {
        let mut authz = authz?;
        if authz.status == AuthorizationStatus::Valid {
            continue;
        }
        let mut challenge =
            authz.challenge(ChallengeType::Http01).ok_or_else(|| AcmeError::NoChallenge(host.into()))?;
        let token = challenge.token.clone();
        let key_auth = challenge.key_authorization().as_str().to_string();
        state.acme_challenges.write().unwrap_or_else(PoisonError::into_inner).insert(token.clone(), key_auth);
        tokens.push(token);
        challenge.set_ready().await?;
    }
    let result = finish(&mut order, host).await;
    let mut challenges = state.acme_challenges.write().unwrap_or_else(PoisonError::into_inner);
    for t in tokens {
        challenges.remove(&t);
    }
    drop(challenges);
    let (chain, key) = result?;
    state.certs.install(host, &chain, &key)?;
    Ok(())
}

async fn finish(order: &mut instant_acme::Order, host: &str) -> Result<(String, String), AcmeError> {
    let retry = RetryPolicy::default().timeout(Duration::from_secs(120));
    let status = order.poll_ready(&retry).await?;
    if status != OrderStatus::Ready {
        return Err(AcmeError::Order { host: host.into(), status });
    }
    let key = rcgen::KeyPair::generate()?;
    let mut params = rcgen::CertificateParams::new(vec![host.to_string()])?;
    // rcgen defaults the subject to CN="rcgen self signed cert", which ACME CAs reject.
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params.serialize_request(&key)?;
    order.finalize_csr(csr.der()).await?;
    let chain = order.poll_certificate(&retry).await?;
    Ok((chain, key.serialize_pem()))
}

/// Keeps certificates for every served host issued and renewed.
pub async fn task(state: Arc<AppState>) {
    let mut account_cache: Option<Account> = None;
    let mut backoff: HashMap<String, (i64, i64)> = HashMap::new();
    loop {
        let due: Vec<String> = state
            .certs
            .needing_certs()
            .into_iter()
            .filter(|h| backoff.get(h).is_none_or(|(retry_at, _)| now() >= *retry_at))
            .collect();
        for host in due {
            if account_cache.is_none() {
                match account(&state).await {
                    Ok(a) => account_cache = Some(a),
                    Err(e) => {
                        tracing::error!(error = %e, "ACME account unavailable");
                        break;
                    }
                }
            }
            let Some(acct) = &account_cache else { break };
            tracing::info!(host, "requesting certificate");
            match issue(&state, acct, &host).await {
                Ok(()) => {
                    backoff.remove(&host);
                    tracing::info!(host, "certificate installed");
                }
                Err(e) => {
                    let delay = backoff.get(&host).map_or(3600, |(_, d)| (d * 2).min(86_400));
                    backoff.insert(host.clone(), (now() + delay, delay));
                    tracing::warn!(host, error = %e, retry_in_secs = delay, "certificate request failed");
                }
            }
        }
        // Re-check hourly, or as soon as the set of hosts changes.
        let _ = tokio::time::timeout(Duration::from_secs(3600), state.acme_wake.notified()).await;
    }
}
