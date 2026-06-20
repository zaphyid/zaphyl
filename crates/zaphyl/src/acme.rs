//! Live ACME (HTTP-01) certificate acquisition and renewal.
//!
//! Model: *obtain, serve, renew.* The plain-HTTP front (see
//! [`crate::http_front`]) answers the CA's validation requests from the shared
//! [`ChallengeStore`]. At startup we obtain (or load from cache) the
//! certificate; a background loop then re-obtains it as it nears expiry,
//! rewriting the cache files. The TLS listener serves the cert through
//! [`crate::tls::DynamicCert`], so a renewed cert is picked up without a restart.

use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zaphyl_config::AcmeConfig;
use zaphyl_core::acme::ChallengeStore;

/// A boxed, thread-safe error.
type DynError = Box<dyn std::error::Error + Send + Sync>;

/// Seconds in a day.
const SECONDS_PER_DAY: i64 = 86_400;

/// Owns the renewal machinery: the configured ACME settings, the shared
/// challenge store (served by the HTTP front), and the cached certificate paths.
/// Kept alive for the life of the process so renewal can keep running.
pub struct AcmeRunner {
    config: AcmeConfig,
    store: Arc<ChallengeStore>,
    cert_path: PathBuf,
    key_path: PathBuf,
}

impl AcmeRunner {
    /// Obtain (or load from cache) the initial certificate. The given `store`
    /// must already be served by a running HTTP front so the CA can validate.
    ///
    /// # Errors
    /// Fails if the ACME order fails or the certificate cannot be written to the
    /// cache directory.
    pub fn start(config: &AcmeConfig, store: Arc<ChallengeStore>) -> Result<Self, DynError> {
        let cache = Path::new(&config.cache_dir);
        std::fs::create_dir_all(cache)?;
        let cert_path = cache.join("cert.pem");
        let key_path = cache.join("key.pem");

        if !(cert_path.exists() && key_path.exists()) {
            obtain(config, &store, &cert_path, &key_path)?;
        }

        Ok(Self {
            config: config.clone(),
            store,
            cert_path,
            key_path,
        })
    }

    /// The cached certificate and key paths to hand to the TLS listener.
    #[must_use]
    pub fn cert_paths(&self) -> (PathBuf, PathBuf) {
        (self.cert_path.clone(), self.key_path.clone())
    }

    /// Spawn the background renewal loop. The loop shares this runner's challenge
    /// store, so renewals are validated by the same (still-running) HTTP front.
    pub fn spawn_renewal(&self) {
        let config = self.config.clone();
        let store = Arc::clone(&self.store);
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();
        std::thread::spawn(move || renewal_loop(&config, &store, &cert_path, &key_path));
    }
}

/// Periodically re-obtain the certificate as it nears expiry.
fn renewal_loop(config: &AcmeConfig, store: &ChallengeStore, cert_path: &Path, key_path: &Path) {
    let interval = Duration::from_secs(config.check_interval_seconds);
    let window = i64::try_from(config.renew_before_days)
        .unwrap_or(i64::MAX)
        .saturating_mul(SECONDS_PER_DAY);
    loop {
        std::thread::sleep(interval);
        let due = match std::fs::read_to_string(cert_path) {
            Ok(pem) => needs_renewal(&pem, now_unix(), window),
            Err(_) => true,
        };
        if !due {
            continue;
        }
        eprintln!("zaphyl: certificate due for renewal, obtaining a new one");
        match obtain(config, store, cert_path, key_path) {
            Ok(()) => eprintln!("zaphyl: certificate renewed"),
            Err(e) => eprintln!("zaphyl: renewal failed: {e}"),
        }
    }
}

/// Whether the certificate should be renewed: true if it expires within
/// `renew_before_secs` of `now_unix`, or cannot be parsed (renew to be safe).
#[must_use]
pub fn needs_renewal(cert_pem: &str, now_unix: i64, renew_before_secs: i64) -> bool {
    match cert_not_after_unix(cert_pem) {
        Some(not_after) => not_after.saturating_sub(now_unix) < renew_before_secs,
        None => true,
    }
}

/// Parse the certificate's `notAfter` as a Unix timestamp.
fn cert_not_after_unix(cert_pem: &str) -> Option<i64> {
    let entry = x509_parser::pem::Pem::iter_from_buffer(cert_pem.as_bytes())
        .next()?
        .ok()?;
    let cert = entry.parse_x509().ok()?;
    Some(cert.validity().not_after.timestamp())
}

/// Current time as seconds since the Unix epoch.
fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(0)
}

/// Run a full ACME order and write the issued certificate and key to the cache.
fn obtain(
    acme: &AcmeConfig,
    store: &ChallengeStore,
    cert_path: &Path,
    key_path: &Path,
) -> Result<(), DynError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(1)
        .enable_all()
        .build()?;
    let (cert_pem, key_pem) = runtime.block_on(run_order(acme, store))?;
    std::fs::write(cert_path, cert_pem)?;
    std::fs::write(key_path, key_pem)?;
    Ok(())
}

/// Run the ACME order to completion and return the (cert chain PEM, key PEM).
async fn run_order(
    acme: &AcmeConfig,
    store: &ChallengeStore,
) -> Result<(String, String), DynError> {
    // Trust a custom root for test CAs (e.g. Pebble); otherwise use webpki roots.
    let builder = match std::env::var("ZAPHYL_ACME_ROOT_CERT") {
        Ok(path) if !path.is_empty() => Account::builder_with_root(path)?,
        _ => Account::builder()?,
    };

    let contact = format!("mailto:{}", acme.email);
    let (account, _credentials) = builder
        .create(
            &NewAccount {
                contact: &[contact.as_str()],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            acme.directory.clone(),
            None,
        )
        .await?;

    let identifiers: Vec<Identifier> = acme
        .domains
        .iter()
        .map(|domain| Identifier::Dns(domain.clone()))
        .collect();
    let mut order = account
        .new_order(&NewOrder::new(identifiers.as_slice()))
        .await?;

    // Scope the authorizations iterator so its mutable borrow of `order` is
    // released before we poll and finalize the order below.
    {
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result?;
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => {
                    return Err(format!("unexpected authorization status: {other:?}").into());
                }
            }
            let mut challenge = authz
                .challenge(ChallengeType::Http01)
                .ok_or("no http-01 challenge offered")?;
            let token = challenge.token.clone();
            let key_authorization = challenge.key_authorization().as_str().to_owned();
            store.insert(token, key_authorization);
            challenge.set_ready().await?;
        }
    }

    let status = order.poll_ready(&RetryPolicy::default()).await?;
    if status != OrderStatus::Ready {
        return Err(format!("order did not become ready: {status:?}").into());
    }
    let key_pem = order.finalize().await?;
    let cert_pem = order.poll_certificate(&RetryPolicy::default()).await?;
    Ok((cert_pem, key_pem))
}

#[cfg(test)]
mod tests {
    use super::{cert_not_after_unix, needs_renewal};

    fn test_cert() -> String {
        rcgen::generate_simple_self_signed(vec!["renew.example".to_owned()])
            .unwrap()
            .cert
            .pem()
    }

    #[test]
    fn renewal_decision_tracks_expiry() {
        let pem = test_cert();
        let not_after = cert_not_after_unix(&pem).expect("parse expiry");
        let day = 86_400;

        // 5 days before expiry, renewing 30 days out -> renew.
        assert!(needs_renewal(&pem, not_after - 5 * day, 30 * day));
        // 60 days before expiry, renewing 30 days out -> not yet.
        assert!(!needs_renewal(&pem, not_after - 60 * day, 30 * day));
        // Already past expiry -> renew.
        assert!(needs_renewal(&pem, not_after + 100, 30 * day));
    }

    #[test]
    fn unparseable_cert_renews() {
        assert!(needs_renewal("not a certificate", 0, 30 * 86_400));
    }
}
