//! Dynamic TLS certificates.
//!
//! Instead of binding the certificate once at startup, the TLS listeners ask a
//! provider for the certificate during each handshake. The provider reads the
//! cert and key from disk and re-parses them only when the cert file's
//! modification time changes. That lets a renewed certificate (ACME rewrites the
//! cached files) take effect without restarting the server.
//!
//! [`ReloadCache`] is the shared reload-on-change primitive; the BoringSSL
//! provider here ([`DynamicCert`], for the HTTP/1·2 listener) and the rustls
//! resolver in [`crate::http3`] (for the QUIC listener) both build on it.

use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::tls::ext::{ssl_add_chain_cert, ssl_use_certificate, ssl_use_private_key};
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::x509::X509;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

/// Caches a value parsed from a file, reloading it when the file's modification
/// time changes. The cached value is shared as an `Arc`, so handshakes read it
/// without re-parsing while the file is unchanged.
#[derive(Debug)]
pub struct ReloadCache<T> {
    path: PathBuf,
    cached: RwLock<Option<(SystemTime, Arc<T>)>>,
}

impl<T> ReloadCache<T> {
    /// Create a cache watching the given file.
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            cached: RwLock::new(None),
        }
    }

    /// Return the current value, calling `load` to (re)parse it when the watched
    /// file changes. `None` if the file is missing or `load` returns `None`.
    pub fn get(&self, load: impl FnOnce() -> Option<T>) -> Option<Arc<T>> {
        let mtime = std::fs::metadata(&self.path).ok()?.modified().ok()?;

        if let Ok(guard) = self.cached.read()
            && let Some((cached_mtime, value)) = guard.as_ref()
            && *cached_mtime == mtime
        {
            return Some(Arc::clone(value));
        }

        let value = Arc::new(load()?);
        if let Ok(mut guard) = self.cached.write() {
            *guard = Some((mtime, Arc::clone(&value)));
        }
        Some(value)
    }
}

/// A parsed certificate chain (leaf first, then any intermediates) and its key.
struct Loaded {
    leaf: X509,
    chain: Vec<X509>,
    key: PKey<Private>,
}

/// Serves a TLS certificate read from PEM files to the BoringSSL (HTTP/1·2)
/// listener, reloading when the cert file changes on disk.
pub struct DynamicCert {
    cert_path: PathBuf,
    key_path: PathBuf,
    cache: ReloadCache<Loaded>,
}

impl DynamicCert {
    /// Create a certificate provider backed by the given cert and key PEM files.
    #[must_use]
    pub fn new(cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            cache: ReloadCache::new(cert_path.clone()),
            cert_path,
            key_path,
        }
    }

    /// The current certificate, reloaded from disk if the cert file changed.
    fn current(&self) -> Option<Arc<Loaded>> {
        let cert_path = &self.cert_path;
        let key_path = &self.key_path;
        self.cache.get(|| {
            let cert_bytes = std::fs::read(cert_path).ok()?;
            let mut certs = X509::stack_from_pem(&cert_bytes).ok()?;
            if certs.is_empty() {
                return None;
            }
            let leaf = certs.remove(0);
            let key_bytes = std::fs::read(key_path).ok()?;
            let key = PKey::private_key_from_pem(&key_bytes).ok()?;
            Some(Loaded {
                leaf,
                chain: certs,
                key,
            })
        })
    }
}

#[async_trait]
impl TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        let Some(loaded) = self.current() else {
            eprintln!(
                "zaphyl: failed to load TLS certificate from {}",
                self.cert_path.display()
            );
            return;
        };
        if let Err(e) = ssl_use_certificate(ssl, &loaded.leaf) {
            eprintln!("zaphyl: failed to set TLS certificate: {e}");
            return;
        }
        if let Err(e) = ssl_use_private_key(ssl, &loaded.key) {
            eprintln!("zaphyl: failed to set TLS private key: {e}");
            return;
        }
        for cert in &loaded.chain {
            if let Err(e) = ssl_add_chain_cert(ssl, cert) {
                eprintln!("zaphyl: failed to add chain certificate: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::DynamicCert;
    use std::sync::Arc;

    fn write_cert(cert: &std::path::Path, key: &std::path::Path, name: &str) {
        let ck = rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        std::fs::write(cert, ck.cert.pem()).unwrap();
        std::fs::write(key, ck.signing_key.serialize_pem()).unwrap();
    }

    #[test]
    fn caches_then_reloads_on_change() {
        let dir = std::env::temp_dir().join("zaphyl-dyncert-test");
        std::fs::create_dir_all(&dir).unwrap();
        let cert = dir.join("cert.pem");
        let key = dir.join("key.pem");
        write_cert(&cert, &key, "first.example");

        let dynamic = DynamicCert::new(cert.clone(), key.clone());
        let first = dynamic.current().expect("load cert");
        let again = dynamic.current().expect("load cached cert");
        assert!(
            Arc::ptr_eq(&first, &again),
            "unchanged file should reuse the cached cert"
        );

        // Rewrite with a different cert; sleep so the mtime is distinct.
        std::thread::sleep(std::time::Duration::from_millis(1100));
        write_cert(&cert, &key, "second.example");

        let reloaded = dynamic.current().expect("reload cert");
        assert!(
            !Arc::ptr_eq(&first, &reloaded),
            "changed file should be reloaded"
        );
    }
}
