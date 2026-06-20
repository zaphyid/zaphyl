//! Conditional re-fetch used to revalidate a stale cache entry with the origin.
//!
//! When a cached response has expired but carries an `ETag`, we ask the origin
//! "has this changed?" with `If-None-Match`. A `304` means the stored body is
//! still good (just refresh its freshness); a `200` is a new response to store.

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use zaphyl_core::router::Target;

/// A small HTTP/HTTPS client used only for cache revalidation requests.
pub type RevalidationClient = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;

/// Build the revalidation client, trusting the bundled roots plus an optional CA.
#[must_use]
pub fn build_client(upstream_ca: Option<&Path>) -> RevalidationClient {
    Client::builder(TokioExecutor::new()).build(https_connector(upstream_ca))
}

/// An HTTP/HTTPS connector trusting the bundled roots plus an optional extra CA.
fn https_connector(upstream_ca: Option<&Path>) -> HttpsConnector<HttpConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = upstream_ca
        && let Ok(certs) = CertificateDer::pem_file_iter(path)
    {
        for cert in certs.flatten() {
            let _ = roots.add(cert);
        }
    }
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("rustls client protocol versions")
    .with_root_certificates(roots)
    .with_no_client_auth();
    hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .build()
}

/// The outcome of revalidating a stale entry with the origin.
pub enum Revalidated {
    /// `304`: the stored body is still valid; refresh its freshness.
    NotModified,
    /// `200`: a new response to store and serve.
    Modified {
        /// Status (always 200 here).
        status: u16,
        /// Cacheable response headers (hop-by-hop and length headers removed).
        headers: Vec<(String, String)>,
        /// The new response body.
        body: Vec<u8>,
    },
    /// The origin could not be reached, errored, or the body was too large - the
    /// caller should fall back to a normal fetch.
    Failed,
}

/// Send a conditional `GET` to `target` and classify the result.
pub async fn revalidate(
    client: &RevalidationClient,
    target: &Target,
    path_and_query: &str,
    host: &str,
    etag: &str,
    timeout: Option<Duration>,
    max_body: u64,
) -> Revalidated {
    let scheme = if target.tls { "https" } else { "http" };
    let uri = format!("{scheme}://{}{path_and_query}", target.address);
    let request = match http::Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", host)
        .header("if-none-match", etag)
        .body(Empty::<Bytes>::new())
    {
        Ok(request) => request,
        Err(_) => return Revalidated::Failed,
    };

    let response = {
        let fetch = client.request(request);
        let result = match timeout {
            Some(timeout) => match tokio::time::timeout(timeout, fetch).await {
                Ok(result) => result,
                Err(_) => return Revalidated::Failed,
            },
            None => fetch.await,
        };
        match result {
            Ok(response) => response,
            Err(_) => return Revalidated::Failed,
        }
    };

    match response.status().as_u16() {
        304 => Revalidated::NotModified,
        200 => {
            let (parts, body) = response.into_parts();
            let Ok(collected) = body.collect().await else {
                return Revalidated::Failed;
            };
            let bytes = collected.to_bytes();
            if bytes.len() as u64 > max_body {
                return Revalidated::Failed;
            }
            let headers = parts
                .headers
                .iter()
                .filter(|(name, _)| !is_skipped_header(name.as_str()))
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_owned(), value.to_owned()))
                })
                .collect();
            Revalidated::Modified {
                status: 200,
                headers,
                body: bytes.to_vec(),
            }
        }
        _ => Revalidated::Failed,
    }
}

/// A boxed, thread-safe error.
type DynError = Box<dyn std::error::Error + Send + Sync>;

/// A client that sends a buffered request body, used to forward plugin-handled
/// requests to the upstream.
pub type FetchClient = Client<HttpsConnector<HttpConnector>, Full<Bytes>>;

/// Build the buffered-body fetch client (same trust as [`build_client`]).
#[must_use]
pub fn build_fetch_client(upstream_ca: Option<&Path>) -> FetchClient {
    Client::builder(TokioExecutor::new()).build(https_connector(upstream_ca))
}

/// Forward a (buffered) request to `target` and return the full response as
/// `(status, headers, body)`. Hop-by-hop and length headers are dropped.
///
/// # Errors
/// Fails if the request cannot be built or sent, the response times out, or the
/// body exceeds `max_body`.
#[allow(clippy::too_many_arguments)]
pub async fn fetch(
    client: &FetchClient,
    target: &Target,
    method: &str,
    path_and_query: &str,
    host: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
    timeout: Option<Duration>,
    max_body: u64,
) -> Result<(u16, Vec<(String, String)>, Vec<u8>), DynError> {
    let scheme = if target.tls { "https" } else { "http" };
    let uri = format!("{scheme}://{}{path_and_query}", target.address);
    let mut builder = http::Request::builder()
        .method(method)
        .uri(uri)
        .header("host", host);
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case("host") {
            builder = builder.header(name, value);
        }
    }
    let request = builder.body(Full::new(Bytes::from(body)))?;

    let send = client.request(request);
    let response = match timeout {
        Some(timeout) => tokio::time::timeout(timeout, send).await??,
        None => send.await?,
    };
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await?.to_bytes();
    if bytes.len() as u64 > max_body {
        return Err("upstream response too large for a plugin route".into());
    }
    let headers = parts
        .headers
        .iter()
        .filter(|(name, _)| !is_skipped_header(name.as_str()))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    Ok((parts.status.as_u16(), headers, bytes.to_vec()))
}

/// Hop-by-hop and length headers that must not be stored/replayed.
fn is_skipped_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-connection"
            | "transfer-encoding"
            | "upgrade"
            | "content-length"
    )
}
