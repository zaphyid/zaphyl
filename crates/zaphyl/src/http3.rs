//! HTTP/3 (QUIC) reverse proxy - Stages 1-2.
//!
//! Terminates QUIC + TLS 1.3, routes each request through the shared
//! [`Router`], and forwards it to the chosen upstream over HTTP/1.1, relaying
//! the response back over HTTP/3 (streamed). HTTP and HTTPS upstreams are both
//! supported, and the request body is streamed to the upstream as well.

use crate::tls::ReloadCache;
use bytes::{Buf, Bytes};
use flate2::Compression;
use flate2::write::GzEncoder;
use h3_quinn::quinn;
use http_body_util::{BodyExt, StreamBody};
use hyper::body::Frame;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use zaphyl_core::access::AccessControl;
use zaphyl_core::cache::{
    CachedResponse, ResponseCache, if_none_match_satisfied, request_cacheable, response_ttl,
};
use zaphyl_core::router::{Route, Router};

/// A boxed, thread-safe error.
type DynError = Box<dyn std::error::Error + Send + Sync>;

/// Default cap on a request's total (decoded) header section: 64 KiB. Bounds the
/// memory a single request's headers can consume (a header-bomb defense), since
/// h3's own default is effectively unlimited.
const DEFAULT_MAX_HEADER_BYTES: u64 = 64 * 1024;

/// Request body-size limit and upstream timeouts for the HTTP/3 path (mirrors
/// the HTTP/1·2 listener's `[limits]`).
#[derive(Clone, Copy, Default)]
pub struct Limits {
    /// Reject requests whose body exceeds this many bytes with `413`.
    pub max_body_bytes: Option<u64>,
    /// Reject requests whose decoded header section exceeds this many bytes
    /// (defaults to [`DEFAULT_MAX_HEADER_BYTES`] when `None`).
    pub max_header_bytes: Option<u64>,
    /// Timeout for establishing the upstream connection.
    pub connect_timeout: Option<Duration>,
    /// Timeout for the upstream response.
    pub read_timeout: Option<Duration>,
    /// If set, gzip the response when the client accepts it (level capped at 9).
    pub compression_level: Option<u32>,
}

/// Optional response cache shared with the HTTP/1·2 listener.
#[derive(Clone, Default)]
pub struct Caching {
    /// The shared cache, if caching is enabled.
    pub cache: Option<Arc<ResponseCache>>,
    /// Do not cache response bodies larger than this many bytes.
    pub max_body: u64,
    /// Client used to revalidate stale entries with the origin.
    pub reval_client: Option<crate::upstream::RevalidationClient>,
    /// Timeout for a revalidation request.
    pub reval_timeout: Option<Duration>,
}

/// The streaming request body forwarded to the upstream.
type RequestBody = StreamBody<ReceiverStream<Result<Frame<Bytes>, DynError>>>;

/// The upstream client used to forward HTTP/3 requests (HTTP or HTTPS).
type HttpClient = Client<HttpsConnector<HttpConnector>, RequestBody>;

/// Run an HTTP/3 reverse proxy on `listen`, terminating TLS with the cert/key at
/// the given paths and forwarding requests via `router`. Runs until the endpoint
/// is closed.
///
/// # Errors
/// Fails if the certificate/key cannot be loaded or the QUIC endpoint cannot
/// bind to `listen`.
// Each parameter is a distinct, meaningful piece of the listener's config.
#[allow(clippy::too_many_arguments)]
pub async fn serve(
    listen: SocketAddr,
    cert_path: &Path,
    key_path: &Path,
    router: Arc<Router>,
    upstream_ca: Option<std::path::PathBuf>,
    limits: Limits,
    access: Arc<AccessControl>,
    caching: Caching,
    plugins: Option<Arc<crate::plugins::Plugins>>,
) -> Result<(), DynError> {
    // Serve the certificate dynamically so a renewed cert is picked up without a
    // restart, mirroring the HTTP/1·2 listener's `tls::DynamicCert`.
    let resolver = Arc::new(DynamicCertResolver::new(
        cert_path.to_path_buf(),
        key_path.to_path_buf(),
    ));
    if resolver.current().is_none() {
        return Err(format!(
            "failed to load HTTP/3 certificate from {}",
            cert_path.display()
        )
        .into());
    }

    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_cert_resolver(resolver);
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // Enable QUIC 0-RTT: clients with a session ticket can send the first request
    // in early data, saving a round trip. Replay safety is enforced per request
    // in `proxy_request` (unsafe methods get 425; safe ones carry `Early-Data`).
    tls.max_early_data_size = u32::MAX;

    let server_config =
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let endpoint = quinn::Endpoint::server(server_config, listen)?;
    let client = build_client(upstream_ca.as_deref(), limits.connect_timeout);
    eprintln!("zaphyl: HTTP/3 listening on {listen}");

    while let Some(incoming) = endpoint.accept().await {
        let router = Arc::clone(&router);
        let client = client.clone();
        let access = Arc::clone(&access);
        let caching = caching.clone();
        let plugins = plugins.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_connection(incoming, router, client, limits, access, caching, plugins).await
            {
                eprintln!("zaphyl: http3 connection error: {e}");
            }
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    incoming: quinn::Incoming,
    router: Arc<Router>,
    client: HttpClient,
    limits: Limits,
    access: Arc<AccessControl>,
    caching: Caching,
    plugins: Option<Arc<crate::plugins::Plugins>>,
) -> Result<(), DynError> {
    // Accept the connection, enabling 0-RTT when the client resumes a session.
    // `handshake_done` flips true once the full TLS handshake completes; until
    // then, requests arrived as (replayable) 0-RTT early data.
    let (connection, handshake_done) = match incoming.accept()?.into_0rtt() {
        Ok((connection, accepted)) => {
            let done = Arc::new(AtomicBool::new(false));
            let flag = Arc::clone(&done);
            tokio::spawn(async move {
                let _ = accepted.await;
                flag.store(true, Ordering::Relaxed);
            });
            (connection, done)
        }
        // 0-RTT not available: a normal full handshake, never early data.
        Err(connecting) => (connecting.await?, Arc::new(AtomicBool::new(true))),
    };
    let client_ip = connection.remote_address().ip();
    // Bound the decoded header section so a single request can't exhaust memory
    // (h3's default is effectively unlimited).
    let max_header_bytes = limits.max_header_bytes.unwrap_or(DEFAULT_MAX_HEADER_BYTES);
    let mut h3_conn = h3::server::builder()
        .max_field_section_size(max_header_bytes)
        .build(h3_quinn::Connection::new(connection))
        .await?;
    while let Some(resolver) = h3_conn.accept().await? {
        let router = Arc::clone(&router);
        let client = client.clone();
        let access = Arc::clone(&access);
        let caching = caching.clone();
        let plugins = plugins.clone();
        let handshake_done = Arc::clone(&handshake_done);
        tokio::spawn(async move {
            if let Err(e) = proxy_request(
                resolver,
                router,
                client,
                limits,
                access,
                client_ip,
                caching,
                plugins,
                handshake_done,
            )
            .await
            {
                eprintln!("zaphyl: http3 request error: {e}");
            }
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn proxy_request(
    resolver: h3::server::RequestResolver<h3_quinn::Connection, Bytes>,
    router: Arc<Router>,
    client: HttpClient,
    limits: Limits,
    access: Arc<AccessControl>,
    client_ip: std::net::IpAddr,
    caching: Caching,
    plugins: Option<Arc<crate::plugins::Plugins>>,
    handshake_done: Arc<AtomicBool>,
) -> Result<(), DynError> {
    let (request, stream) = resolver.resolve_request().await?;

    // A request seen before the handshake completes arrived as 0-RTT early data,
    // which an attacker could replay.
    let is_early = !handshake_done.load(Ordering::Relaxed);

    // Deny by client IP before doing any routing or forwarding.
    if !access.is_empty() && !access.allows(client_ip) {
        let mut stream = stream;
        let response = http::Response::builder().status(403).body(()).unwrap();
        stream.send_response(response).await?;
        stream.finish().await?;
        return Ok(());
    }

    let path = request.uri().path().to_owned();
    let host = request.uri().host().map(str::to_owned);
    let method = request.method().clone();

    // Replay safety for 0-RTT: an early-data request with an unsafe (non-
    // idempotent) method could cause a side effect if replayed, so reject it
    // with 425; a conformant client retries it after the handshake (RFC 8470).
    if is_early && !is_safe_method(&method) {
        let mut stream = stream;
        let response = http::Response::builder().status(425).body(()).unwrap();
        stream.send_response(response).await?;
        stream.finish().await?;
        return Ok(());
    }

    let route = router.match_route(host.as_deref(), &path);

    // Serve static files for routes backed by a directory.
    if let Some(matched) = route
        && let Some(static_dir) = matched.static_dir()
    {
        let relative = matched.rewrite_path(&path).unwrap_or_else(|| path.clone());
        let mut stream = stream;
        let file = static_dir
            .resolve(&relative)
            .and_then(|file| std::fs::read(&file).ok().map(|body| (file, body)));
        let response = match &file {
            Some((file, body)) => {
                let mime = mime_guess::from_path(file)
                    .first_or_octet_stream()
                    .to_string();
                http::Response::builder()
                    .status(200)
                    .header("content-type", mime)
                    .header("content-length", body.len())
                    .body(())
                    .unwrap()
            }
            None => http::Response::builder().status(404).body(()).unwrap(),
        };
        stream.send_response(response).await?;
        if let Some((_, body)) = file {
            stream.send_data(Bytes::from(body)).await?;
        }
        stream.finish().await?;
        return Ok(());
    }

    // Routes with a WASM plugin chain take the buffered plugin path: read the
    // request body (bounded), run the chain (which may short-circuit), forward to
    // the upstream, run the response plugins, and write the result. A plugin owns
    // request rewriting, so strip_prefix is not auto-applied here.
    if let Some(plugins) = plugins.as_deref()
        && let Some(matched) = route
        && let Some(chain) = plugins.chain(matched.id())
    {
        let declared = request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        // A declared length above the cap can't be buffered; fall through to the
        // streaming proxy below.
        if declared.is_none_or(|len| len <= plugins.max_body()) {
            let chain = chain.clone();
            let req_headers = matched.request_headers().to_vec();
            let resp_headers = matched.response_headers().to_vec();
            let target = matched.next_target().cloned();
            let host_value = host.clone().unwrap_or_default();
            let path_and_query = request
                .uri()
                .path_and_query()
                .map_or("/", |p| p.as_str())
                .to_owned();
            let mut headers: Vec<(String, String)> = request
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|v| (name.as_str().to_owned(), v.to_owned()))
                })
                .collect();
            for (name, value) in &req_headers {
                headers.push((name.clone(), value.clone()));
            }
            if is_early {
                headers.push(("early-data".to_owned(), "1".to_owned()));
            }

            let mut stream = stream;
            let Some(target) = target else {
                let response = http::Response::builder().status(404).body(()).unwrap();
                stream.send_response(response).await?;
                stream.finish().await?;
                return Ok(());
            };

            // Buffer the request body, bounded by the plugin body cap.
            let (mut send, mut recv) = stream.split();
            let mut body = Vec::new();
            let mut too_large = false;
            while let Ok(Some(mut chunk)) = recv.recv_data().await {
                let bytes = chunk.copy_to_bytes(chunk.remaining());
                if body.len() as u64 + bytes.len() as u64 > plugins.max_body() {
                    too_large = true;
                    break;
                }
                body.extend_from_slice(&bytes);
            }
            if too_large {
                let response = http::Response::builder().status(413).body(()).unwrap();
                send.send_response(response).await?;
                send.finish().await?;
                return Ok(());
            }

            let plugin_request = zaphyl_plugin::Request {
                method: method.as_str().to_owned(),
                path: path_and_query,
                headers,
                body,
                client_ip: client_ip.to_string(),
            };
            let response = match plugins
                .run(&chain, plugin_request, &host_value, &target)
                .await
            {
                Ok(response) => response,
                Err(e) => {
                    eprintln!("zaphyl: plugin error: {e}");
                    let response = http::Response::builder().status(502).body(()).unwrap();
                    send.send_response(response).await?;
                    send.finish().await?;
                    return Ok(());
                }
            };

            // Plugin-supplied status and headers are untrusted: build the head
            // defensively so a bad value can't panic the request.
            let head = response_head(
                response.status,
                response
                    .headers
                    .iter()
                    .chain(resp_headers.iter())
                    .map(|(name, value)| (name.as_str(), value.as_str())),
                Some(response.body.len()),
            );
            send.send_response(head).await?;
            if !response.body.is_empty() {
                send.send_data(Bytes::from(response.body)).await?;
            }
            send.finish().await?;
            return Ok(());
        }
    }

    // Serve from cache (revalidating a stale entry), or remember the key to store
    // the response on the way back. `to_serve` is the cached body to return.
    let now = std::time::SystemTime::now();
    let (to_serve, cache_key) = if let Some(cache) = &caching.cache {
        let cc = request
            .headers()
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok());
        let has_auth = request.headers().contains_key(http::header::AUTHORIZATION);
        if request_cacheable(method.as_str(), cc, has_auth) {
            let host_key = host.as_deref().unwrap_or("");
            let pq = request.uri().path_and_query().map_or("/", |p| p.as_str());
            let accept_encoding = request
                .headers()
                .get(http::header::ACCEPT_ENCODING)
                .and_then(|value| value.to_str().ok());
            let key = ResponseCache::key(host_key, pq, accept_encoding);
            match cache.lookup(&key, now) {
                zaphyl_core::cache::Lookup::Fresh(hit) => (Some(hit), None),
                zaphyl_core::cache::Lookup::Stale(hit) => {
                    let etag = hit.etag().map(str::to_owned);
                    let target = route.and_then(Route::next_target).cloned();
                    match (etag, target, caching.reval_client.as_ref()) {
                        (Some(etag), Some(target), Some(client)) => {
                            match crate::upstream::revalidate(
                                client,
                                &target,
                                pq,
                                host_key,
                                &etag,
                                caching.reval_timeout,
                                caching.max_body,
                            )
                            .await
                            {
                                crate::upstream::Revalidated::NotModified => {
                                    let ttl = stored_ttl(&hit).unwrap_or(Duration::from_secs(60));
                                    cache.put(key.clone(), now + ttl, hit.clone());
                                    (Some(hit), None)
                                }
                                crate::upstream::Revalidated::Modified {
                                    status,
                                    headers,
                                    body,
                                } => {
                                    let fresh = CachedResponse {
                                        status,
                                        headers,
                                        body,
                                    };
                                    if let Some(ttl) = stored_ttl(&fresh) {
                                        cache.put(key.clone(), now + ttl, fresh.clone());
                                    }
                                    (Some(fresh), None)
                                }
                                crate::upstream::Revalidated::Failed => (None, Some(key)),
                            }
                        }
                        _ => (None, Some(key)),
                    }
                }
                zaphyl_core::cache::Lookup::Miss => (None, Some(key)),
            }
        } else {
            (None, None)
        }
    } else {
        (None, None)
    };

    if let Some(hit) = to_serve {
        let mut stream = stream;
        let etag = hit.etag().map(str::to_owned);
        let inm = request
            .headers()
            .get(http::header::IF_NONE_MATCH)
            .and_then(|value| value.to_str().ok());
        if let (Some(inm), Some(etag)) = (inm, etag.as_deref())
            && if_none_match_satisfied(inm, etag)
        {
            let response = response_head(304, [("etag", etag), ("x-cache", "HIT")], None);
            stream.send_response(response).await?;
            stream.finish().await?;
            return Ok(());
        }
        // Stored headers are treated as untrusted (a cache file may be corrupt).
        let head = response_head(
            hit.status,
            hit.headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str()))
                .chain(std::iter::once(("x-cache", "HIT"))),
            Some(hit.body.len()),
        );
        stream.send_response(head).await?;
        stream.send_data(Bytes::from(hit.body)).await?;
        stream.finish().await?;
        return Ok(());
    }

    let target = match route.and_then(Route::next_target) {
        Some(target) => target.clone(),
        None => {
            let mut stream = stream;
            let response = http::Response::builder().status(404).body(()).unwrap();
            stream.send_response(response).await?;
            stream.finish().await?;
            return Ok(());
        }
    };

    // Apply per-route prefix stripping, preserving the query string.
    let forward_path = route
        .and_then(|route| route.rewrite_path(&path))
        .unwrap_or(path);
    let path_and_query = match request.uri().query() {
        Some(query) => format!("{forward_path}?{query}"),
        None => forward_path,
    };

    // Reject an oversized body early when its length is declared.
    if let Some(max) = limits.max_body_bytes
        && let Some(len) = request
            .headers()
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
        && len > max
    {
        let mut stream = stream;
        let response = http::Response::builder().status(413).body(()).unwrap();
        stream.send_response(response).await?;
        stream.finish().await?;
        return Ok(());
    }

    // Split the bidirectional stream: the request body streams to the upstream
    // on one half while we send the response back on the other.
    let (mut send, mut recv) = stream.split();
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, DynError>>(4);
    let max_body = limits.max_body_bytes;
    tokio::spawn(async move {
        let mut seen: u64 = 0;
        while let Ok(Some(mut chunk)) = recv.recv_data().await {
            let bytes = chunk.copy_to_bytes(chunk.remaining());
            if let Some(max) = max_body {
                seen += bytes.len() as u64;
                if seen > max {
                    // Stop forwarding; bounds an undeclared (chunked) upload.
                    break;
                }
            }
            if tx.send(Ok(Frame::data(bytes))).await.is_err() {
                break;
            }
        }
    });

    // Forward to the upstream, HTTP or HTTPS per the route.
    let scheme = if target.tls { "https" } else { "http" };
    let uri = format!("{scheme}://{}{path_and_query}", target.address);
    let mut builder = http::Request::builder().method(method).uri(uri);
    for (name, value) in request.headers() {
        if name.as_str() != "host" {
            builder = builder.header(name, value);
        }
    }
    if let Some(route) = route {
        for (name, value) in route.request_headers() {
            builder = builder.header(name, value);
        }
    }
    // Tell the origin this was 0-RTT early data (it may answer 425 per RFC 8470).
    if is_early {
        builder = builder.header("early-data", "1");
    }
    let upstream_request = builder.body(StreamBody::new(ReceiverStream::new(rx)))?;
    let upstream_response = match limits.read_timeout {
        Some(timeout) => {
            match tokio::time::timeout(timeout, client.request(upstream_request)).await {
                Ok(result) => result?,
                Err(_) => {
                    let response = http::Response::builder().status(504).body(()).unwrap();
                    send.send_response(response).await?;
                    send.finish().await?;
                    return Ok(());
                }
            }
        }
        None => client.request(upstream_request).await?,
    };

    // Relay the response back over H3, dropping hop-by-hop headers.
    let (mut parts, mut upstream_body) = upstream_response.into_parts();
    for hop in [
        http::header::CONNECTION,
        http::header::TRANSFER_ENCODING,
        http::header::UPGRADE,
    ] {
        parts.headers.remove(hop);
    }
    if let Some(route) = route {
        for (name, value) in route.response_headers() {
            if let (Ok(name), Ok(value)) = (
                name.parse::<http::header::HeaderName>(),
                value.parse::<http::header::HeaderValue>(),
            ) {
                parts.headers.insert(name, value);
            }
        }
    }

    // Capture cache metadata from the upstream response before any local
    // re-encoding, so the cached body is the (uncompressed) upstream body.
    let cache_store = if let Some(key) = &cache_key {
        let cc = parts
            .headers
            .get(http::header::CACHE_CONTROL)
            .and_then(|value| value.to_str().ok());
        let has_set_cookie = parts.headers.contains_key(http::header::SET_COOKIE);
        let vary = parts
            .headers
            .get(http::header::VARY)
            .and_then(|value| value.to_str().ok());
        let status = parts.status.as_u16();
        response_ttl(status, cc, has_set_cookie, vary).map(|ttl| {
            let headers: Vec<(String, String)> = parts
                .headers
                .iter()
                .filter(|(name, _)| !is_uncacheable_header(name.as_str()))
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|v| (name.as_str().to_owned(), v.to_owned()))
                })
                .collect();
            (key.clone(), ttl, status, headers)
        })
    } else {
        None
    };
    let caching_active = cache_store.is_some();
    let mut cache_buf: Vec<u8> = Vec::new();
    let mut cache_overflow = false;

    // Compress the response when enabled and the client accepts a coding we
    // support (preferring br > zstd > gzip), and the upstream hasn't already
    // encoded it.
    let encoding = if limits.compression_level.is_some()
        && !parts.headers.contains_key(http::header::CONTENT_ENCODING)
    {
        negotiate_encoding(request.headers())
    } else {
        None
    };
    if let Some(encoding) = encoding {
        parts.headers.insert(
            http::header::CONTENT_ENCODING,
            http::header::HeaderValue::from_static(encoding.header_value()),
        );
        // The encoded length differs and is streamed, so drop Content-Length.
        parts.headers.remove(http::header::CONTENT_LENGTH);
    }

    send.send_response(http::Response::from_parts(parts, ()))
        .await?;

    if let Some(encoding) = encoding {
        let mut encoder = BodyEncoder::new(encoding, limits.compression_level.unwrap_or(6))?;
        while let Some(frame) = upstream_body.frame().await {
            if let Ok(data) = frame?.into_data() {
                accumulate_cache_body(
                    caching_active,
                    &mut cache_buf,
                    &mut cache_overflow,
                    &data,
                    caching.max_body,
                );
                let chunk = encoder.push(&data)?;
                if !chunk.is_empty() {
                    send.send_data(Bytes::from(chunk)).await?;
                }
            }
        }
        let tail = encoder.finish()?;
        if !tail.is_empty() {
            send.send_data(Bytes::from(tail)).await?;
        }
    } else {
        while let Some(frame) = upstream_body.frame().await {
            if let Ok(data) = frame?.into_data() {
                accumulate_cache_body(
                    caching_active,
                    &mut cache_buf,
                    &mut cache_overflow,
                    &data,
                    caching.max_body,
                );
                send.send_data(data).await?;
            }
        }
    }
    send.finish().await?;

    // Store the response if it was cacheable and within the size limit.
    if let (Some(cache), Some((key, ttl, status, headers))) = (&caching.cache, cache_store)
        && !cache_overflow
    {
        cache.put(
            key,
            std::time::SystemTime::now() + ttl,
            CachedResponse {
                status,
                headers,
                body: cache_buf,
            },
        );
    }
    Ok(())
}

/// The freshness lifetime of a stored response, from its own `Cache-Control`
/// (and `Vary`), used to refresh an entry after revalidation.
fn stored_ttl(response: &CachedResponse) -> Option<Duration> {
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    response_ttl(200, header("cache-control"), false, header("vary"))
}

/// Headers not stored in the cache (hop-by-hop or framing headers).
fn is_uncacheable_header(name: &str) -> bool {
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

/// Accumulate a response body chunk for caching, bounding it to `max` bytes.
fn accumulate_cache_body(
    active: bool,
    buf: &mut Vec<u8>,
    overflow: &mut bool,
    data: &[u8],
    max: u64,
) {
    if active && !*overflow {
        if buf.len() + data.len() > max as usize {
            *overflow = true;
            buf.clear();
        } else {
            buf.extend_from_slice(data);
        }
    }
}

/// Build an HTTP/3 response head from a status and header pairs that may have
/// originated from a plugin or the on-disk cache. An out-of-range status falls
/// back to `502`, and any header whose name or value fails to parse is dropped,
/// so untrusted values can never make response construction panic.
fn response_head<'a>(
    status: u16,
    headers: impl IntoIterator<Item = (&'a str, &'a str)>,
    content_length: Option<usize>,
) -> http::Response<()> {
    let mut response = http::Response::new(());
    *response.status_mut() =
        http::StatusCode::from_u16(status).unwrap_or(http::StatusCode::BAD_GATEWAY);
    let map = response.headers_mut();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_str(value),
        ) {
            map.append(name, value);
        }
    }
    if let Some(length) = content_length
        && let Ok(value) = http::HeaderValue::from_str(&length.to_string())
    {
        map.insert(http::header::CONTENT_LENGTH, value);
    }
    response
}

/// Whether `method` is safe to process as 0-RTT early data - i.e. replaying it
/// has no side effect. Only safe methods (per RFC 7231) qualify; idempotent-but-
/// unsafe methods like `PUT`/`DELETE` do not, since a replay still mutates state.
fn is_safe_method(method: &http::Method) -> bool {
    matches!(
        *method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS | http::Method::TRACE
    )
}

/// A content-coding negotiated for the HTTP/3 response body.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Encoding {
    Brotli,
    Zstd,
    Gzip,
}

impl Encoding {
    /// The `Content-Encoding` token for this coding.
    fn header_value(self) -> &'static str {
        match self {
            Encoding::Brotli => "br",
            Encoding::Zstd => "zstd",
            Encoding::Gzip => "gzip",
        }
    }
}

/// Pick the best coding the client accepts, in server preference order
/// (br > zstd > gzip). `None` if the client accepts none of them.
fn negotiate_encoding(headers: &http::HeaderMap) -> Option<Encoding> {
    let header = headers
        .get(http::header::ACCEPT_ENCODING)
        .and_then(|value| value.to_str().ok())?;
    for (token, encoding) in [
        ("br", Encoding::Brotli),
        ("zstd", Encoding::Zstd),
        ("gzip", Encoding::Gzip),
    ] {
        if accepts_coding(header, token) {
            return Some(encoding);
        }
    }
    None
}

/// Whether an `Accept-Encoding` header accepts `coding` (listed with a non-zero
/// quality). A `;q=0` on the coding means explicitly not acceptable.
fn accepts_coding(header: &str, coding: &str) -> bool {
    header.split(',').any(|part| {
        let mut fields = part.trim().split(';');
        let name = fields.next().unwrap_or("").trim();
        if !name.eq_ignore_ascii_case(coding) {
            return false;
        }
        // Reject `q=0` (and `q=0.0`, `q=0.000`); any other quality is acceptable.
        !fields.any(|field| {
            let q = field.trim();
            q.strip_prefix("q=")
                .or_else(|| q.strip_prefix("Q="))
                .is_some_and(|value| value.parse::<f32>().is_ok_and(|q| q == 0.0))
        })
    })
}

/// A streaming compressor over an in-memory buffer. Each [`Self::push`] returns
/// the bytes produced so far; [`Self::finish`] returns the trailing bytes.
enum BodyEncoder {
    Gzip(GzEncoder<Vec<u8>>),
    Brotli(Box<brotli::CompressorWriter<Vec<u8>>>),
    Zstd(zstd::stream::write::Encoder<'static, Vec<u8>>),
}

impl BodyEncoder {
    /// Build an encoder for `encoding`. `level` is the configured gzip-style
    /// level (0-9); it is mapped into each codec's own range.
    fn new(encoding: Encoding, level: u32) -> std::io::Result<Self> {
        Ok(match encoding {
            Encoding::Gzip => {
                BodyEncoder::Gzip(GzEncoder::new(Vec::new(), Compression::new(level.min(9))))
            }
            // Brotli quality is 0-11, window 22 (the standard default).
            Encoding::Brotli => BodyEncoder::Brotli(Box::new(brotli::CompressorWriter::new(
                Vec::new(),
                4096,
                level.min(11),
                22,
            ))),
            // zstd level is 1-22; keep the configured number within range.
            Encoding::Zstd => BodyEncoder::Zstd(zstd::stream::write::Encoder::new(
                Vec::new(),
                level.clamp(1, 21) as i32,
            )?),
        })
    }

    /// Compress `data` and return whatever encoded bytes are ready (may be empty).
    fn push(&mut self, data: &[u8]) -> std::io::Result<Vec<u8>> {
        match self {
            BodyEncoder::Gzip(encoder) => {
                encoder.write_all(data)?;
                encoder.flush()?;
                Ok(std::mem::take(encoder.get_mut()))
            }
            BodyEncoder::Brotli(encoder) => {
                encoder.write_all(data)?;
                encoder.flush()?;
                Ok(std::mem::take(encoder.get_mut()))
            }
            BodyEncoder::Zstd(encoder) => {
                encoder.write_all(data)?;
                encoder.flush()?;
                Ok(std::mem::take(encoder.get_mut()))
            }
        }
    }

    /// Finalize the stream and return the trailing bytes.
    fn finish(self) -> std::io::Result<Vec<u8>> {
        match self {
            BodyEncoder::Gzip(encoder) => encoder.finish(),
            // `into_inner` performs the terminating brotli FINISH op.
            BodyEncoder::Brotli(encoder) => Ok(encoder.into_inner()),
            BodyEncoder::Zstd(encoder) => encoder.finish(),
        }
    }
}

/// Build the upstream client. Trusts the bundled Mozilla roots plus an optional
/// extra CA (used by tests, and for private upstream CAs).
fn build_client(upstream_ca: Option<&Path>, connect_timeout: Option<Duration>) -> HttpClient {
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
    // Build the HTTP connector ourselves so we can set the connect timeout.
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_connect_timeout(connect_timeout);
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(http);
    Client::builder(TokioExecutor::new()).build(https)
}

/// Resolves the QUIC listener's certificate per handshake, reloading it from
/// disk when the cert file changes (the rustls counterpart to
/// [`crate::tls::DynamicCert`]).
#[derive(Debug)]
struct DynamicCertResolver {
    cert_path: PathBuf,
    key_path: PathBuf,
    cache: ReloadCache<CertifiedKey>,
}

impl DynamicCertResolver {
    fn new(cert_path: PathBuf, key_path: PathBuf) -> Self {
        Self {
            cache: ReloadCache::new(cert_path.clone()),
            cert_path,
            key_path,
        }
    }

    /// The current certificate, reloaded from disk if the cert file changed.
    fn current(&self) -> Option<Arc<CertifiedKey>> {
        let cert_path = &self.cert_path;
        let key_path = &self.key_path;
        self.cache.get(|| {
            let certs = load_certs(cert_path).ok()?;
            let key = load_key(key_path).ok()?;
            let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).ok()?;
            Some(CertifiedKey::new(certs, signing_key))
        })
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        self.current()
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, DynError> {
    let certs = CertificateDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?;
    Ok(certs)
}

fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, DynError> {
    Ok(PrivateKeyDer::from_pem_file(path)?)
}

#[cfg(test)]
mod tests {
    use super::{quinn, serve};
    use bytes::Buf;
    use rustls::pki_types::CertificateDer;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;
    use zaphyl_core::router::{Route, Router, Target};

    fn spawn_upstream(body: &'static str) -> SocketAddr {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        std::thread::spawn(move || {
            for request in server.incoming_requests() {
                let _ = request.respond(tiny_http::Response::from_string(body));
            }
        });
        addr
    }

    /// Drive a single HTTP/3 GET, trusting only `ca`. Fallible so callers can
    /// distinguish a served-and-trusted cert from a rejected handshake.
    async fn h3_try(
        addr: SocketAddr,
        ca: CertificateDer<'static>,
    ) -> Result<(u16, String), super::DynError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca)?;
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];

        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
        ));
        endpoint.set_default_client_config(client_config);

        let connection = endpoint.connect(addr, "localhost")?.await?;
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let request = http::Request::builder()
            .uri("https://localhost/")
            .body(())?;
        let mut stream = send_request.send_request(request).await?;
        stream.finish().await?;
        let response = stream.recv_response().await?;
        let status = response.status().as_u16();

        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }

        drop(send_request);
        endpoint.wait_idle().await;
        let _ = drive.await;
        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    }

    /// Drive a single HTTP/3 GET, panicking on any error.
    async fn h3_get(addr: SocketAddr, ca: CertificateDer<'static>) -> (u16, String) {
        h3_try(addr, ca).await.expect("http/3 request failed")
    }

    /// Whether a full HTTP/3 GET succeeds with a 200 when trusting only `ca`.
    async fn h3_succeeds(addr: SocketAddr, ca: CertificateDer<'static>) -> bool {
        matches!(h3_try(addr, ca).await, Ok((200, _)))
    }

    #[test]
    fn proxies_over_http3() {
        let upstream = spawn_upstream("from upstream h3");
        let router = Arc::new(Router::new(vec![Route::new(
            None,
            None,
            vec![Target::new(upstream.to_string(), false, String::new())],
        )]));

        let dir = std::env::temp_dir().join("zaphyl-h3-test");
        std::fs::create_dir_all(&dir).unwrap();
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let ca = key.cert.der().clone();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, key.cert.pem()).unwrap();
        std::fs::write(&key_path, key.signing_key.serialize_pem()).unwrap();

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    super::Limits::default(),
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let (status, body) = h3_get(addr, ca).await;
            assert_eq!(status, 200);
            assert_eq!(body, "from upstream h3");
        });
    }

    #[test]
    fn reloads_http3_certificate_without_restart() {
        fn regen(cert: &std::path::Path, key: &std::path::Path) -> CertificateDer<'static> {
            let ck = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
            let der = ck.cert.der().clone();
            std::fs::write(cert, ck.cert.pem()).unwrap();
            std::fs::write(key, ck.signing_key.serialize_pem()).unwrap();
            der
        }

        let upstream = spawn_upstream("h3 reload");
        let router = Arc::new(Router::new(vec![Route::new(
            None,
            None,
            vec![Target::new(upstream.to_string(), false, String::new())],
        )]));

        let dir = std::env::temp_dir().join("zaphyl-h3-reload");
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        let ca_a = regen(&cert_path, &key_path);

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);

        let serve_cert = cert_path.clone();
        let serve_key = key_path.clone();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &serve_cert,
                    &serve_key,
                    router,
                    None,
                    super::Limits::default(),
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            // Certificate A is served and trusted by CA A.
            assert!(
                h3_succeeds(addr, ca_a.clone()).await,
                "certificate A should be served"
            );

            // Rotate to a brand-new certificate B (sleep so the mtime differs).
            tokio::time::sleep(Duration::from_millis(1100)).await;
            let ca_b = regen(&cert_path, &key_path);

            // The new certificate is served without restarting the endpoint.
            assert!(
                h3_succeeds(addr, ca_b).await,
                "rotated certificate B should now be served"
            );
            assert!(
                !h3_succeeds(addr, ca_a).await,
                "old certificate A should no longer be served"
            );
        });
    }

    /// A minimal HTTPS/1.1 upstream that replies with a fixed body.
    async fn spawn_tls_upstream(
        certs: Vec<rustls::pki_types::CertificateDer<'static>>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
        body: &'static str,
    ) -> SocketAddr {
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    if let Ok(mut stream) = acceptor.accept(tcp).await {
                        let mut buf = [0u8; 1024];
                        let _ = stream.read(&mut buf).await;
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    }
                });
            }
        });
        addr
    }

    #[test]
    fn proxies_to_tls_upstream_over_http3() {
        let dir = std::env::temp_dir().join("zaphyl-h3-tls");
        std::fs::create_dir_all(&dir).unwrap();

        let proxy = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let proxy_ca = proxy.cert.der().clone();
        let proxy_cert = dir.join("proxy-cert.pem");
        let proxy_key = dir.join("proxy-key.pem");
        std::fs::write(&proxy_cert, proxy.cert.pem()).unwrap();
        std::fs::write(&proxy_key, proxy.signing_key.serialize_pem()).unwrap();

        let up = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let up_cert = dir.join("up-cert.pem");
        let up_key = dir.join("up-key.pem");
        std::fs::write(&up_cert, up.cert.pem()).unwrap();
        std::fs::write(&up_key, up.signing_key.serialize_pem()).unwrap();

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let up_certs = super::load_certs(&up_cert).unwrap();
            let up_keypair = super::load_key(&up_key).unwrap();
            let upstream = spawn_tls_upstream(up_certs, up_keypair, "secure upstream").await;

            let router = Arc::new(Router::new(vec![Route::new(
                None,
                None,
                vec![Target::new(
                    format!("localhost:{}", upstream.port()),
                    true,
                    "localhost".to_owned(),
                )],
            )]));
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &proxy_cert,
                    &proxy_key,
                    router,
                    Some(up_cert),
                    super::Limits::default(),
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let (status, body) = h3_get(addr, proxy_ca).await;
            assert_eq!(status, 200);
            assert_eq!(body, "secure upstream");
        });
    }

    /// Drive an HTTP/3 POST with `body` (declaring Content-Length) and return the
    /// response status. Body-send errors are ignored: the server may reset the
    /// send side after rejecting the request.
    async fn h3_post(addr: SocketAddr, ca: CertificateDer<'static>, body: Vec<u8>) -> u16 {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];

        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        )));
        let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/")
            .header("content-length", body.len())
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(request).await.unwrap();
        let _ = stream.send_data(bytes::Bytes::from(body)).await;
        let _ = stream.finish().await;
        let response = stream.recv_response().await.unwrap();
        let status = response.status().as_u16();

        drop(send_request);
        endpoint.wait_idle().await;
        let _ = drive.await;
        status
    }

    /// An upstream that echoes the request headers it received into the body.
    fn spawn_header_echo_upstream() -> SocketAddr {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        std::thread::spawn(move || {
            for request in server.incoming_requests() {
                let dump = request
                    .headers()
                    .iter()
                    .map(|h| format!("{}: {}", h.field, h.value))
                    .collect::<Vec<_>>()
                    .join("\n");
                let _ = request.respond(tiny_http::Response::from_string(dump));
            }
        });
        addr
    }

    #[test]
    fn injects_request_headers_over_http3() {
        let upstream = spawn_header_echo_upstream();
        let router = Arc::new(Router::new(vec![
            Route::new(
                None,
                None,
                vec![Target::new(upstream.to_string(), false, String::new())],
            )
            .with_headers(vec![("x-api-key".to_owned(), "secret".to_owned())], vec![]),
        ]));
        let dir = std::env::temp_dir().join("zaphyl-h3-headers");
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, ca) = write_localhost_cert(&dir);
        let addr = free_udp_addr();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    super::Limits::default(),
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let (status, body) = h3_get(addr, ca).await;
            assert_eq!(status, 200);
            assert!(
                body.to_lowercase().contains("x-api-key: secret"),
                "injected request header missing:\n{body}"
            );
        });
    }

    #[test]
    fn denies_blocked_ip_over_http3() {
        let upstream = spawn_upstream("ok");
        let router = Arc::new(Router::new(vec![Route::new(
            None,
            None,
            vec![Target::new(upstream.to_string(), false, String::new())],
        )]));
        let dir = std::env::temp_dir().join("zaphyl-h3-access");
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, ca) = write_localhost_cert(&dir);
        let addr = free_udp_addr();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let access = std::sync::Arc::new(
                zaphyl_core::access::AccessControl::parse(&[], &["127.0.0.1".to_owned()]).unwrap(),
            );
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    super::Limits::default(),
                    access,
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let (status, _) = h3_get(addr, ca).await;
            assert_eq!(status, 403);
        });
    }

    /// An upstream that accepts connections but never replies.
    async fn spawn_silent_upstream() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        addr
    }

    fn write_localhost_cert(
        dir: &std::path::Path,
    ) -> (
        std::path::PathBuf,
        std::path::PathBuf,
        CertificateDer<'static>,
    ) {
        let key = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let ca = key.cert.der().clone();
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, key.cert.pem()).unwrap();
        std::fs::write(&key_path, key.signing_key.serialize_pem()).unwrap();
        (cert_path, key_path, ca)
    }

    fn free_udp_addr() -> SocketAddr {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        drop(socket);
        addr
    }

    #[test]
    fn rejects_oversized_body_over_http3() {
        let upstream = spawn_upstream("ok");
        let router = Arc::new(Router::new(vec![Route::new(
            None,
            None,
            vec![Target::new(upstream.to_string(), false, String::new())],
        )]));
        let dir = std::env::temp_dir().join("zaphyl-h3-bodylimit");
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, ca) = write_localhost_cert(&dir);
        let addr = free_udp_addr();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let limits = super::Limits {
                max_body_bytes: Some(10),
                ..Default::default()
            };
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    limits,
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let status = h3_post(addr, ca, vec![b'x'; 100]).await;
            assert_eq!(status, 413);
        });
    }

    #[test]
    fn upstream_read_timeout_over_http3() {
        let dir = std::env::temp_dir().join("zaphyl-h3-timeout");
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, ca) = write_localhost_cert(&dir);
        let addr = free_udp_addr();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let upstream = spawn_silent_upstream().await;
            let router = Arc::new(Router::new(vec![Route::new(
                None,
                None,
                vec![Target::new(upstream.to_string(), false, String::new())],
            )]));
            let limits = super::Limits {
                read_timeout: Some(Duration::from_secs(1)),
                ..Default::default()
            };
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    limits,
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let (status, _) = h3_get(addr, ca).await;
            assert_eq!(status, 504);
        });
    }

    /// An upstream that replies with `unit` repeated `times` (compressible body).
    fn spawn_repeated_upstream(unit: &'static str, times: usize) -> SocketAddr {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        std::thread::spawn(move || {
            let body = unit.repeat(times);
            for request in server.incoming_requests() {
                let _ = request.respond(tiny_http::Response::from_string(body.clone()));
            }
        });
        addr
    }

    /// HTTP/3 GET sending the given `Accept-Encoding`; returns the
    /// Content-Encoding header (if any) and the raw response body.
    async fn h3_get_encoded(
        addr: SocketAddr,
        ca: CertificateDer<'static>,
        accept_encoding: &'static str,
    ) -> (Option<String>, Vec<u8>) {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];

        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        )));
        let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        let request = http::Request::builder()
            .uri("https://localhost/")
            .header("accept-encoding", accept_encoding)
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(request).await.unwrap();
        stream.finish().await.unwrap();
        let response = stream.recv_response().await.unwrap();
        let encoding = response
            .headers()
            .get("content-encoding")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.unwrap() {
            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
        }

        drop(send_request);
        endpoint.wait_idle().await;
        let _ = drive.await;
        (encoding, body)
    }

    #[test]
    fn serves_static_files_over_http3() {
        let www = std::env::temp_dir().join("zaphyl-h3-www");
        std::fs::create_dir_all(&www).unwrap();
        std::fs::write(www.join("index.html"), "<h1>h3 home</h1>").unwrap();
        let router = Arc::new(Router::new(vec![
            Route::new(None, Some("/".to_owned()), vec![])
                .with_static(zaphyl_core::static_files::StaticDir::new(&www)),
        ]));
        let dir = std::env::temp_dir().join("zaphyl-h3-static");
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, ca) = write_localhost_cert(&dir);
        let addr = free_udp_addr();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    super::Limits::default(),
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let (status, body) = h3_get(addr, ca).await;
            assert_eq!(status, 200);
            assert_eq!(body, "<h1>h3 home</h1>");
        });
    }

    #[test]
    fn compresses_response_over_http3() {
        use std::io::Read;

        let original = "zaphyl ".repeat(500);
        let upstream = spawn_repeated_upstream("zaphyl ", 500);
        let router = Arc::new(Router::new(vec![Route::new(
            None,
            None,
            vec![Target::new(upstream.to_string(), false, String::new())],
        )]));
        let dir = std::env::temp_dir().join("zaphyl-h3-gzip");
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, ca) = write_localhost_cert(&dir);
        let addr = free_udp_addr();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let limits = super::Limits {
                compression_level: Some(6),
                ..Default::default()
            };
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    limits,
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let (encoding, body) = h3_get_encoded(addr, ca, "gzip").await;
            assert_eq!(encoding.as_deref(), Some("gzip"));
            assert!(
                body.len() < original.len(),
                "compressed body should be smaller"
            );

            let mut decoded = String::new();
            flate2::read::GzDecoder::new(&body[..])
                .read_to_string(&mut decoded)
                .unwrap();
            assert_eq!(decoded, original);
        });
    }

    #[test]
    fn brotli_compresses_response_over_http3() {
        use std::io::Read;

        let original = "zaphyl ".repeat(500);
        let upstream = spawn_repeated_upstream("zaphyl ", 500);
        let router = Arc::new(Router::new(vec![Route::new(
            None,
            None,
            vec![Target::new(upstream.to_string(), false, String::new())],
        )]));
        let dir = std::env::temp_dir().join("zaphyl-h3-brotli");
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, ca) = write_localhost_cert(&dir);
        let addr = free_udp_addr();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let limits = super::Limits {
                compression_level: Some(6),
                ..Default::default()
            };
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    limits,
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            // The client prefers br; the server should pick it over gzip.
            let (encoding, body) = h3_get_encoded(addr, ca, "gzip, br").await;
            assert_eq!(encoding.as_deref(), Some("br"));
            assert!(body.len() < original.len(), "brotli body should be smaller");

            let mut decoded = String::new();
            brotli::Decompressor::new(&body[..], 4096)
                .read_to_string(&mut decoded)
                .unwrap();
            assert_eq!(decoded, original);
        });
    }

    /// A cacheable upstream that numbers each response.
    fn spawn_cacheable_counter() -> SocketAddr {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        std::thread::spawn(move || {
            let mut n = 0;
            for request in server.incoming_requests() {
                n += 1;
                let header = tiny_http::Header::from_bytes("Cache-Control", "max-age=60").unwrap();
                let response =
                    tiny_http::Response::from_string(format!("response {n}")).with_header(header);
                let _ = request.respond(response);
            }
        });
        addr
    }

    /// An upstream that 304s a matching `If-None-Match: "v1"`, else a numbered
    /// body with `ETag: "v1"` and 1-second freshness.
    fn spawn_revalidating_upstream() -> SocketAddr {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let addr = server.server_addr().to_ip().unwrap();
        std::thread::spawn(move || {
            let mut n = 0;
            for request in server.incoming_requests() {
                let inm = request
                    .headers()
                    .iter()
                    .find(|h| {
                        h.field
                            .as_str()
                            .as_str()
                            .eq_ignore_ascii_case("if-none-match")
                    })
                    .map(|h| h.value.as_str().to_owned());
                if inm.as_deref() == Some("\"v1\"") {
                    let _ = request.respond(tiny_http::Response::empty(304));
                } else {
                    n += 1;
                    let response = tiny_http::Response::from_string(format!("response {n}"))
                        .with_header(
                            tiny_http::Header::from_bytes("Cache-Control", "max-age=1").unwrap(),
                        )
                        .with_header(tiny_http::Header::from_bytes("ETag", "\"v1\"").unwrap());
                    let _ = request.respond(response);
                }
            }
        });
        addr
    }

    #[test]
    fn revalidates_stale_entry_over_http3() {
        let upstream = spawn_revalidating_upstream();
        let router = Arc::new(Router::new(vec![Route::new(
            None,
            None,
            vec![Target::new(upstream.to_string(), false, String::new())],
        )]));
        let dir = std::env::temp_dir().join("zaphyl-h3-reval");
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, ca) = write_localhost_cert(&dir);
        let addr = free_udp_addr();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let caching = super::Caching {
                cache: Some(std::sync::Arc::new(zaphyl_core::cache::ResponseCache::new(
                    16,
                ))),
                max_body: 1 << 20,
                reval_client: Some(crate::upstream::build_client(None)),
                reval_timeout: Some(Duration::from_secs(5)),
            };
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    super::Limits::default(),
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    caching,
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let (_, first) = h3_get(addr, ca.clone()).await;
            assert_eq!(first, "response 1");
            // Let it go stale, then revalidate: the origin 304s, so the cached
            // body is served rather than a fresh "response 2".
            tokio::time::sleep(Duration::from_millis(1500)).await;
            let (_, second) = h3_get(addr, ca).await;
            assert_eq!(second, "response 1");
        });
    }

    #[test]
    fn caches_responses_over_http3() {
        let upstream = spawn_cacheable_counter();
        let router = Arc::new(Router::new(vec![Route::new(
            None,
            None,
            vec![Target::new(upstream.to_string(), false, String::new())],
        )]));
        let dir = std::env::temp_dir().join("zaphyl-h3-cache");
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, ca) = write_localhost_cert(&dir);
        let addr = free_udp_addr();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let caching = super::Caching {
                cache: Some(std::sync::Arc::new(zaphyl_core::cache::ResponseCache::new(
                    16,
                ))),
                max_body: 1 << 20,
                reval_client: None,
                reval_timeout: None,
            };
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    super::Limits::default(),
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    caching,
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let (_, first) = h3_get(addr, ca.clone()).await;
            assert_eq!(first, "response 1");
            // The second request is served from cache, not the upstream.
            let (_, second) = h3_get(addr, ca).await;
            assert_eq!(second, "response 1");
        });
    }

    /// Encode a payload in two chunks plus a finish, then decode with the
    /// matching decoder and confirm the round-trip is lossless and shrinks.
    fn round_trip(encoding: super::Encoding) {
        use std::io::Read;
        let original = "zaphyl ".repeat(500);
        let bytes = original.as_bytes();
        let mut encoder = super::BodyEncoder::new(encoding, 6).unwrap();
        let mut out = encoder.push(&bytes[..1000]).unwrap();
        out.extend(encoder.push(&bytes[1000..]).unwrap());
        out.extend(encoder.finish().unwrap());
        assert!(
            out.len() < bytes.len(),
            "{encoding:?} should shrink the body"
        );

        let mut decoded = Vec::new();
        match encoding {
            super::Encoding::Gzip => {
                flate2::read::GzDecoder::new(&out[..])
                    .read_to_end(&mut decoded)
                    .unwrap();
            }
            super::Encoding::Brotli => {
                brotli::Decompressor::new(&out[..], 4096)
                    .read_to_end(&mut decoded)
                    .unwrap();
            }
            super::Encoding::Zstd => {
                zstd::stream::read::Decoder::new(&out[..])
                    .unwrap()
                    .read_to_end(&mut decoded)
                    .unwrap();
            }
        }
        assert_eq!(decoded, bytes, "{encoding:?} round-trip mismatch");
    }

    #[test]
    fn body_encoder_round_trips_gzip() {
        round_trip(super::Encoding::Gzip);
    }

    #[test]
    fn body_encoder_round_trips_brotli() {
        round_trip(super::Encoding::Brotli);
    }

    #[test]
    fn body_encoder_round_trips_zstd() {
        round_trip(super::Encoding::Zstd);
    }

    #[test]
    fn negotiate_prefers_brotli_then_zstd_then_gzip() {
        use super::{Encoding, negotiate_encoding};
        let headers = |value: &str| {
            let mut map = http::HeaderMap::new();
            map.insert(http::header::ACCEPT_ENCODING, value.parse().unwrap());
            map
        };
        assert_eq!(
            negotiate_encoding(&headers("gzip, br, zstd")),
            Some(Encoding::Brotli)
        );
        assert_eq!(
            negotiate_encoding(&headers("gzip, zstd")),
            Some(Encoding::Zstd)
        );
        assert_eq!(negotiate_encoding(&headers("gzip")), Some(Encoding::Gzip));
        assert_eq!(negotiate_encoding(&headers("identity")), None);
        assert_eq!(negotiate_encoding(&http::HeaderMap::new()), None);
        // `q=0` means explicitly not acceptable: fall through to the next coding.
        assert_eq!(
            negotiate_encoding(&headers("br;q=0, gzip")),
            Some(Encoding::Gzip)
        );
    }

    #[test]
    fn response_head_sanitizes_untrusted_values() {
        use super::response_head;
        // An out-of-range status falls back to 502; a header with a control
        // character in its value is dropped; valid ones survive.
        let head = response_head(1000, [("x-ok", "fine"), ("x-bad", "bad\nvalue")], Some(5));
        assert_eq!(head.status().as_u16(), 502);
        assert_eq!(head.headers().get("x-ok").unwrap(), "fine");
        assert!(head.headers().get("x-bad").is_none());
        assert_eq!(head.headers().get("content-length").unwrap(), "5");
        // A valid status and no content-length are preserved as-is.
        let head = response_head(201, std::iter::empty(), None);
        assert_eq!(head.status().as_u16(), 201);
        assert!(head.headers().get("content-length").is_none());
    }

    #[test]
    fn only_safe_methods_are_early_data_eligible() {
        use super::is_safe_method;
        for method in [
            http::Method::GET,
            http::Method::HEAD,
            http::Method::OPTIONS,
            http::Method::TRACE,
        ] {
            assert!(
                is_safe_method(&method),
                "{method} should be early-data safe"
            );
        }
        for method in [
            http::Method::POST,
            http::Method::PUT,
            http::Method::DELETE,
            http::Method::PATCH,
        ] {
            assert!(
                !is_safe_method(&method),
                "{method} must not be early-data safe"
            );
        }
    }

    /// Establish a session, then resume it and send a GET as 0-RTT early data.
    /// Panics if 0-RTT is not offered on resumption (so the test really tests it).
    async fn h3_zero_rtt_get(addr: SocketAddr, ca: CertificateDer<'static>) -> u16 {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca).unwrap();
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.enable_early_data = true;
        let client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap(),
        ));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);

        // First connection: full handshake so the server issues a session ticket.
        let connection = endpoint.connect(addr, "localhost").unwrap().await.unwrap();
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let request = http::Request::builder()
            .uri("https://localhost/")
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(request).await.unwrap();
        stream.finish().await.unwrap();
        let _ = stream.recv_response().await.unwrap();
        while stream.recv_data().await.unwrap().is_some() {}
        drop(send_request);
        connection.close(0u32.into(), b"done");
        let _ = drive.await;
        endpoint.wait_idle().await;

        // Second connection: resume with 0-RTT and send the request as early data.
        let connection = match endpoint.connect(addr, "localhost").unwrap().into_0rtt() {
            Ok((connection, _accepted)) => connection,
            Err(_) => panic!("0-RTT was not offered on resumption"),
        };
        let (mut driver, mut send_request) = h3::client::new(h3_quinn::Connection::new(connection))
            .await
            .unwrap();
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let request = http::Request::builder()
            .uri("https://localhost/")
            .body(())
            .unwrap();
        let mut stream = send_request.send_request(request).await.unwrap();
        stream.finish().await.unwrap();
        let status = stream.recv_response().await.unwrap().status().as_u16();
        while stream.recv_data().await.unwrap().is_some() {}
        drop(send_request);
        endpoint.wait_idle().await;
        let _ = drive.await;
        status
    }

    /// Drive an HTTP/3 GET carrying one extra header, returning the status or an
    /// error (a rejected request errors at the client or stream layer).
    async fn h3_get_with_header(
        addr: SocketAddr,
        ca: CertificateDer<'static>,
        name: &'static str,
        value: String,
    ) -> Result<u16, super::DynError> {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca)?;
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
        endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
        )));
        let connection = endpoint.connect(addr, "localhost")?.await?;
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;
        let drive = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });
        let request = http::Request::builder()
            .uri("https://localhost/")
            .header(name, value)
            .body(())?;
        let mut stream = send_request.send_request(request).await?;
        stream.finish().await?;
        let status = stream.recv_response().await?.status().as_u16();
        drop(send_request);
        endpoint.wait_idle().await;
        let _ = drive.await;
        Ok(status)
    }

    #[test]
    fn rejects_oversized_request_headers_over_http3() {
        let upstream = spawn_upstream("should not be reached");
        let router = Arc::new(Router::new(vec![Route::new(
            None,
            None,
            vec![Target::new(upstream.to_string(), false, String::new())],
        )]));
        let dir = std::env::temp_dir().join("zaphyl-h3-bigheader");
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, ca) = write_localhost_cert(&dir);
        let addr = free_udp_addr();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let limits = super::Limits {
                max_header_bytes: Some(1024),
                ..Default::default()
            };
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    limits,
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            // An 8 KiB header far exceeds the 1 KiB limit, so it must be rejected
            // (and never reach the upstream), not served with a 200.
            let result = h3_get_with_header(addr, ca, "x-big", "x".repeat(8 * 1024)).await;
            assert!(
                !matches!(result, Ok(200)),
                "oversized headers must be rejected, got {result:?}"
            );
        });
    }

    #[test]
    fn zero_rtt_get_is_accepted_over_http3() {
        let upstream = spawn_upstream("0-rtt body");
        let router = Arc::new(Router::new(vec![Route::new(
            None,
            None,
            vec![Target::new(upstream.to_string(), false, String::new())],
        )]));
        let dir = std::env::temp_dir().join("zaphyl-h3-0rtt");
        std::fs::create_dir_all(&dir).unwrap();
        let (cert_path, key_path, ca) = write_localhost_cert(&dir);
        let addr = free_udp_addr();

        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            tokio::spawn(async move {
                let _ = serve(
                    addr,
                    &cert_path,
                    &key_path,
                    router,
                    None,
                    super::Limits::default(),
                    std::sync::Arc::new(zaphyl_core::access::AccessControl::default()),
                    super::Caching::default(),
                    None,
                )
                .await;
            });
            tokio::time::sleep(Duration::from_millis(300)).await;

            let status = h3_zero_rtt_get(addr, ca).await;
            assert_eq!(status, 200, "a resumed 0-RTT GET should be served");
        });
    }
}
