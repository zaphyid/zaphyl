//! Zaphyl server entrypoint: load a config file and run the reverse proxy.

mod acme;
mod cli;
mod http3;
mod http_front;
mod metrics;
mod plugins;
mod tls;
mod upstream;

use async_trait::async_trait;
use pingora::prelude::{
    HttpPeer, ProxyHttp, RequestHeader, ResponseHeader, Result as PResult, Server, Session,
    http_proxy_service,
};
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use zaphyl_config::Config;
use zaphyl_core::access::AccessControl;
use zaphyl_core::acme::ChallengeStore;
use zaphyl_core::cache::{
    CachedResponse, ResponseCache, if_none_match_satisfied, request_cacheable, response_ttl,
};
use zaphyl_core::ratelimit::RateLimiter;
use zaphyl_core::router::{Route, Router, Target};
use zaphyl_core::static_files::StaticDir;

/// Reverse proxy: routes each request to an upstream chosen by host and path.
struct ZaphylProxy {
    router: std::sync::Arc<Router>,
    rate_limiter: Option<RateLimiter>,
    started: std::time::Instant,
    response_headers: Vec<(String, String)>,
    tls_enabled: bool,
    alt_svc: Option<String>,
    max_body_bytes: Option<u64>,
    connect_timeout: Option<std::time::Duration>,
    read_timeout: Option<std::time::Duration>,
    access: Arc<AccessControl>,
    compression_level: Option<u32>,
    cache: Option<Arc<ResponseCache>>,
    cache_max_body: u64,
    revalidation_client: upstream::RevalidationClient,
    plugins: Option<Arc<plugins::Plugins>>,
}

impl ZaphylProxy {
    fn new(
        config: &Config,
        tls_enabled: bool,
        router: std::sync::Arc<Router>,
        access: Arc<AccessControl>,
        cache: Option<Arc<ResponseCache>>,
        plugins: Option<Arc<plugins::Plugins>>,
    ) -> Self {
        let rate_limiter = config
            .rate_limit
            .as_ref()
            .map(|limit| RateLimiter::new(1000, limit.requests_per_second));
        let response_headers = config
            .response_headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone()))
            .collect();
        let alt_svc = config
            .http3
            .as_ref()
            .map(|http3| format!("h3=\":{}\"; ma=86400", http3.listen.port()));
        let limits = config.limits.as_ref();
        let max_body_bytes = limits.and_then(|l| l.max_request_body_bytes);
        let connect_timeout = limits
            .and_then(|l| l.upstream_connect_timeout_seconds)
            .map(std::time::Duration::from_secs);
        let read_timeout = limits
            .and_then(|l| l.upstream_read_timeout_seconds)
            .map(std::time::Duration::from_secs);
        let compression_level = config.compression.as_ref().map(|c| c.level);
        let cache_max_body = config.cache.as_ref().map_or(0, |c| c.max_body_bytes);
        let upstream_ca = std::env::var("ZAPHYL_UPSTREAM_CA").ok().map(PathBuf::from);
        let revalidation_client = upstream::build_client(upstream_ca.as_deref());
        Self {
            router,
            rate_limiter,
            started: std::time::Instant::now(),
            response_headers,
            tls_enabled,
            alt_svc,
            max_body_bytes,
            connect_timeout,
            read_timeout,
            access,
            compression_level,
            cache,
            cache_max_body,
            revalidation_client,
            plugins,
        }
    }

    /// Write a cached response to the client, or a bodyless `304` if the request's
    /// `If-None-Match` matches the entry's ETag. Always returns `Ok(true)`.
    async fn serve_cache_hit(
        &self,
        session: &mut Session,
        hit: CachedResponse,
        if_none_match: Option<&str>,
    ) -> PResult<bool> {
        let etag = hit.etag().map(str::to_owned);
        if let (Some(inm), Some(etag)) = (if_none_match, etag.as_deref())
            && if_none_match_satisfied(inm, etag)
        {
            let mut header = ResponseHeader::build(304u16, None)
                .map_err(|_| pingora::Error::new_str("cache header"))?;
            let _ = header.insert_header("etag", etag);
            let _ = header.insert_header("x-cache", "HIT");
            session
                .write_response_header(Box::new(header), true)
                .await?;
            return Ok(true);
        }
        let mut header = ResponseHeader::build(hit.status, None)
            .map_err(|_| pingora::Error::new_str("cache header"))?;
        for (name, value) in &hit.headers {
            let _ = header.insert_header(name.clone(), value.as_str());
        }
        let _ = header.insert_header("content-length", hit.body.len().to_string());
        let _ = header.insert_header("x-cache", "HIT");
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(bytes::Bytes::from(hit.body)), true)
            .await?;
        Ok(true)
    }

    /// If the matched route serves static files, write the file (or a 404) to the
    /// client and return `true`; otherwise return `false` to continue proxying.
    async fn try_serve_static(&self, session: &mut Session) -> PResult<bool> {
        let req = session.req_header();
        let path = req.uri.path().to_owned();
        let host = req
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(':').next().unwrap_or(value).to_owned());

        let Some(route) = self.router.match_route(host.as_deref(), &path) else {
            return Ok(false);
        };
        let Some(static_dir) = route.static_dir() else {
            return Ok(false);
        };

        // Honor strip_prefix so a route at `/assets` maps into the root.
        let relative = route.rewrite_path(&path).unwrap_or(path);
        let Some(file) = static_dir.resolve(&relative) else {
            session.respond_error(404).await?;
            return Ok(true);
        };
        let Ok(contents) = std::fs::read(&file) else {
            session.respond_error(404).await?;
            return Ok(true);
        };

        let mime = mime_guess::from_path(&file)
            .first_or_octet_stream()
            .to_string();
        let mut header = ResponseHeader::build(200u16, None)
            .map_err(|_| pingora::Error::new_str("failed to build response header"))?;
        let _ = header.insert_header("content-type", mime);
        let _ = header.insert_header("content-length", contents.len().to_string());
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(bytes::Bytes::from(contents)), true)
            .await?;
        Ok(true)
    }

    /// If the matched route has a WASM plugin chain, run it: buffer the request,
    /// run the request plugins (which may short-circuit), forward to the upstream
    /// over a buffered client, run the response plugins, and write the result.
    /// Returns `true` once handled, `false` for routes without plugins (which
    /// keep the streaming proxy path).
    ///
    /// Note: `strip_prefix` is not auto-applied on plugin routes - a plugin owns
    /// request rewriting (it can modify the forwarded path itself).
    async fn try_run_plugins(&self, session: &mut Session) -> PResult<bool> {
        let Some(plugins) = &self.plugins else {
            return Ok(false);
        };

        // Resolve the route to a plugin chain and target while only borrowing the
        // request header, then build the owned plugin request.
        let Some((chain, target, request, host_value, resp_headers, content_length)) = ({
            let req = session.req_header();
            let path = req.uri.path();
            let host_header = req
                .headers
                .get("host")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            let host = host_header
                .as_deref()
                .map(|value| value.split(':').next().unwrap_or(value));
            let route = self.router.match_route(host, path);
            route.and_then(|route| {
                let chain = plugins.chain(route.id())?.clone();
                let target = route.next_target()?.clone();
                let mut headers: Vec<(String, String)> = req
                    .headers
                    .iter()
                    .filter_map(|(name, value)| {
                        value
                            .to_str()
                            .ok()
                            .map(|value| (name.as_str().to_owned(), value.to_owned()))
                    })
                    .collect();
                // The route's configured request headers (a plugin may override).
                for (name, value) in route.request_headers() {
                    headers.push((name.clone(), value.clone()));
                }
                let request = zaphyl_plugin::Request {
                    method: req.method.as_str().to_owned(),
                    path: req
                        .uri
                        .path_and_query()
                        .map_or("/", http::uri::PathAndQuery::as_str)
                        .to_owned(),
                    headers,
                    body: Vec::new(),
                    client_ip: String::new(),
                };
                let content_length = req
                    .headers
                    .get(http::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .and_then(|value| value.parse::<u64>().ok());
                Some((
                    chain,
                    target,
                    request,
                    host_header.unwrap_or_default(),
                    route.response_headers().to_vec(),
                    content_length,
                ))
            })
        }) else {
            return Ok(false);
        };

        // A declared length above the buffer cap can't be handled without
        // partially reading the body, so fall back to the streaming path.
        if content_length.is_some_and(|len| len > plugins.max_body()) {
            return Ok(false);
        }

        let client_ip = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.ip().to_string())
            .unwrap_or_default();

        // Buffer the request body, bounded by the plugin body cap.
        let mut body = Vec::new();
        while let Some(chunk) = session.read_request_body().await? {
            if body.len() as u64 + chunk.len() as u64 > plugins.max_body() {
                session.respond_error(413).await?;
                return Ok(true);
            }
            body.extend_from_slice(&chunk);
        }

        let request = zaphyl_plugin::Request {
            body,
            client_ip,
            ..request
        };
        let response = match plugins.run(&chain, request, &host_value, &target).await {
            Ok(response) => response,
            Err(e) => {
                eprintln!("zaphyl: plugin error: {e}");
                session.respond_error(502).await?;
                return Ok(true);
            }
        };

        let mut header = ResponseHeader::build(response.status, None)
            .map_err(|_| pingora::Error::new_str("plugin response header"))?;
        for (name, value) in &response.headers {
            let _ = header.append_header(name.clone(), value.as_str());
        }
        // The route's configured response headers win over the plugin's.
        for (name, value) in &resp_headers {
            let _ = header.insert_header(name.clone(), value.as_str());
        }
        let _ = header.insert_header("content-length", response.body.len().to_string());
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(bytes::Bytes::from(response.body)), true)
            .await?;
        Ok(true)
    }
}

/// Build the shared router from the configured routes.
fn build_router(config: &Config) -> Router {
    let routes = config
        .routes
        .iter()
        .enumerate()
        .map(|(index, route)| {
            let targets = route
                .upstream
                .iter()
                .map(|address| {
                    let sni = address
                        .rsplit_once(':')
                        .map(|(host, _)| host.to_owned())
                        .unwrap_or_default();
                    Target::new(address.clone(), route.tls, sni).with_h2(route.grpc)
                })
                .collect();
            let mut built = Route::new(route.host.clone(), route.path.clone(), targets)
                .with_id(index)
                .with_strip_prefix(route.strip_prefix)
                .with_headers(
                    header_pairs(&route.request_headers),
                    header_pairs(&route.response_headers),
                );
            if let Some(root) = &route.root {
                built = built.with_static(StaticDir::new(root));
            }
            built
        })
        .collect();
    Router::new(routes)
}

/// Headers that must not be stored and replayed from the cache (hop-by-hop or
/// length/framing headers, which are recomputed when serving).
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

/// The freshness lifetime of a stored response, from its own `Cache-Control`
/// (and `Vary`), used to refresh an entry after revalidation.
fn stored_ttl(response: &CachedResponse) -> Option<std::time::Duration> {
    let header = |name: &str| {
        response
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    };
    response_ttl(200, header("cache-control"), false, header("vary"))
}

/// Turn a header map into owned name/value pairs.
fn header_pairs(headers: &std::collections::HashMap<String, String>) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect()
}

/// Per-request state: log timing, an optional rewritten upstream path, and the
/// running count of request-body bytes seen (for body-size limiting).
struct RequestCtx {
    start: std::time::Instant,
    rewrite_path: Option<String>,
    body_seen: u64,
    req_headers: Vec<(String, String)>,
    resp_headers: Vec<(String, String)>,
    // Response caching: the key to store under (set on a cacheable miss), the
    // TTL and captured status/headers, and the accumulated body.
    cache_key: Option<String>,
    cache_ttl: Option<std::time::Duration>,
    cache_status: u16,
    cache_headers: Vec<(String, String)>,
    cache_body: Vec<u8>,
    cache_overflow: bool,
}

#[async_trait]
impl ProxyHttp for ZaphylProxy {
    type CTX = RequestCtx;

    fn new_ctx(&self) -> Self::CTX {
        RequestCtx {
            start: std::time::Instant::now(),
            rewrite_path: None,
            body_seen: 0,
            req_headers: Vec::new(),
            resp_headers: Vec::new(),
            cache_key: None,
            cache_ttl: None,
            cache_status: 0,
            cache_headers: Vec::new(),
            cache_body: Vec::new(),
            cache_overflow: false,
        }
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> PResult<bool> {
        // Access control by client IP, evaluated before anything else.
        if !self.access.is_empty()
            && let Some(ip) = session
                .client_addr()
                .and_then(|addr| addr.as_inet())
                .map(|inet| inet.ip())
            && !self.access.allows(ip)
        {
            session.respond_error(403).await?;
            return Ok(true);
        }
        if let Some(limiter) = &self.rate_limiter {
            let key = session
                .client_addr()
                .and_then(|addr| addr.as_inet())
                .map(|inet| inet.ip().to_string())
                .unwrap_or_default();
            let now_ms = self.started.elapsed().as_millis() as u64;
            if !limiter.check(&key, now_ms) {
                session.respond_error(429).await?;
                return Ok(true);
            }
        }
        // Reject an oversized body early when its length is declared.
        if let Some(max) = self.max_body_bytes
            && let Some(len) = session
                .req_header()
                .headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
            && len > max
        {
            session.respond_error(413).await?;
            return Ok(true);
        }
        // Serve static files directly for routes backed by a directory.
        if self.try_serve_static(session).await? {
            return Ok(true);
        }
        // Routes with a WASM plugin chain are handled by the buffered plugin
        // path (which forwards to the upstream itself).
        if self.try_run_plugins(session).await? {
            return Ok(true);
        }
        // Serve from cache (revalidating a stale entry with the origin), or
        // remember the key so a cacheable response can be stored on the way back.
        if let Some(cache) = &self.cache {
            let lookup = {
                let req = session.req_header();
                let cc = req
                    .headers
                    .get(http::header::CACHE_CONTROL)
                    .and_then(|value| value.to_str().ok());
                let has_auth = req.headers.contains_key(http::header::AUTHORIZATION);
                if request_cacheable(req.method.as_str(), cc, has_auth) {
                    let host = req
                        .headers
                        .get("host")
                        .and_then(|value| value.to_str().ok())
                        .map_or("", |value| value.split(':').next().unwrap_or(value))
                        .to_owned();
                    let path_and_query = req
                        .uri
                        .path_and_query()
                        .map_or("/", |pq| pq.as_str())
                        .to_owned();
                    let accept_encoding = req
                        .headers
                        .get(http::header::ACCEPT_ENCODING)
                        .and_then(|value| value.to_str().ok());
                    let if_none_match = req
                        .headers
                        .get(http::header::IF_NONE_MATCH)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned);
                    let key = ResponseCache::key(&host, &path_and_query, accept_encoding);
                    Some((key, if_none_match, host, path_and_query))
                } else {
                    None
                }
            };
            if let Some((key, if_none_match, host, path_and_query)) = lookup {
                use zaphyl_core::cache::Lookup;
                match cache.lookup(&key, std::time::SystemTime::now()) {
                    Lookup::Fresh(hit) => {
                        return self
                            .serve_cache_hit(session, hit, if_none_match.as_deref())
                            .await;
                    }
                    Lookup::Stale(hit) => {
                        let etag = hit.etag().map(str::to_owned);
                        let path = path_and_query.split('?').next().unwrap_or(&path_and_query);
                        let target = self
                            .router
                            .match_route(Some(&host), path)
                            .and_then(Route::next_target)
                            .cloned();
                        if let (Some(etag), Some(target)) = (etag, target) {
                            match upstream::revalidate(
                                &self.revalidation_client,
                                &target,
                                &path_and_query,
                                &host,
                                &etag,
                                self.read_timeout,
                                self.cache_max_body,
                            )
                            .await
                            {
                                upstream::Revalidated::NotModified => {
                                    let ttl = stored_ttl(&hit)
                                        .unwrap_or(std::time::Duration::from_secs(60));
                                    cache.put(
                                        key.clone(),
                                        std::time::SystemTime::now() + ttl,
                                        hit.clone(),
                                    );
                                    return self
                                        .serve_cache_hit(session, hit, if_none_match.as_deref())
                                        .await;
                                }
                                upstream::Revalidated::Modified {
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
                                        cache.put(
                                            key.clone(),
                                            std::time::SystemTime::now() + ttl,
                                            fresh.clone(),
                                        );
                                    }
                                    return self.serve_cache_hit(session, fresh, None).await;
                                }
                                // Origin unreachable: fall back to a normal fetch.
                                upstream::Revalidated::Failed => ctx.cache_key = Some(key),
                            }
                        } else {
                            ctx.cache_key = Some(key);
                        }
                    }
                    Lookup::Miss => ctx.cache_key = Some(key),
                }
            }
        }
        // Enable response compression; Pingora negotiates the algorithm with the
        // client's Accept-Encoding and compresses the upstream response.
        if let Some(level) = self.compression_level {
            session.upstream_compression.adjust_level(level);
        }
        Ok(false)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> PResult<()>
    where
        Self::CTX: Send + Sync,
    {
        // Backstop for chunked uploads with no declared length: abort once the
        // accumulated body exceeds the limit.
        if let Some(max) = self.max_body_bytes
            && let Some(chunk) = body
        {
            ctx.body_seen += chunk.len() as u64;
            if ctx.body_seen > max {
                return Err(pingora::Error::new_str("request body exceeds limit"));
            }
        }
        Ok(())
    }

    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PResult<Box<HttpPeer>> {
        let request = session.req_header();
        let path = request.uri.path().to_owned();
        let host = request
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.split(':').next().unwrap_or(value).to_owned());

        let route = self.router.match_route(host.as_deref(), &path);
        match route.and_then(Route::next_target) {
            Some(target) => {
                if let Some(route) = route {
                    ctx.rewrite_path = route.rewrite_path(&path);
                    ctx.req_headers = route.request_headers().to_vec();
                    ctx.resp_headers = route.response_headers().to_vec();
                }
                let mut peer =
                    HttpPeer::new(target.address.as_str(), target.tls, target.sni.clone());
                peer.options.connection_timeout = self.connect_timeout;
                peer.options.read_timeout = self.read_timeout;
                if target.h2 {
                    // Speak HTTP/2 (h2 over TLS, or h2c for a plaintext gRPC
                    // backend) so gRPC requests and trailers pass through.
                    peer.options.alpn = pingora::protocols::ALPN::H2;
                }
                Ok(Box::new(peer))
            }
            None => Err(pingora::Error::new_str("no matching route")),
        }
    }

    async fn logging(
        &self,
        session: &mut Session,
        _e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        let status = session
            .response_written()
            .map_or(0, |response| response.status.as_u16());
        metrics::record(status);
        let request = session.req_header();
        let method = request.method.as_str();
        let path = request.uri.path();
        let host = request
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("-");
        let duration_ms = ctx.start.elapsed().as_millis();
        let mut out = std::io::stdout().lock();
        let _ = writeln!(
            out,
            "method={method} host={host} path={path} status={status} dur_ms={duration_ms}"
        );
        let _ = out.flush();
    }

    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PResult<()>
    where
        Self::CTX: Send + Sync,
    {
        for (name, value) in &self.response_headers {
            let _ = upstream_response.insert_header(name.clone(), value.as_str());
        }
        // Per-route response headers override the global ones.
        for (name, value) in &ctx.resp_headers {
            let _ = upstream_response.insert_header(name.clone(), value.as_str());
        }
        if let Some(alt_svc) = &self.alt_svc {
            let _ = upstream_response.insert_header("alt-svc", alt_svc.as_str());
        }
        Ok(())
    }

    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PResult<()>
    where
        Self::CTX: Send + Sync,
    {
        if let Some(new_path) = &ctx.rewrite_path {
            let target = match upstream_request.uri.query() {
                Some(query) => format!("{new_path}?{query}"),
                None => new_path.clone(),
            };
            if let Ok(uri) = target.parse::<http::Uri>() {
                upstream_request.set_uri(uri);
            }
        }
        for (name, value) in &ctx.req_headers {
            let _ = upstream_request.insert_header(name.clone(), value.as_str());
        }
        if let Some(client_ip) = session
            .client_addr()
            .and_then(|addr| addr.as_inet())
            .map(|inet| inet.ip().to_string())
        {
            let _ = upstream_request.append_header("x-forwarded-for", client_ip.as_str());
        }
        let proto = if self.tls_enabled { "https" } else { "http" };
        let _ = upstream_request.insert_header("x-forwarded-proto", proto);
        Ok(())
    }

    async fn upstream_response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PResult<()>
    where
        Self::CTX: Send + Sync,
    {
        // Decide whether this response may be cached and capture its metadata.
        if self.cache.is_some() && ctx.cache_key.is_some() {
            let cc = upstream_response
                .headers
                .get(http::header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok());
            let has_set_cookie = upstream_response
                .headers
                .contains_key(http::header::SET_COOKIE);
            let vary = upstream_response
                .headers
                .get(http::header::VARY)
                .and_then(|value| value.to_str().ok());
            let status = upstream_response.status.as_u16();
            match response_ttl(status, cc, has_set_cookie, vary) {
                Some(ttl) => {
                    ctx.cache_ttl = Some(ttl);
                    ctx.cache_status = status;
                    ctx.cache_headers = upstream_response
                        .headers
                        .iter()
                        .filter(|(name, _)| !is_uncacheable_header(name.as_str()))
                        .filter_map(|(name, value)| {
                            value
                                .to_str()
                                .ok()
                                .map(|value| (name.as_str().to_owned(), value.to_owned()))
                        })
                        .collect();
                }
                None => ctx.cache_key = None,
            }
        }
        Ok(())
    }

    fn upstream_response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<bytes::Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> PResult<Option<std::time::Duration>> {
        if let (Some(cache), Some(ttl)) = (&self.cache, ctx.cache_ttl)
            && !ctx.cache_overflow
        {
            if let Some(chunk) = body {
                if ctx.cache_body.len() + chunk.len() > self.cache_max_body as usize {
                    // Too large to cache; stop accumulating.
                    ctx.cache_overflow = true;
                    ctx.cache_body = Vec::new();
                } else {
                    ctx.cache_body.extend_from_slice(chunk);
                }
            }
            if end_of_stream
                && !ctx.cache_overflow
                && let Some(key) = ctx.cache_key.take()
            {
                cache.put(
                    key,
                    std::time::SystemTime::now() + ttl,
                    CachedResponse {
                        status: ctx.cache_status,
                        headers: std::mem::take(&mut ctx.cache_headers),
                        body: std::mem::take(&mut ctx.cache_body),
                    },
                );
            }
        }
        Ok(None)
    }

    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        e: &pingora::Error,
        _ctx: &mut Self::CTX,
    ) -> pingora::proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        use pingora::{ErrorSource, ErrorType};
        // Like Pingora's default, but report upstream timeouts as 504 Gateway
        // Timeout rather than a generic 502.
        let code = match e.etype() {
            ErrorType::HTTPStatus(code) => *code,
            ErrorType::ConnectTimedout
            | ErrorType::ReadTimedout
            | ErrorType::WriteTimedout
            | ErrorType::TLSHandshakeTimedout => 504,
            _ => match e.esource() {
                ErrorSource::Upstream => 502,
                ErrorSource::Downstream => match e.etype() {
                    ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
                    _ => 400,
                },
                ErrorSource::Internal | ErrorSource::Unset => 500,
            },
        };
        if code > 0 {
            let _ = session.respond_error(code).await;
        }
        pingora::proxy::FailToProxy {
            error_code: code,
            can_reuse_downstream: false,
        }
    }
}

/// Find `--config <path>` (or `-c <path>`) in the process arguments.
fn config_path_from_args() -> Option<PathBuf> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if arg == "--config" || arg == "-c" {
            return args.next().map(PathBuf::from);
        }
    }
    None
}

/// Resolve the TLS certificate and key paths: an explicit `[tls]` section, or a
/// certificate obtained (or cached) via `[acme]`. `None` means plain HTTP.
///
/// When ACME is used, the returned [`acme::AcmeRunner`] must be kept alive for
/// the life of the process: it owns the renewal loop. `challenge_store` must
/// already be served by a running HTTP front (see [`spawn_http_front`]).
fn resolve_tls(
    config: &Config,
    challenge_store: Arc<ChallengeStore>,
) -> (Option<(PathBuf, PathBuf)>, Option<acme::AcmeRunner>) {
    if let Some(tls) = &config.tls {
        return (
            Some((PathBuf::from(&tls.cert), PathBuf::from(&tls.key))),
            None,
        );
    }
    if let Some(acme) = &config.acme {
        let runner = acme::AcmeRunner::start(acme, challenge_store).unwrap_or_else(|e| {
            eprintln!("zaphyl: acme failed: {e}");
            std::process::exit(1);
        });
        runner.spawn_renewal();
        return (Some(runner.cert_paths()), Some(runner));
    }
    (None, None)
}

/// Start the plain-HTTP front (port 80) when `[http]` (redirect) or `[acme]`
/// (challenges) is configured, and wait until it is accepting connections.
///
/// `[http]` redirects non-challenge requests to HTTPS; ACME alone serves
/// challenges and replies 404 to everything else. The `store` is shared with the
/// ACME machinery so renewals are validated by this same listener.
fn spawn_http_front(config: &Config, store: Arc<ChallengeStore>) {
    let https_port = config.listen.port();
    let front = if let Some(http) = &config.http {
        Some((
            http.listen,
            http_front::NonChallenge::RedirectToHttps(https_port),
        ))
    } else if config.acme.is_some() {
        let addr = std::env::var("ZAPHYL_ACME_HTTP_ADDR")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 80)));
        Some((addr, http_front::NonChallenge::NotFound))
    } else {
        None
    };
    let Some((addr, behavior)) = front else {
        return;
    };

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to build http front runtime");
        if let Err(e) = runtime.block_on(http_front::serve(addr, store, behavior)) {
            eprintln!("zaphyl: http front error: {e}");
        }
    });
    wait_bound(addr);
}

/// Best-effort wait until `addr` is accepting connections (so the first ACME
/// challenge can be served right after the front starts).
fn wait_bound(addr: SocketAddr) {
    let probe = match addr {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
            SocketAddr::from(([127, 0, 0, 1], addr.port()))
        }
        other => other,
    };
    let start = std::time::Instant::now();
    while std::net::TcpStream::connect(probe).is_err() {
        if start.elapsed() > std::time::Duration::from_secs(3) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Build the Pingora server with a single HTTP(S) proxy service.
fn build_server(
    config: &Config,
    tls: Option<&(PathBuf, PathBuf)>,
    router: std::sync::Arc<Router>,
    access: Arc<AccessControl>,
    cache: Option<Arc<ResponseCache>>,
    plugins: Option<Arc<plugins::Plugins>>,
) -> PResult<Server> {
    // Pingora's default graceful-shutdown grace period is 5 minutes, which makes
    // the server hang on SIGTERM until Docker/Kubernetes force-kill it. Use a
    // short, configurable grace period so SIGTERM drains in-flight requests and
    // then exits promptly. (SIGINT/Ctrl-C still exits immediately.)
    let conf = pingora::server::configuration::ServerConf {
        grace_period_seconds: Some(config.shutdown_grace_seconds.unwrap_or(5)),
        graceful_shutdown_timeout_seconds: Some(3),
        ..Default::default()
    };
    let mut server = Server::new_with_opt_and_conf(None, conf);
    server.bootstrap();

    let app = ZaphylProxy::new(config, tls.is_some(), router, access, cache, plugins);
    let mut proxy = http_proxy_service(&server.configuration, app);
    // Run the proxy across all CPUs by default (Pingora's per-service default is
    // a single thread); override with `worker_threads`.
    proxy.threads = Some(config.worker_threads.unwrap_or_else(|| {
        std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get)
    }));
    let listen = config.listen.to_string();
    match tls {
        Some((cert, key)) => {
            // Serve the certificate dynamically so a renewed cert is picked up
            // without a restart (see `tls::DynamicCert`).
            let provider = tls::DynamicCert::new(cert.clone(), key.clone());
            let callbacks: pingora::listeners::TlsAcceptCallbacks = Box::new(provider);
            let mut settings = pingora::listeners::tls::TlsSettings::with_callbacks(callbacks)?;
            // Advertise HTTP/2 (and HTTP/1.1) via ALPN.
            settings.enable_h2();
            proxy.add_tls_with_settings(&listen, None, settings);
        }
        None => proxy.add_tcp(&listen),
    }
    server.add_service(proxy);

    if let Some(metrics) = &config.metrics {
        let mut metrics_service = pingora::services::listening::Service::prometheus_http_service();
        metrics_service.add_tcp(&metrics.listen.to_string());
        server.add_service(metrics_service);
    }

    Ok(server)
}

/// Spawn a background thread that TCP-probes each upstream on the given interval
/// and updates its health flag.
fn spawn_health_prober(
    probes: Vec<(String, std::sync::Arc<std::sync::atomic::AtomicBool>)>,
    interval: std::time::Duration,
) {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::sync::atomic::Ordering;
    std::thread::spawn(move || {
        loop {
            for (address, healthy) in &probes {
                let reachable = address
                    .to_socket_addrs()
                    .ok()
                    .and_then(|mut addrs| addrs.next())
                    .is_some_and(|addr| {
                        TcpStream::connect_timeout(&addr, std::time::Duration::from_secs(2)).is_ok()
                    });
                healthy.store(reachable, Ordering::Relaxed);
            }
            std::thread::sleep(interval);
        }
    });
}

fn main() -> std::process::ExitCode {
    use clap::Parser as _;
    let parsed = cli::Cli::parse();
    match parsed.command {
        Some(cli::Command::Site(cmd)) => return cli::run_site(cmd),
        Some(cli::Command::Reload) => return cli::run_reload(),
        Some(cli::Command::Run) | None => {}
    }

    let Some(path) = parsed.config.or_else(config_path_from_args) else {
        eprintln!("usage: zaphyl --config <path>");
        std::process::exit(2);
    };

    let config = Config::load(&path).unwrap_or_else(|e| {
        eprintln!("zaphyl: {e}");
        std::process::exit(1);
    });

    // Start the plain-HTTP front first so it can answer the initial ACME
    // challenge during the obtain below.
    let challenge_store = Arc::new(ChallengeStore::new());
    spawn_http_front(&config, Arc::clone(&challenge_store));

    // `_acme` owns the renewal loop; keep it alive until the process exits
    // (`run_forever` never returns).
    let (tls, _acme) = resolve_tls(&config, challenge_store);
    let router = std::sync::Arc::new(build_router(&config));

    let access = Arc::new(
        config
            .access
            .as_ref()
            .map(|a| {
                AccessControl::parse(&a.allow, &a.deny).unwrap_or_else(|bad| {
                    eprintln!("zaphyl: invalid access entry: {bad}");
                    std::process::exit(1);
                })
            })
            .unwrap_or_default(),
    );

    // One cache shared by the HTTP/1·2 and HTTP/3 listeners.
    let cache = config.cache.as_ref().map(|c| {
        Arc::new(match &c.disk_path {
            Some(dir) => ResponseCache::with_disk(c.max_entries, PathBuf::from(dir)),
            None => ResponseCache::new(c.max_entries),
        })
    });

    // Compile the WASM plugin chains once, shared by all listeners.
    let plugins = {
        let upstream_ca = std::env::var("ZAPHYL_UPSTREAM_CA").ok().map(PathBuf::from);
        let read_timeout = config
            .limits
            .as_ref()
            .and_then(|l| l.upstream_read_timeout_seconds)
            .map(std::time::Duration::from_secs);
        plugins::Plugins::build(&config, upstream_ca.as_deref(), read_timeout)
            .unwrap_or_else(|e| {
                eprintln!("zaphyl: failed to load plugins: {e}");
                std::process::exit(1);
            })
            .map(Arc::new)
    };

    if let Some(health_check) = &config.health_check {
        spawn_health_prober(
            router.health_probes(),
            std::time::Duration::from_secs(health_check.interval_seconds),
        );
    }

    if let (Some(http3), Some((cert_path, key_path))) = (&config.http3, tls.as_ref()) {
        let listen = http3.listen;
        let cert_path = cert_path.clone();
        let key_path = key_path.clone();
        let router = std::sync::Arc::clone(&router);
        let access = Arc::clone(&access);
        let plugins = plugins.clone();
        let caching = http3::Caching {
            cache: cache.clone(),
            max_body: config.cache.as_ref().map_or(0, |c| c.max_body_bytes),
            reval_client: cache.as_ref().map(|_| {
                let ca = std::env::var("ZAPHYL_UPSTREAM_CA").ok().map(PathBuf::from);
                upstream::build_client(ca.as_deref())
            }),
            reval_timeout: config
                .limits
                .as_ref()
                .and_then(|l| l.upstream_read_timeout_seconds)
                .map(std::time::Duration::from_secs),
        };
        let upstream_ca = std::env::var("ZAPHYL_UPSTREAM_CA").ok().map(PathBuf::from);
        let limits = http3::Limits {
            max_body_bytes: config
                .limits
                .as_ref()
                .and_then(|l| l.max_request_body_bytes),
            max_header_bytes: config
                .limits
                .as_ref()
                .and_then(|l| l.max_request_header_bytes),
            connect_timeout: config
                .limits
                .as_ref()
                .and_then(|l| l.upstream_connect_timeout_seconds)
                .map(std::time::Duration::from_secs),
            read_timeout: config
                .limits
                .as_ref()
                .and_then(|l| l.upstream_read_timeout_seconds)
                .map(std::time::Duration::from_secs),
            compression_level: config.compression.as_ref().map(|c| c.level),
        };
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("failed to build http3 runtime");
            if let Err(e) = runtime.block_on(http3::serve(
                listen,
                &cert_path,
                &key_path,
                router,
                upstream_ca,
                limits,
                access,
                caching,
                plugins,
            )) {
                eprintln!("zaphyl: http3 error: {e}");
            }
        });
    }

    let server = build_server(
        &config,
        tls.as_ref(),
        router,
        Arc::clone(&access),
        cache,
        plugins,
    )
    .unwrap_or_else(|e| {
        eprintln!("zaphyl: failed to start: {e}");
        std::process::exit(1);
    });

    let scheme = if tls.is_some() { "https" } else { "http" };
    eprintln!(
        "Zaphyl {} listening on {}://{} ({} route(s))",
        zaphyl_core::version(),
        scheme,
        config.listen,
        config.routes.len()
    );
    server.run_forever();
    #[allow(unreachable_code)]
    std::process::ExitCode::SUCCESS
}
