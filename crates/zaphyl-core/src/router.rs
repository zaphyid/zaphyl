//! Request routing and per-route round-robin load balancing.
//!
//! Transport-agnostic on purpose - it knows nothing about Pingora or the HTTP
//! version. Given a host and path it selects a route, and each route round-robins
//! across its upstream targets.

use crate::static_files::StaticDir;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

/// An upstream target a request can be forwarded to.
#[derive(Debug, Clone)]
pub struct Target {
    /// Upstream address as `host:port`.
    pub address: String,
    /// Whether to connect to the upstream over TLS.
    pub tls: bool,
    /// SNI hostname used when `tls` is true.
    pub sni: String,
    /// Whether to speak HTTP/2 to the upstream (h2 over TLS, or h2c plaintext).
    /// Required for gRPC backends.
    pub h2: bool,
    healthy: Arc<AtomicBool>,
}

impl Target {
    /// Create a target that starts out healthy.
    #[must_use]
    pub fn new(address: String, tls: bool, sni: String) -> Self {
        Self {
            address,
            tls,
            sni,
            h2: false,
            healthy: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Enable HTTP/2 to the upstream (for gRPC and h2 backends).
    #[must_use]
    pub fn with_h2(mut self, h2: bool) -> Self {
        self.h2 = h2;
        self
    }

    /// Whether this target is currently considered healthy.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    /// A shared handle a health checker uses to update this target's health.
    #[must_use]
    pub fn health_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.healthy)
    }
}

/// A routing rule: optional host and path-prefix matchers plus one or more
/// upstream targets that are load-balanced round-robin.
#[derive(Debug)]
pub struct Route {
    host: Option<String>,
    path_prefix: Option<String>,
    targets: Vec<Target>,
    strip_prefix: bool,
    request_headers: Vec<(String, String)>,
    response_headers: Vec<(String, String)>,
    static_dir: Option<StaticDir>,
    id: usize,
    next: AtomicUsize,
}

impl Route {
    /// Create a route. `host`/`path_prefix` of `None` match anything.
    #[must_use]
    pub fn new(host: Option<String>, path_prefix: Option<String>, targets: Vec<Target>) -> Self {
        Self {
            host,
            path_prefix,
            targets,
            strip_prefix: false,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            static_dir: None,
            id: 0,
            next: AtomicUsize::new(0),
        }
    }

    /// Set this route's index, used by the proxy to find its plugin chain.
    #[must_use]
    pub fn with_id(mut self, id: usize) -> Self {
        self.id = id;
        self
    }

    /// This route's index among the configured routes.
    #[must_use]
    pub fn id(&self) -> usize {
        self.id
    }

    /// Serve static files from `dir` instead of proxying to an upstream.
    #[must_use]
    pub fn with_static(mut self, dir: StaticDir) -> Self {
        self.static_dir = Some(dir);
        self
    }

    /// The static-file root for this route, if it serves files.
    #[must_use]
    pub fn static_dir(&self) -> Option<&StaticDir> {
        self.static_dir.as_ref()
    }

    /// Enable stripping the matched path prefix from the path forwarded upstream.
    #[must_use]
    pub fn with_strip_prefix(mut self, strip: bool) -> Self {
        self.strip_prefix = strip;
        self
    }

    /// Set the headers to add to the upstream request and the downstream response.
    #[must_use]
    pub fn with_headers(
        mut self,
        request_headers: Vec<(String, String)>,
        response_headers: Vec<(String, String)>,
    ) -> Self {
        self.request_headers = request_headers;
        self.response_headers = response_headers;
        self
    }

    /// Headers to set on the request forwarded upstream.
    #[must_use]
    pub fn request_headers(&self) -> &[(String, String)] {
        &self.request_headers
    }

    /// Headers to set on the response returned to the client.
    #[must_use]
    pub fn response_headers(&self) -> &[(String, String)] {
        &self.response_headers
    }

    /// The path to forward upstream for a request `path` that matched this route:
    /// `Some(stripped)` when `strip_prefix` is enabled, else `None` (forward the
    /// path unchanged). The result always begins with `/`.
    #[must_use]
    pub fn rewrite_path(&self, path: &str) -> Option<String> {
        if !self.strip_prefix {
            return None;
        }
        let prefix = self.path_prefix.as_deref()?.trim_end_matches('/');
        let rest = path.strip_prefix(prefix).unwrap_or(path);
        Some(if rest.is_empty() {
            "/".to_owned()
        } else {
            rest.to_owned()
        })
    }

    /// Pick the next upstream target for this route, round-robin. `None` only if
    /// the route has no targets.
    pub fn next_target(&self) -> Option<&Target> {
        let count = self.targets.len();
        if count == 0 {
            return None;
        }
        // Prefer a healthy target, scanning round-robin; if none are healthy,
        // fall back to the next one so traffic still flows.
        for _ in 0..count {
            let index = self.next.fetch_add(1, Ordering::Relaxed) % count;
            if self.targets[index].is_healthy() {
                return self.targets.get(index);
            }
        }
        let index = self.next.fetch_add(1, Ordering::Relaxed) % count;
        self.targets.get(index)
    }

    fn matches(&self, host: Option<&str>, path: &str) -> bool {
        self.host_matches(host) && self.path_matches(path)
    }

    fn host_matches(&self, host: Option<&str>) -> bool {
        match &self.host {
            None => true,
            Some(expected) => host.is_some_and(|h| h.eq_ignore_ascii_case(expected)),
        }
    }

    fn path_matches(&self, path: &str) -> bool {
        match &self.path_prefix {
            None => true,
            Some(prefix) => path_under_prefix(path, prefix),
        }
    }
}

/// An ordered set of routes. The first route that matches a request wins.
#[derive(Debug, Default)]
pub struct Router {
    routes: Vec<Route>,
}

impl Router {
    /// Build a router from routes in priority order (first match wins).
    #[must_use]
    pub fn new(routes: Vec<Route>) -> Self {
        Self { routes }
    }

    /// Find the first route whose host and path matchers accept the request.
    #[must_use]
    pub fn match_route(&self, host: Option<&str>, path: &str) -> Option<&Route> {
        self.routes.iter().find(|route| route.matches(host, path))
    }

    /// Every target's address paired with a handle to update its health.
    #[must_use]
    pub fn health_probes(&self) -> Vec<(String, Arc<AtomicBool>)> {
        self.routes
            .iter()
            .flat_map(|route| {
                route
                    .targets
                    .iter()
                    .map(|target| (target.address.clone(), target.health_handle()))
            })
            .collect()
    }
}

/// True if `path` equals `prefix` or is a sub-path of it on a segment boundary,
/// so that the prefix `/v1` matches `/v1` and `/v1/users` but not `/v10`.
fn path_under_prefix(path: &str, prefix: &str) -> bool {
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        return true;
    }
    match path.strip_prefix(prefix) {
        Some("") => true,
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{Route, Router, Target};

    fn target(address: &str) -> Target {
        Target::new(address.to_owned(), false, String::new())
    }

    fn router() -> Router {
        Router::new(vec![
            Route::new(
                Some("api.example.com".to_owned()),
                Some("/v1".to_owned()),
                vec![target("a:1")],
            ),
            Route::new(Some("example.com".to_owned()), None, vec![target("b:2")]),
            Route::new(None, Some("/static".to_owned()), vec![target("c:3")]),
        ])
    }

    fn matched(host: Option<&str>, path: &str) -> Option<String> {
        router()
            .match_route(host, path)
            .and_then(Route::next_target)
            .map(|t| t.address.clone())
    }

    #[test]
    fn matches_host_and_path() {
        assert_eq!(
            matched(Some("api.example.com"), "/v1/users").as_deref(),
            Some("a:1")
        );
    }

    #[test]
    fn host_match_is_case_insensitive() {
        assert_eq!(
            matched(Some("Example.COM"), "/anything").as_deref(),
            Some("b:2")
        );
    }

    #[test]
    fn path_only_route_matches_any_host() {
        assert_eq!(
            matched(Some("whatever.com"), "/static/app.js").as_deref(),
            Some("c:3")
        );
    }

    #[test]
    fn first_match_wins() {
        assert_eq!(
            matched(Some("api.example.com"), "/v1").as_deref(),
            Some("a:1")
        );
    }

    #[test]
    fn path_prefix_respects_segment_boundary() {
        assert_eq!(matched(Some("api.example.com"), "/v10"), None);
    }

    #[test]
    fn no_match_returns_none() {
        assert_eq!(matched(Some("nope.com"), "/x"), None);
    }

    #[test]
    fn strip_prefix_rewrites_path() {
        let route =
            Route::new(None, Some("/api".to_owned()), vec![target("a:1")]).with_strip_prefix(true);
        assert_eq!(route.rewrite_path("/api/users").as_deref(), Some("/users"));
        // The matched prefix on its own becomes `/`.
        assert_eq!(route.rewrite_path("/api").as_deref(), Some("/"));
        assert_eq!(route.rewrite_path("/api/").as_deref(), Some("/"));
    }

    #[test]
    fn without_strip_prefix_path_is_unchanged() {
        let route = Route::new(None, Some("/api".to_owned()), vec![target("a:1")]);
        assert_eq!(route.rewrite_path("/api/users"), None);
    }

    #[test]
    fn target_can_enable_http2() {
        assert!(!target("a:1").h2);
        assert!(target("a:1").with_h2(true).h2);
    }

    #[test]
    fn route_carries_headers() {
        let route = Route::new(None, None, vec![target("a:1")]).with_headers(
            vec![("x-req".to_owned(), "1".to_owned())],
            vec![("x-resp".to_owned(), "2".to_owned())],
        );
        assert_eq!(
            route.request_headers(),
            &[("x-req".to_owned(), "1".to_owned())]
        );
        assert_eq!(
            route.response_headers(),
            &[("x-resp".to_owned(), "2".to_owned())]
        );
    }

    #[test]
    fn round_robins_targets() {
        let route = Route::new(None, None, vec![target("a:1"), target("b:2")]);
        let pick = || route.next_target().unwrap().address.clone();
        assert_eq!(pick(), "a:1");
        assert_eq!(pick(), "b:2");
        assert_eq!(pick(), "a:1");
    }

    #[test]
    fn skips_unhealthy_target() {
        let router = Router::new(vec![Route::new(
            None,
            None,
            vec![target("a:1"), target("b:2")],
        )]);
        for (address, handle) in router.health_probes() {
            if address == "a:1" {
                handle.store(false, super::Ordering::Relaxed);
            }
        }
        let route = router.match_route(None, "/").unwrap();
        assert_eq!(route.next_target().unwrap().address, "b:2");
        assert_eq!(route.next_target().unwrap().address, "b:2");
    }
}
