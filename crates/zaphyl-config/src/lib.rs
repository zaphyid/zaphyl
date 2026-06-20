//! Configuration types and parsing for Zaphyl.

pub mod sites;

use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use std::net::SocketAddr;

/// Top-level Zaphyl configuration, loaded from a TOML file.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address the proxy listens on, e.g. `0.0.0.0:8080`.
    pub listen: SocketAddr,
    /// Number of worker threads for the HTTP/1·2 listener. Defaults to the
    /// number of available CPUs when unset.
    #[serde(default)]
    pub worker_threads: Option<usize>,
    /// On `SIGTERM`, how many seconds to let in-flight requests drain before
    /// exiting (graceful shutdown). Defaults to 5. Kept short so the server stops
    /// promptly under Docker/Kubernetes; raise it for long-running requests.
    #[serde(default)]
    pub shutdown_grace_seconds: Option<u64>,
    /// If set, terminate TLS on the listener using this certificate and key.
    #[serde(default)]
    pub tls: Option<TlsConfig>,
    /// If set, obtain and renew the listener certificate automatically via ACME.
    /// Mutually exclusive with `[tls]`.
    #[serde(default)]
    pub acme: Option<AcmeConfig>,
    /// If set, expose Prometheus metrics on this address.
    #[serde(default)]
    pub metrics: Option<MetricsConfig>,
    /// If set, rate-limit requests per client IP.
    #[serde(default)]
    pub rate_limit: Option<RateLimitConfig>,
    /// If set, periodically TCP-probe upstreams and skip unhealthy ones.
    #[serde(default)]
    pub health_check: Option<HealthCheckConfig>,
    /// If set, request body-size limits and upstream timeouts.
    #[serde(default)]
    pub limits: Option<LimitsConfig>,
    /// If set, allow/deny client access by IP. TOML table `[access]`.
    #[serde(default)]
    pub access: Option<AccessConfig>,
    /// If set, compress responses (gzip/brotli/zstd by client support).
    #[serde(default)]
    pub compression: Option<CompressionConfig>,
    /// If set, cache cacheable upstream responses in memory. TOML table `[cache]`.
    #[serde(default)]
    pub cache: Option<CacheConfig>,
    /// WebAssembly plugins applied to every request (before per-route plugins).
    /// TOML table `[plugins]`.
    #[serde(default)]
    pub plugins: Option<PluginsConfig>,
    /// If set, also serve HTTP/3 on this UDP address. Requires `[tls]` or `[acme]`.
    #[serde(default)]
    pub http3: Option<Http3Config>,
    /// If set, run a plain-HTTP listener that redirects to HTTPS (and answers
    /// ACME challenges). Requires `[tls]` or `[acme]`.
    #[serde(default)]
    pub http: Option<HttpRedirectConfig>,
    /// Headers added to every response. TOML table `[response_headers]`.
    #[serde(default)]
    pub response_headers: HashMap<String, String>,
    /// Routing rules, tried in order (first match wins). TOML key: `[[route]]`.
    #[serde(rename = "route", default)]
    pub routes: Vec<RouteConfig>,
}

/// TLS termination settings for the listener.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    /// Path to the PEM-encoded certificate chain.
    pub cert: String,
    /// Path to the PEM-encoded private key.
    pub key: String,
}

/// Prometheus metrics endpoint settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Address to serve Prometheus metrics on, e.g. `127.0.0.1:9090`.
    pub listen: SocketAddr,
}

/// Per-client-IP request rate limiting.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Maximum requests per second allowed per client IP (at least 1).
    pub requests_per_second: u32,
}

/// Background upstream health checking.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheckConfig {
    /// How often to TCP-probe each upstream, in seconds (at least 1).
    pub interval_seconds: u64,
}

/// Response compression settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompressionConfig {
    /// Compression level (at least 1; higher is smaller but slower).
    pub level: u32,
}

/// WebAssembly plugin settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginsConfig {
    /// Paths to plugin `.wasm` files run on every request, in order.
    #[serde(default)]
    pub global: Vec<String>,
    /// Buffer at most this many body bytes when handing a request/response to a
    /// plugin (larger bodies skip the plugin chain).
    #[serde(default = "default_plugin_max_body_bytes")]
    pub max_body_bytes: u64,
}

fn default_plugin_max_body_bytes() -> u64 {
    1024 * 1024
}

/// In-memory response cache settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheConfig {
    /// Maximum number of cached responses.
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,
    /// Do not cache response bodies larger than this many bytes.
    #[serde(default = "default_cache_max_body_bytes")]
    pub max_body_bytes: u64,
    /// If set, also persist cache entries under this directory (survives restart).
    #[serde(default)]
    pub disk_path: Option<String>,
}

fn default_cache_max_entries() -> usize {
    1024
}

fn default_cache_max_body_bytes() -> u64 {
    1024 * 1024
}

/// Client-IP access control. Each entry is a bare IP or a CIDR block.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessConfig {
    /// If non-empty, only clients matching one of these are allowed.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Clients matching any of these are denied (takes precedence over `allow`).
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Request body-size limits and upstream timeouts.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitsConfig {
    /// Reject requests whose body exceeds this many bytes with `413`.
    #[serde(default)]
    pub max_request_body_bytes: Option<u64>,
    /// Reject requests whose decoded header section exceeds this many bytes
    /// (HTTP/3; defaults to 64 KiB when unset).
    #[serde(default)]
    pub max_request_header_bytes: Option<u64>,
    /// Timeout for establishing the upstream connection, in seconds.
    #[serde(default)]
    pub upstream_connect_timeout_seconds: Option<u64>,
    /// Timeout for reading from the upstream, in seconds.
    #[serde(default)]
    pub upstream_read_timeout_seconds: Option<u64>,
}

/// HTTP/3 (QUIC) listener settings.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Http3Config {
    /// UDP address to serve HTTP/3 on, e.g. `0.0.0.0:443`.
    pub listen: SocketAddr,
}

/// Plain-HTTP listener that redirects to HTTPS and answers ACME challenges.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpRedirectConfig {
    /// Address to serve plain HTTP on, e.g. `0.0.0.0:80`.
    pub listen: SocketAddr,
}

/// Automatic HTTPS via the ACME protocol (e.g. Let's Encrypt).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcmeConfig {
    /// Domains to obtain a certificate for (at least one, all non-empty).
    pub domains: Vec<String>,
    /// Contact email registered with the ACME account.
    pub email: String,
    /// ACME directory URL. Defaults to Let's Encrypt production.
    #[serde(default = "default_acme_directory")]
    pub directory: String,
    /// Directory where the account key and issued certificates are cached.
    #[serde(default = "default_acme_cache_dir")]
    pub cache_dir: String,
    /// Renew the certificate once it is within this many days of expiry.
    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u64,
    /// How often to check whether the certificate is due for renewal, in seconds.
    #[serde(default = "default_acme_check_interval")]
    pub check_interval_seconds: u64,
}

fn default_acme_directory() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_owned()
}

fn default_acme_cache_dir() -> String {
    "./acme".to_owned()
}

fn default_renew_before_days() -> u64 {
    30
}

fn default_acme_check_interval() -> u64 {
    12 * 60 * 60
}

/// Deserialize a field that may be a single string or a list of strings.
fn string_or_seq<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(String),
        Many(Vec<String>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(value) => vec![value],
        OneOrMany::Many(values) => values,
    })
}

/// A single routing rule.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// If set, the request host must equal this (compared case-insensitively).
    #[serde(default)]
    pub host: Option<String>,
    /// If set, the request path must be under this prefix (must start with `/`).
    #[serde(default)]
    pub path: Option<String>,
    /// Upstream address(es) as `host:port`. Accepts a single string or a list;
    /// multiple upstreams are load-balanced round-robin. Omit for a static route.
    #[serde(default, deserialize_with = "string_or_seq")]
    pub upstream: Vec<String>,
    /// Serve static files from this directory instead of proxying. Mutually
    /// exclusive with `upstream`.
    #[serde(default)]
    pub root: Option<String>,
    /// Connect to the upstream over TLS. Defaults to `false`.
    #[serde(default)]
    pub tls: bool,
    /// Strip the matched `path` prefix before forwarding. Requires `path`.
    #[serde(default)]
    pub strip_prefix: bool,
    /// Headers to set on the request forwarded upstream. TOML table
    /// `[route.request_headers]`.
    #[serde(default)]
    pub request_headers: HashMap<String, String>,
    /// Headers to set on the response returned to the client. TOML table
    /// `[route.response_headers]`.
    #[serde(default)]
    pub response_headers: HashMap<String, String>,
    /// Speak HTTP/2 to the upstream (required for gRPC backends). Defaults to
    /// `false`.
    #[serde(default)]
    pub grpc: bool,
    /// Paths to plugin `.wasm` files for this route, run after the global ones.
    #[serde(default)]
    pub plugins: Vec<String>,
}

/// An error produced while loading or validating configuration.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// The TOML text could not be parsed.
    #[error("invalid TOML: {0}")]
    Toml(#[from] toml::de::Error),
    /// The configuration parsed but failed validation.
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

impl Config {
    /// Load the main config file plus every `*.toml` in its `sites/` directory.
    ///
    /// # Errors
    /// Fails if a file cannot be read or parsed.
    pub fn load(main: &std::path::Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(main)
            .map_err(|e| ConfigError::Invalid(format!("cannot read {}: {e}", main.display())))?;
        let mut config = Config::from_toml(&text)?;

        let sites_dir = main
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join("sites");
        let mut site_files: Vec<_> = match std::fs::read_dir(&sites_dir) {
            Ok(rd) => rd
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "toml"))
                .collect(),
            Err(_) => Vec::new(),
        };
        site_files.sort();

        let mut site_routes = Vec::new();
        let mut acme_domains = Vec::new();
        for path in site_files {
            let body = std::fs::read_to_string(&path).map_err(|e| {
                ConfigError::Invalid(format!("cannot read {}: {e}", path.display()))
            })?;
            let site = crate::sites::SiteConfig::from_toml(&body)?;
            if let Some(route) = site.to_route() {
                site_routes.push(route);
            }
            if let Some(domain) = site.tls_domain() {
                acme_domains.push(domain.to_owned());
            }
        }

        // Host-specific site routes win over the main config's catch-all.
        site_routes.append(&mut config.routes);
        config.routes = site_routes;

        // Merge auto-TLS domains into ACME when ACME is configured.
        if let Some(acme) = config.acme.as_mut() {
            for d in acme_domains {
                if !acme.domains.contains(&d) {
                    acme.domains.push(d);
                }
            }
        }

        Ok(config)
    }

    /// Parse and validate a [`Config`] from a TOML string.
    ///
    /// # Errors
    /// Returns [`ConfigError`] if the TOML is malformed or a value is invalid.
    pub fn from_toml(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if self.routes.is_empty() {
            return Err(ConfigError::Invalid(
                "at least one [[route]] is required".to_owned(),
            ));
        }
        if let Some(tls) = &self.tls
            && (tls.cert.trim().is_empty() || tls.key.trim().is_empty())
        {
            return Err(ConfigError::Invalid(
                "tls.cert and tls.key must not be empty".to_owned(),
            ));
        }
        if self.tls.is_some() && self.acme.is_some() {
            return Err(ConfigError::Invalid(
                "[tls] and [acme] are mutually exclusive".to_owned(),
            ));
        }
        if let Some(acme) = &self.acme {
            if acme.domains.is_empty() || acme.domains.iter().any(|d| d.trim().is_empty()) {
                return Err(ConfigError::Invalid(
                    "acme.domains must list at least one non-empty domain".to_owned(),
                ));
            }
            if acme.email.trim().is_empty() {
                return Err(ConfigError::Invalid(
                    "acme.email must not be empty".to_owned(),
                ));
            }
            if acme.renew_before_days == 0 {
                return Err(ConfigError::Invalid(
                    "acme.renew_before_days must be at least 1".to_owned(),
                ));
            }
            if acme.check_interval_seconds == 0 {
                return Err(ConfigError::Invalid(
                    "acme.check_interval_seconds must be at least 1".to_owned(),
                ));
            }
        }
        if let Some(rate_limit) = &self.rate_limit
            && rate_limit.requests_per_second == 0
        {
            return Err(ConfigError::Invalid(
                "rate_limit.requests_per_second must be at least 1".to_owned(),
            ));
        }
        if let Some(health_check) = &self.health_check
            && health_check.interval_seconds == 0
        {
            return Err(ConfigError::Invalid(
                "health_check.interval_seconds must be at least 1".to_owned(),
            ));
        }
        if let Some(limits) = &self.limits {
            if limits.max_request_body_bytes == Some(0) {
                return Err(ConfigError::Invalid(
                    "limits.max_request_body_bytes must be at least 1".to_owned(),
                ));
            }
            if limits.upstream_connect_timeout_seconds == Some(0)
                || limits.upstream_read_timeout_seconds == Some(0)
            {
                return Err(ConfigError::Invalid(
                    "limits upstream timeouts must be at least 1 second".to_owned(),
                ));
            }
        }
        if self.http3.is_some() && self.tls.is_none() && self.acme.is_none() {
            return Err(ConfigError::Invalid(
                "[http3] requires a TLS certificate ([tls] or [acme])".to_owned(),
            ));
        }
        if self.http.is_some() && self.tls.is_none() && self.acme.is_none() {
            return Err(ConfigError::Invalid(
                "[http] redirect requires a TLS certificate ([tls] or [acme])".to_owned(),
            ));
        }
        if let Some(compression) = &self.compression
            && compression.level == 0
        {
            return Err(ConfigError::Invalid(
                "compression.level must be at least 1".to_owned(),
            ));
        }
        if let Some(cache) = &self.cache
            && (cache.max_entries == 0 || cache.max_body_bytes == 0)
        {
            return Err(ConfigError::Invalid(
                "cache.max_entries and cache.max_body_bytes must be at least 1".to_owned(),
            ));
        }
        for (index, route) in self.routes.iter().enumerate() {
            let has_upstream = !route.upstream.is_empty();
            let has_root = route.root.is_some();
            if !has_upstream && !has_root {
                return Err(ConfigError::Invalid(format!(
                    "route {index}: requires an upstream or a root"
                )));
            }
            if has_upstream && has_root {
                return Err(ConfigError::Invalid(format!(
                    "route {index}: cannot set both upstream and root"
                )));
            }
            for upstream in &route.upstream {
                let valid = upstream
                    .trim()
                    .rsplit_once(':')
                    .is_some_and(|(host, port)| !host.is_empty() && port.parse::<u16>().is_ok());
                if !valid {
                    return Err(ConfigError::Invalid(format!(
                        "route {index}: upstream must be `host:port`, got `{upstream}`"
                    )));
                }
            }
            if let Some(path) = &route.path
                && !path.starts_with('/')
            {
                return Err(ConfigError::Invalid(format!(
                    "route {index}: path must start with `/`, got `{path}`"
                )));
            }
            if route.strip_prefix && route.path.is_none() {
                return Err(ConfigError::Invalid(format!(
                    "route {index}: strip_prefix requires a path"
                )));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, ConfigError};

    #[test]
    fn parses_multiple_routes() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [[route]]
            host = "api.example.com"
            path = "/v1"
            upstream = "127.0.0.1:3000"
            [[route]]
            upstream = "127.0.0.1:4000"
            tls = true
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert_eq!(cfg.listen, "0.0.0.0:8080".parse().unwrap());
        assert_eq!(cfg.routes.len(), 2);
        assert_eq!(cfg.routes[0].host.as_deref(), Some("api.example.com"));
        assert_eq!(cfg.routes[0].path.as_deref(), Some("/v1"));
        assert_eq!(cfg.routes[0].upstream, ["127.0.0.1:3000"]);
        assert!(!cfg.routes[0].tls);
        assert_eq!(cfg.routes[1].host, None);
        assert!(cfg.routes[1].tls);
        assert!(cfg.tls.is_none());
    }

    #[test]
    fn parses_tls_section() {
        let toml = r#"
            listen = "0.0.0.0:8443"
            [tls]
            cert = "/etc/zaphyl/cert.pem"
            key = "/etc/zaphyl/key.pem"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        let tls = cfg.tls.expect("tls present");
        assert_eq!(tls.cert, "/etc/zaphyl/cert.pem");
        assert_eq!(tls.key, "/etc/zaphyl/key.pem");
    }

    #[test]
    fn rejects_empty_tls_cert() {
        let toml = r#"
            listen = "0.0.0.0:8443"
            [tls]
            cert = ""
            key = "/etc/zaphyl/key.pem"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn parses_rate_limit() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [rate_limit]
            requests_per_second = 10
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert_eq!(cfg.rate_limit.expect("present").requests_per_second, 10);
    }

    #[test]
    fn rejects_zero_rate_limit() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [rate_limit]
            requests_per_second = 0
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn parses_metrics_section() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [metrics]
            listen = "127.0.0.1:9090"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert_eq!(
            cfg.metrics.expect("metrics present").listen,
            "127.0.0.1:9090".parse().unwrap()
        );
    }

    #[test]
    fn parses_acme_with_defaults() {
        let toml = r#"
            listen = "0.0.0.0:443"
            [acme]
            domains = ["example.com", "www.example.com"]
            email = "admin@example.com"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        let acme = cfg.acme.expect("acme present");
        assert_eq!(acme.domains, ["example.com", "www.example.com"]);
        assert_eq!(acme.email, "admin@example.com");
        assert_eq!(
            acme.directory,
            "https://acme-v02.api.letsencrypt.org/directory"
        );
        assert_eq!(acme.cache_dir, "./acme");
        assert_eq!(acme.renew_before_days, 30);
        assert_eq!(acme.check_interval_seconds, 12 * 60 * 60);
    }

    #[test]
    fn rejects_zero_renew_window() {
        let toml = r#"
            listen = "0.0.0.0:443"
            [acme]
            domains = ["example.com"]
            email = "admin@example.com"
            renew_before_days = 0
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_acme_without_domains() {
        let toml = r#"
            listen = "0.0.0.0:443"
            [acme]
            domains = []
            email = "admin@example.com"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_tls_and_acme_together() {
        let toml = r#"
            listen = "0.0.0.0:443"
            [tls]
            cert = "/c.pem"
            key = "/k.pem"
            [acme]
            domains = ["example.com"]
            email = "admin@example.com"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn parses_list_of_upstreams() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [[route]]
            upstream = ["127.0.0.1:3000", "127.0.0.1:3001"]
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert_eq!(cfg.routes[0].upstream, ["127.0.0.1:3000", "127.0.0.1:3001"]);
    }

    #[test]
    fn parses_http3() {
        let toml = r#"
            listen = "0.0.0.0:443"
            [tls]
            cert = "/c.pem"
            key = "/k.pem"
            [http3]
            listen = "0.0.0.0:443"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert!(cfg.http3.is_some());
    }

    #[test]
    fn parses_http_redirect() {
        let toml = r#"
            listen = "0.0.0.0:443"
            [tls]
            cert = "/c.pem"
            key = "/k.pem"
            [http]
            listen = "0.0.0.0:80"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert_eq!(
            cfg.http.expect("http present").listen,
            "0.0.0.0:80".parse().unwrap()
        );
    }

    #[test]
    fn rejects_http_redirect_without_tls() {
        let toml = r#"
            listen = "0.0.0.0:80"
            [http]
            listen = "0.0.0.0:8080"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_http3_without_tls() {
        let toml = r#"
            listen = "0.0.0.0:443"
            [http3]
            listen = "0.0.0.0:443"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn parses_limits() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [limits]
            max_request_body_bytes = 1048576
            upstream_connect_timeout_seconds = 5
            upstream_read_timeout_seconds = 30
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        let limits = cfg.limits.expect("limits present");
        assert_eq!(limits.max_request_body_bytes, Some(1_048_576));
        assert_eq!(limits.upstream_connect_timeout_seconds, Some(5));
        assert_eq!(limits.upstream_read_timeout_seconds, Some(30));
    }

    #[test]
    fn rejects_zero_timeout() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [limits]
            upstream_read_timeout_seconds = 0
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn parses_cache_with_defaults() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [cache]
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        let cache = cfg.cache.expect("cache present");
        assert_eq!(cache.max_entries, 1024);
        assert_eq!(cache.max_body_bytes, 1024 * 1024);
    }

    #[test]
    fn parses_compression() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [compression]
            level = 6
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert_eq!(cfg.compression.expect("present").level, 6);
    }

    #[test]
    fn rejects_zero_compression_level() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [compression]
            level = 0
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn parses_access() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [access]
            allow = ["10.0.0.0/8"]
            deny = ["10.0.0.5"]
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        let access = cfg.access.expect("access present");
        assert_eq!(access.allow, ["10.0.0.0/8"]);
        assert_eq!(access.deny, ["10.0.0.5"]);
    }

    #[test]
    fn parses_health_check() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [health_check]
            interval_seconds = 5
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert_eq!(cfg.health_check.expect("present").interval_seconds, 5);
    }

    #[test]
    fn parses_response_headers() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [response_headers]
            "X-Zaphyl" = "yes"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert_eq!(
            cfg.response_headers.get("X-Zaphyl").map(String::as_str),
            Some("yes")
        );
    }

    #[test]
    fn rejects_no_routes() {
        let toml = r#"listen = "0.0.0.0:8080""#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_bad_listen() {
        let toml = r#"
            listen = "nope"
            [[route]]
            upstream = "127.0.0.1:3000"
        "#;
        assert!(matches!(Config::from_toml(toml), Err(ConfigError::Toml(_))));
    }

    #[test]
    fn rejects_upstream_without_port() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [[route]]
            upstream = "127.0.0.1"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn parses_per_route_headers() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [[route]]
            upstream = "127.0.0.1:3000"
            [route.request_headers]
            "X-Api-Key" = "secret"
            [route.response_headers]
            "X-Served-By" = "zaphyl"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert_eq!(
            cfg.routes[0]
                .request_headers
                .get("X-Api-Key")
                .map(String::as_str),
            Some("secret")
        );
        assert_eq!(
            cfg.routes[0]
                .response_headers
                .get("X-Served-By")
                .map(String::as_str),
            Some("zaphyl")
        );
    }

    #[test]
    fn parses_static_route() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [[route]]
            path = "/"
            root = "/var/www"
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert_eq!(cfg.routes[0].root.as_deref(), Some("/var/www"));
        assert!(cfg.routes[0].upstream.is_empty());
    }

    #[test]
    fn rejects_route_with_upstream_and_root() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [[route]]
            upstream = "127.0.0.1:3000"
            root = "/var/www"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn parses_plugins() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [plugins]
            global = ["/etc/zaphyl/auth.wasm"]
            [[route]]
            upstream = "127.0.0.1:3000"
            plugins = ["/etc/zaphyl/headers.wasm"]
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        let plugins = cfg.plugins.expect("plugins present");
        assert_eq!(plugins.global, ["/etc/zaphyl/auth.wasm"]);
        assert_eq!(plugins.max_body_bytes, 1024 * 1024);
        assert_eq!(cfg.routes[0].plugins, ["/etc/zaphyl/headers.wasm"]);
    }

    #[test]
    fn parses_grpc_route() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [[route]]
            upstream = "127.0.0.1:50051"
            grpc = true
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert!(cfg.routes[0].grpc);
    }

    #[test]
    fn parses_strip_prefix() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [[route]]
            path = "/api"
            upstream = "127.0.0.1:3000"
            strip_prefix = true
        "#;
        let cfg = Config::from_toml(toml).expect("should parse");
        assert!(cfg.routes[0].strip_prefix);
    }

    #[test]
    fn rejects_strip_prefix_without_path() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [[route]]
            upstream = "127.0.0.1:3000"
            strip_prefix = true
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_path_without_leading_slash() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [[route]]
            path = "v1"
            upstream = "127.0.0.1:3000"
        "#;
        assert!(matches!(
            Config::from_toml(toml),
            Err(ConfigError::Invalid(_))
        ));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let toml = r#"
            listen = "0.0.0.0:8080"
            [[route]]
            upstream = "127.0.0.1:3000"
            bogus = true
        "#;
        assert!(Config::from_toml(toml).is_err());
    }
}
