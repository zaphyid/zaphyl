//! A single managed site (one file under the sites directory), expanded into a
//! route plus optional ACME domain by the config loader.

use std::collections::HashMap;

use serde::Deserialize;

use crate::ConfigError;
use crate::RouteConfig;

/// How a site's requests are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SiteKind {
    /// Serve files directly from the document root.
    Static,
    /// Forward requests to a php-fpm process.
    Php,
    /// Reverse-proxy to an upstream HTTP application.
    App,
}

/// Whether a site gets an automatic certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum SiteTls {
    /// Obtain and renew a certificate automatically via ACME.
    #[default]
    Auto,
    /// Do not obtain a certificate - serve plain HTTP only.
    Off,
}

fn default_enabled() -> bool {
    true
}

/// One managed site.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    /// The host this site answers for.
    pub domain: String,
    /// The document root on disk.
    pub root: String,
    /// How requests are served.
    #[serde(rename = "type")]
    pub kind: SiteKind,
    /// Whether to obtain a certificate automatically.
    #[serde(default)]
    pub tls: SiteTls,
    /// Upstream HTTP app, required when `type = "app"`.
    #[serde(default)]
    pub app: Option<String>,
    /// php-fpm address, used when `type = "php"`.
    #[serde(default)]
    pub php_fpm: Option<String>,
    /// Whether this site contributes routes.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

impl SiteConfig {
    /// Parse one site file.
    ///
    /// # Errors
    /// Fails if the TOML is malformed or a required field is missing.
    pub fn from_toml(input: &str) -> Result<SiteConfig, ConfigError> {
        toml::from_str(input).map_err(ConfigError::Toml)
    }

    /// The route this site contributes, or `None` when disabled.
    #[must_use]
    pub fn to_route(&self) -> Option<RouteConfig> {
        if !self.enabled {
            return None;
        }
        let upstream = match (self.kind, &self.app) {
            (SiteKind::App, Some(app)) => vec![app.clone()],
            _ => Vec::new(),
        };
        Some(RouteConfig {
            host: Some(self.domain.clone()),
            path: None,
            upstream,
            root: Some(self.root.clone()),
            tls: false,
            strip_prefix: false,
            request_headers: HashMap::new(),
            response_headers: HashMap::new(),
            grpc: false,
            plugins: Vec::new(),
        })
    }

    /// The domain needing an automatic certificate, if any.
    #[must_use]
    pub fn tls_domain(&self) -> Option<&str> {
        if !self.enabled {
            return None;
        }
        match self.tls {
            SiteTls::Auto => Some(&self.domain),
            SiteTls::Off => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_static_site() {
        let site = SiteConfig::from_toml(
            "domain = \"blog.example.com\"\nroot = \"/var/www/blog\"\ntype = \"static\"\n",
        )
        .unwrap();
        assert_eq!(site.domain, "blog.example.com");
        assert_eq!(site.root, "/var/www/blog");
        assert_eq!(site.kind, SiteKind::Static);
        assert_eq!(site.tls, SiteTls::Auto);
        assert!(site.enabled);
    }

    #[test]
    fn static_site_expands_to_a_static_route() {
        let site = SiteConfig::from_toml(
            "domain = \"blog.example.com\"\nroot = \"/var/www/blog\"\ntype = \"static\"\n",
        )
        .unwrap();
        let route = site.to_route().expect("enabled site yields a route");
        assert_eq!(route.host.as_deref(), Some("blog.example.com"));
        assert_eq!(route.root.as_deref(), Some("/var/www/blog"));
        assert!(route.upstream.is_empty());
        assert_eq!(site.tls_domain(), Some("blog.example.com"));
    }

    #[test]
    fn app_site_expands_to_static_plus_upstream() {
        let site = SiteConfig::from_toml(
            "domain = \"app.example.com\"\nroot = \"/var/www/app\"\ntype = \"app\"\napp = \"http://127.0.0.1:8000\"\n",
        )
        .unwrap();
        let route = site.to_route().unwrap();
        assert_eq!(route.host.as_deref(), Some("app.example.com"));
        assert_eq!(route.root.as_deref(), Some("/var/www/app"));
        assert_eq!(route.upstream, vec!["http://127.0.0.1:8000".to_owned()]);
    }

    #[test]
    fn disabled_site_yields_no_route() {
        let site = SiteConfig::from_toml(
            "domain = \"x.example.com\"\nroot = \"/var/www/x\"\ntype = \"static\"\nenabled = false\n",
        )
        .unwrap();
        assert!(site.to_route().is_none());
        assert_eq!(site.tls_domain(), None);
    }
}
