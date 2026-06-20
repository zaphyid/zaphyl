//! A single managed site (one file under the sites directory), expanded into a
//! route plus optional ACME domain by the config loader.

use serde::Deserialize;

use crate::ConfigError;

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
}
