//! Command-line interface: run the server, or manage sites.

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use zaphyl_config::sites::SiteKind;

#[derive(Parser)]
#[command(name = "zaphyl", version, about = "Reverse proxy and web server")]
pub struct Cli {
    /// Config file to run with (default mode).
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the server (this is also the default with --config).
    Run,
    /// Manage sites.
    #[command(subcommand)]
    Site(SiteCmd),
    /// Apply config changes to the running server.
    Reload,
}

#[derive(Subcommand)]
pub enum SiteCmd {
    /// Add a site for a domain.
    Add {
        domain: String,
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        app: Option<String>,
        #[arg(long)]
        php: bool,
        #[arg(long)]
        r#static: bool,
        #[arg(long)]
        no_tls: bool,
    },
    /// List configured sites.
    List,
    /// Remove a site.
    Remove { domain: String },
    /// Enable a previously disabled site.
    Enable { domain: String },
    /// Disable a site without deleting it.
    Disable { domain: String },
}

/// Detect the kind of site from the directory layout.
///
/// Checks for `composer.json` + `public/` (=> Php serving `<root>/public`)
/// or `index.php` (=> Php), otherwise defaults to Static. Explicit CLI flags
/// override this result at the call site.
pub fn detect_kind(root: &Path) -> SiteKind {
    if root.join("composer.json").exists() && root.join("public").is_dir() {
        return SiteKind::Php;
    }
    if root.join("index.php").exists() {
        return SiteKind::Php;
    }
    SiteKind::Static
}

/// Return true if the domain should be treated as local (no ACME certificate).
///
/// Covers `localhost`, any domain ending with `.local` or `.test`, and any
/// bare IP address (v4 or v6).
pub fn is_local(domain: &str) -> bool {
    if domain == "localhost" {
        return true;
    }
    if domain.ends_with(".local") || domain.ends_with(".test") {
        return true;
    }
    domain.parse::<std::net::IpAddr>().is_ok()
}

/// Serialize a site configuration to TOML that round-trips through
/// `zaphyl_config::sites::SiteConfig::from_toml`.
///
/// Fields are written with the names the deserializer expects (`type`, not
/// `kind`). Optional fields are omitted when absent.
fn write_site_toml(
    domain: &str,
    root: &Path,
    kind: SiteKind,
    tls_off: bool,
    app: Option<&str>,
) -> String {
    let kind_str = match kind {
        SiteKind::Static => "static",
        SiteKind::Php => "php",
        SiteKind::App => "app",
    };
    let tls_str = if tls_off { "off" } else { "auto" };
    let root_str = root.to_string_lossy();

    let mut out = String::new();
    out.push_str(&format!("domain = \"{domain}\"\n"));
    out.push_str(&format!("root = \"{root_str}\"\n"));
    out.push_str(&format!("type = \"{kind_str}\"\n"));
    out.push_str(&format!("tls = \"{tls_str}\"\n"));
    if let Some(upstream) = app {
        out.push_str(&format!("app = \"{upstream}\"\n"));
    }
    out
}

pub fn run_site(cmd: SiteCmd) -> std::process::ExitCode {
    match cmd {
        SiteCmd::Add {
            domain,
            root,
            app,
            php,
            r#static,
            no_tls,
        } => run_site_add(&domain, root, app, php, r#static, no_tls),
        _ => {
            eprintln!("not yet implemented");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run_site_add(
    domain: &str,
    root: Option<PathBuf>,
    app: Option<String>,
    force_php: bool,
    force_static: bool,
    no_tls: bool,
) -> std::process::ExitCode {
    // Resolve the sites directory.
    let sites_dir = std::env::var("ZAPHYL_SITES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/zaphyl/sites"));

    // Resolve the web root: explicit --root, or /var/www/<domain>.
    let webroot_base = std::env::var("ZAPHYL_WEBROOT_BASE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/www"));
    let root = root.unwrap_or_else(|| webroot_base.join(domain));

    // Detect kind; explicit flags win.
    let mut kind = detect_kind(&root);
    if app.is_some() {
        kind = SiteKind::App;
    } else if force_php {
        kind = SiteKind::Php;
    } else if force_static {
        kind = SiteKind::Static;
    }

    // For Php with a public/ subdir present, serve from <root>/public.
    let served_root = if kind == SiteKind::Php && root.join("public").is_dir() {
        root.join("public")
    } else {
        root.clone()
    };

    // Decide TLS.
    let tls_off = no_tls || is_local(domain);

    // Create the web root directory.
    if let Err(e) = std::fs::create_dir_all(&root) {
        eprintln!("zaphyl: could not create web root {}: {e}", root.display());
        return std::process::ExitCode::FAILURE;
    }

    // Write the site file.
    let site_file = sites_dir.join(format!("{domain}.toml"));
    let toml = write_site_toml(domain, &served_root, kind, tls_off, app.as_deref());
    if let Err(e) = std::fs::write(&site_file, &toml) {
        eprintln!("zaphyl: could not write {}: {e}", site_file.display());
        return std::process::ExitCode::FAILURE;
    }

    let scheme = if tls_off { "http" } else { "https" };
    println!("Site added: {domain}");
    println!("  Site file : {}", site_file.display());
    println!("  Web root  : {}", root.display());
    println!("  Kind      : {kind:?}");
    println!("  URL       : {scheme}://{domain}/");

    std::process::ExitCode::SUCCESS
}

pub fn run_reload() -> std::process::ExitCode {
    eprintln!("not yet implemented");
    std::process::ExitCode::FAILURE
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    // --- detect_kind ---

    #[test]
    fn detect_kind_returns_static_for_empty_dir() {
        let tmp = std::env::temp_dir().join("zaphyl-dk-static");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        assert_eq!(detect_kind(&tmp), SiteKind::Static);
    }

    #[test]
    fn detect_kind_returns_php_for_index_php() {
        let tmp = std::env::temp_dir().join("zaphyl-dk-iphp");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("index.php"), b"<?php").unwrap();
        assert_eq!(detect_kind(&tmp), SiteKind::Php);
    }

    #[test]
    fn detect_kind_returns_php_for_composer_and_public() {
        let tmp = std::env::temp_dir().join("zaphyl-dk-composer");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("public")).unwrap();
        std::fs::write(tmp.join("composer.json"), b"{}").unwrap();
        assert_eq!(detect_kind(&tmp), SiteKind::Php);
    }

    #[test]
    fn detect_kind_composer_without_public_is_static() {
        let tmp = std::env::temp_dir().join("zaphyl-dk-comp-nopub");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        std::fs::write(tmp.join("composer.json"), b"{}").unwrap();
        // No public/ subdir -> static.
        assert_eq!(detect_kind(&tmp), SiteKind::Static);
    }

    #[test]
    fn detect_kind_non_existent_root_is_static() {
        assert_eq!(
            detect_kind(Path::new("/nonexistent/path/that/does/not/exist")),
            SiteKind::Static
        );
    }

    // --- is_local ---

    #[test]
    fn is_local_localhost() {
        assert!(is_local("localhost"));
    }

    #[test]
    fn is_local_dot_local() {
        assert!(is_local("mysite.local"));
    }

    #[test]
    fn is_local_dot_test() {
        assert!(is_local("blog.test"));
    }

    #[test]
    fn is_local_ipv4() {
        assert!(is_local("127.0.0.1"));
    }

    #[test]
    fn is_local_ipv6() {
        assert!(is_local("::1"));
    }

    #[test]
    fn is_local_public_domain_is_not_local() {
        assert!(!is_local("example.com"));
    }

    #[test]
    fn is_local_subdomain_of_public_is_not_local() {
        assert!(!is_local("blog.example.com"));
    }

    // --- write_site_toml round-trip ---

    #[test]
    fn static_site_toml_round_trips() {
        use zaphyl_config::sites::{SiteConfig, SiteTls};
        let tmp = std::env::temp_dir().join("zaphyl-toml-static");
        let root = tmp.join("www").join("blog");
        let toml = write_site_toml("blog.test", &root, SiteKind::Static, true, None);
        let parsed = SiteConfig::from_toml(&toml).expect("TOML must round-trip");
        assert_eq!(parsed.domain, "blog.test");
        assert_eq!(parsed.root, root.to_string_lossy());
        assert_eq!(parsed.kind, SiteKind::Static);
        assert_eq!(parsed.tls, SiteTls::Off);
        assert!(parsed.app.is_none());
        assert!(parsed.php_fpm.is_none());
    }

    #[test]
    fn app_site_toml_round_trips() {
        use zaphyl_config::sites::{SiteConfig, SiteTls};
        let root = Path::new("/var/www/myapp");
        let toml = write_site_toml(
            "myapp.example.com",
            root,
            SiteKind::App,
            false,
            Some("http://127.0.0.1:3000"),
        );
        let parsed = SiteConfig::from_toml(&toml).expect("TOML must round-trip");
        assert_eq!(parsed.domain, "myapp.example.com");
        assert_eq!(parsed.kind, SiteKind::App);
        assert_eq!(parsed.tls, SiteTls::Auto);
        assert_eq!(parsed.app.as_deref(), Some("http://127.0.0.1:3000"));
    }

    #[test]
    fn php_site_toml_round_trips() {
        use zaphyl_config::sites::{SiteConfig, SiteTls};
        let root = Path::new("/var/www/phpsite/public");
        let toml = write_site_toml("phpsite.local", root, SiteKind::Php, true, None);
        let parsed = SiteConfig::from_toml(&toml).expect("TOML must round-trip");
        assert_eq!(parsed.kind, SiteKind::Php);
        assert_eq!(parsed.tls, SiteTls::Off);
    }
}
