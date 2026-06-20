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
    /// Print guidance to apply config changes to the running server.
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
        /// Overwrite an existing site file if one already exists.
        #[arg(long)]
        force: bool,
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

/// Escape a string for use inside a TOML basic string (double-quoted).
///
/// Replaces `\` with `\\` and `"` with `\"` so that the emitted TOML is
/// always well-formed regardless of what characters the value contains.
fn toml_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
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
    php_fpm: Option<&str>,
) -> String {
    let kind_str = match kind {
        SiteKind::Static => "static",
        SiteKind::Php => "php",
        SiteKind::App => "app",
    };
    let tls_str = if tls_off { "off" } else { "auto" };
    let root_str = toml_escape(&root.to_string_lossy());
    let domain_str = toml_escape(domain);

    let mut out = String::new();
    out.push_str(&format!("domain = \"{domain_str}\"\n"));
    out.push_str(&format!("root = \"{root_str}\"\n"));
    out.push_str(&format!("type = \"{kind_str}\"\n"));
    out.push_str(&format!("tls = \"{tls_str}\"\n"));
    if let Some(upstream) = app {
        out.push_str(&format!("app = \"{}\"\n", toml_escape(upstream)));
    }
    if let Some(fpm) = php_fpm {
        out.push_str(&format!("php_fpm = \"{}\"\n", toml_escape(fpm)));
    }
    out
}

/// Flags for the `site add` subcommand, gathered in one place so the inner
/// function stays within clippy's argument-count limit.
struct SiteAddOpts {
    root: Option<PathBuf>,
    app: Option<String>,
    force_php: bool,
    force_static: bool,
    no_tls: bool,
    force: bool,
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
            force,
        } => {
            let sites_dir = std::env::var("ZAPHYL_SITES_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/etc/zaphyl/sites"));
            let webroot_base = std::env::var("ZAPHYL_WEBROOT_BASE")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/var/www"));
            let opts = SiteAddOpts {
                root,
                app,
                force_php: php,
                force_static: r#static,
                no_tls,
                force,
            };
            run_site_add_inner(&domain, opts, &sites_dir, &webroot_base)
        }
        SiteCmd::List => run_site_list(),
        SiteCmd::Remove { domain } => run_site_remove(&domain),
        SiteCmd::Enable { domain } => run_site_set_enabled(&domain, true),
        SiteCmd::Disable { domain } => run_site_set_enabled(&domain, false),
    }
}

/// Core logic for `site add`, separated from env-var resolution to allow
/// direct testing without mutating process-global environment.
fn run_site_add_inner(
    domain: &str,
    opts: SiteAddOpts,
    sites_dir: &Path,
    webroot_base: &Path,
) -> std::process::ExitCode {
    let SiteAddOpts {
        root,
        app,
        force_php,
        force_static,
        no_tls,
        force,
    } = opts;
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

    // Ensure the sites directory exists.
    if let Err(e) = std::fs::create_dir_all(sites_dir) {
        eprintln!(
            "zaphyl: could not create sites directory {}: {e}",
            sites_dir.display()
        );
        return std::process::ExitCode::FAILURE;
    }

    // Refuse to overwrite an existing site unless --force was given.
    let site_file = sites_dir.join(format!("{domain}.toml"));
    if site_file.exists() && !force {
        eprintln!(
            "zaphyl: site {domain} already exists at {} (use --force to overwrite)",
            site_file.display()
        );
        return std::process::ExitCode::FAILURE;
    }

    // Create the web root directory.
    if let Err(e) = std::fs::create_dir_all(&root) {
        eprintln!("zaphyl: could not create web root {}: {e}", root.display());
        return std::process::ExitCode::FAILURE;
    }

    // Write the site file.
    let toml = write_site_toml(domain, &served_root, kind, tls_off, app.as_deref(), None);
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
    if !tls_off {
        println!(
            "  Note: for automatic HTTPS, ensure the main config listens on 443 with [acme] and 80 for redirects"
        );
    }

    std::process::ExitCode::SUCCESS
}

fn sites_dir() -> PathBuf {
    std::env::var("ZAPHYL_SITES_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/etc/zaphyl/sites"))
}

fn run_site_list() -> std::process::ExitCode {
    let dir = sites_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) => {
            eprintln!("zaphyl: cannot read sites directory {}: {e}", dir.display());
            return std::process::ExitCode::FAILURE;
        }
    };

    let mut paths: Vec<_> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "toml"))
        .collect();
    paths.sort();

    for path in paths {
        let body = match std::fs::read_to_string(&path) {
            Ok(b) => b,
            Err(e) => {
                eprintln!("zaphyl: cannot read {}: {e}", path.display());
                continue;
            }
        };
        let site = match zaphyl_config::sites::SiteConfig::from_toml(&body) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("zaphyl: cannot parse {}: {e}", path.display());
                continue;
            }
        };
        let kind_str = match site.kind {
            zaphyl_config::sites::SiteKind::Static => "static",
            zaphyl_config::sites::SiteKind::Php => "php",
            zaphyl_config::sites::SiteKind::App => "app",
        };
        let status = if site.enabled { "enabled" } else { "DISABLED" };
        println!("{} [{}] ({})", site.domain, kind_str, status);
    }
    std::process::ExitCode::SUCCESS
}

fn run_site_remove(domain: &str) -> std::process::ExitCode {
    let dir = sites_dir();
    let path = dir.join(format!("{domain}.toml"));
    if !path.exists() {
        eprintln!(
            "zaphyl: site file not found: {} (no site named '{domain}')",
            path.display()
        );
        return std::process::ExitCode::FAILURE;
    }
    if let Err(e) = std::fs::remove_file(&path) {
        eprintln!("zaphyl: could not remove {}: {e}", path.display());
        return std::process::ExitCode::FAILURE;
    }
    println!("Removed site: {domain}");
    std::process::ExitCode::SUCCESS
}

fn run_site_set_enabled(domain: &str, enabled: bool) -> std::process::ExitCode {
    let dir = sites_dir();
    let path = dir.join(format!("{domain}.toml"));
    let body = match std::fs::read_to_string(&path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("zaphyl: cannot read {}: {e}", path.display());
            return std::process::ExitCode::FAILURE;
        }
    };
    let site = match zaphyl_config::sites::SiteConfig::from_toml(&body) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("zaphyl: cannot parse {}: {e}", path.display());
            return std::process::ExitCode::FAILURE;
        }
    };

    let tls_off = matches!(site.tls, zaphyl_config::sites::SiteTls::Off);
    let mut new_toml = write_site_toml(
        &site.domain,
        std::path::Path::new(&site.root),
        site.kind,
        tls_off,
        site.app.as_deref(),
        site.php_fpm.as_deref(),
    );
    new_toml.push_str(&format!("enabled = {enabled}\n"));

    if let Err(e) = std::fs::write(&path, &new_toml) {
        eprintln!("zaphyl: could not write {}: {e}", path.display());
        return std::process::ExitCode::FAILURE;
    }
    let action = if enabled { "enabled" } else { "disabled" };
    println!("Site {action}: {domain}");
    std::process::ExitCode::SUCCESS
}

/// Print guidance to restart the service so that site changes take effect.
///
/// Phase 1 has no config hot-reload: the server does not install a SIGHUP
/// handler and the service unit has no ExecReload. Instructing the operator
/// to restart is the honest and safe action in all environments.
pub fn run_reload() -> std::process::ExitCode {
    if std::path::Path::new("/run/systemd/system").exists() {
        println!("Run: systemctl restart zaphyl to apply site changes");
    } else {
        println!("Restart Zaphyl to apply site changes (e.g. systemctl restart zaphyl)");
    }
    std::process::ExitCode::SUCCESS
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

    // --- toml_escape ---

    #[test]
    fn toml_escape_plain_string_unchanged() {
        assert_eq!(toml_escape("hello/world"), "hello/world");
    }

    #[test]
    fn toml_escape_backslash_is_doubled() {
        assert_eq!(toml_escape(r"C:\path\to"), r"C:\\path\\to");
    }

    #[test]
    fn toml_escape_double_quote_is_escaped() {
        assert_eq!(toml_escape(r#"say "hi""#), r#"say \"hi\""#);
    }

    #[test]
    fn toml_escape_both_special_chars() {
        assert_eq!(toml_escape(r#"C:\say "hi""#), r#"C:\\say \"hi\""#);
    }

    // --- write_site_toml round-trip ---

    #[test]
    fn static_site_toml_round_trips() {
        use zaphyl_config::sites::{SiteConfig, SiteTls};
        let tmp = std::env::temp_dir().join("zaphyl-toml-static");
        let root = tmp.join("www").join("blog");
        let toml = write_site_toml("blog.test", &root, SiteKind::Static, true, None, None);
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
            None,
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
        let toml = write_site_toml("phpsite.local", root, SiteKind::Php, true, None, None);
        let parsed = SiteConfig::from_toml(&toml).expect("TOML must round-trip");
        assert_eq!(parsed.kind, SiteKind::Php);
        assert_eq!(parsed.tls, SiteTls::Off);
    }

    // --- FIX 4: TOML escape round-trip with special characters ---

    #[test]
    fn toml_escape_in_root_with_backslash_and_quote_round_trips() {
        use zaphyl_config::sites::SiteConfig;
        // A root path containing both a backslash and a double-quote - this is
        // the exact case that produces malformed TOML without escaping.
        let tricky_root = Path::new("/var/www/say\"hello\\world");
        let toml = write_site_toml(
            "escape.test",
            tricky_root,
            SiteKind::Static,
            true,
            None,
            None,
        );
        let parsed = SiteConfig::from_toml(&toml)
            .expect("TOML with special chars in root must still round-trip");
        assert_eq!(
            parsed.root,
            tricky_root.to_string_lossy().as_ref(),
            "root must survive the TOML round-trip unchanged"
        );
        assert_eq!(parsed.domain, "escape.test");
    }

    #[test]
    fn toml_escape_in_app_with_special_chars_round_trips() {
        use zaphyl_config::sites::SiteConfig;
        let root = Path::new("/var/www/app");
        // An app upstream containing a double-quote (unusual but must not break TOML).
        let upstream = "http://127.0.0.1:3000/path?a=\"b\"";
        let toml = write_site_toml("app.test", root, SiteKind::App, true, Some(upstream), None);
        let parsed =
            SiteConfig::from_toml(&toml).expect("TOML with special chars in app must round-trip");
        assert_eq!(
            parsed.app.as_deref(),
            Some(upstream),
            "app upstream must survive TOML round-trip unchanged"
        );
    }

    // --- FIX 5: php_fpm preserved through enable/disable rewrite ---

    #[test]
    fn php_fpm_survives_disable_enable_rewrite() {
        use zaphyl_config::sites::{SiteConfig, SiteTls};

        let original_toml = concat!(
            "domain = \"phpsite.local\"\n",
            "root = \"/var/www/php\"\n",
            "type = \"php\"\n",
            "tls = \"off\"\n",
            "php_fpm = \"127.0.0.1:9000\"\n",
        );

        // Parse the original.
        let site = SiteConfig::from_toml(original_toml).expect("original TOML must parse");
        assert_eq!(site.php_fpm.as_deref(), Some("127.0.0.1:9000"));
        assert!(site.enabled, "site should start enabled");

        // Simulate disable: rewrite via write_site_toml then append enabled = false.
        let tls_off = matches!(site.tls, SiteTls::Off);
        let mut disabled_toml = write_site_toml(
            &site.domain,
            Path::new(&site.root),
            site.kind,
            tls_off,
            site.app.as_deref(),
            site.php_fpm.as_deref(),
        );
        disabled_toml.push_str("enabled = false\n");

        let disabled_site =
            SiteConfig::from_toml(&disabled_toml).expect("disabled TOML must parse");
        assert!(!disabled_site.enabled, "site must be disabled");
        assert_eq!(
            disabled_site.php_fpm.as_deref(),
            Some("127.0.0.1:9000"),
            "php_fpm must be preserved after disable rewrite"
        );

        // Simulate enable: rewrite again with enabled = true.
        let mut enabled_toml = write_site_toml(
            &disabled_site.domain,
            Path::new(&disabled_site.root),
            disabled_site.kind,
            matches!(disabled_site.tls, SiteTls::Off),
            disabled_site.app.as_deref(),
            disabled_site.php_fpm.as_deref(),
        );
        enabled_toml.push_str("enabled = true\n");

        let enabled_site = SiteConfig::from_toml(&enabled_toml).expect("enabled TOML must parse");
        assert!(enabled_site.enabled, "site must be enabled again");
        assert_eq!(
            enabled_site.php_fpm.as_deref(),
            Some("127.0.0.1:9000"),
            "php_fpm must be preserved after enable rewrite"
        );
    }

    // --- FIX 1: run_reload always returns SUCCESS ---

    #[test]
    fn run_reload_returns_success() {
        // run_reload now only prints guidance and never calls systemctl,
        // so it must always return SUCCESS regardless of the environment.
        let code = run_reload();
        assert_eq!(
            code,
            std::process::ExitCode::SUCCESS,
            "run_reload must always return SUCCESS"
        );
    }

    // --- FIX 2: site add creates the sites directory if missing ---

    #[test]
    fn site_add_creates_sites_dir_when_missing() {
        // Pick a directory path that does NOT yet exist.
        let base = std::env::temp_dir().join("zaphyl-fix2-sites-missing");
        let _ = std::fs::remove_dir_all(&base);
        // base exists but sites/ inside it does not.
        std::fs::create_dir_all(&base).unwrap();
        let sites_dir = base.join("sites-new");
        let webroot = base.join("www");

        // sites_dir must NOT exist before we call run_site_add_inner.
        assert!(!sites_dir.exists(), "sites_dir must not exist before test");

        let code = run_site_add_inner(
            "missing-dir.test",
            SiteAddOpts {
                root: None,
                app: None,
                force_php: false,
                force_static: false,
                no_tls: true,
                force: false,
            },
            &sites_dir,
            &webroot,
        );

        assert_eq!(
            code,
            std::process::ExitCode::SUCCESS,
            "site add must succeed even when sites dir does not yet exist"
        );
        assert!(
            sites_dir.join("missing-dir.test.toml").exists(),
            "site file must be created inside the newly created sites dir"
        );
    }

    // --- FIX 3: site add refuses to overwrite without --force ---

    #[test]
    fn site_add_refuses_overwrite_without_force() {
        let base = std::env::temp_dir().join("zaphyl-fix3-no-overwrite");
        let _ = std::fs::remove_dir_all(&base);
        let sites_dir = base.join("sites");
        let webroot = base.join("www");
        std::fs::create_dir_all(&sites_dir).unwrap();

        // Write an existing site file with recognisable content.
        let original_content =
            "domain = \"dup.test\"\nroot = \"/original\"\ntype = \"static\"\ntls = \"off\"\n";
        std::fs::write(sites_dir.join("dup.test.toml"), original_content).unwrap();

        // Without --force: must FAIL and leave the original file intact.
        let code_no_force = run_site_add_inner(
            "dup.test",
            SiteAddOpts {
                root: None,
                app: None,
                force_php: false,
                force_static: false,
                no_tls: true,
                force: false,
            },
            &sites_dir,
            &webroot,
        );
        assert_eq!(
            code_no_force,
            std::process::ExitCode::FAILURE,
            "site add without --force must FAIL when site already exists"
        );
        // Original content must still be present.
        let after_no_force = std::fs::read_to_string(sites_dir.join("dup.test.toml")).unwrap();
        assert_eq!(
            after_no_force, original_content,
            "original file must be untouched when --force is absent"
        );

        // With --force: must SUCCEED and overwrite.
        let code_with_force = run_site_add_inner(
            "dup.test",
            SiteAddOpts {
                root: None,
                app: None,
                force_php: false,
                force_static: false,
                no_tls: true,
                force: true,
            },
            &sites_dir,
            &webroot,
        );
        assert_eq!(
            code_with_force,
            std::process::ExitCode::SUCCESS,
            "site add with --force must SUCCEED"
        );
        let after_force = std::fs::read_to_string(sites_dir.join("dup.test.toml")).unwrap();
        assert!(
            !after_force.contains("/original"),
            "after --force the original content must be replaced"
        );
    }

    #[test]
    fn site_add_without_force_leaves_original_file_intact() {
        let base = std::env::temp_dir().join("zaphyl-fix3-original-intact");
        let _ = std::fs::remove_dir_all(&base);
        let sites_dir = base.join("sites");
        let webroot = base.join("www");
        std::fs::create_dir_all(&sites_dir).unwrap();

        let original_content =
            "domain = \"intact.test\"\nroot = \"/untouched\"\ntype = \"static\"\ntls = \"off\"\n";
        std::fs::write(sites_dir.join("intact.test.toml"), original_content).unwrap();

        let code = run_site_add_inner(
            "intact.test",
            SiteAddOpts {
                root: None,
                app: None,
                force_php: false,
                force_static: false,
                no_tls: true,
                force: false,
            },
            &sites_dir,
            &webroot,
        );

        assert_eq!(
            code,
            std::process::ExitCode::FAILURE,
            "must refuse without --force"
        );
        // File must be completely unchanged.
        let after = std::fs::read_to_string(sites_dir.join("intact.test.toml")).unwrap();
        assert_eq!(
            after, original_content,
            "original file must not be touched when --force is absent"
        );
    }
}
