//! Loading the main config plus a sites directory.

use std::fs;

#[test]
fn loads_sites_dir_and_prepends_site_routes() {
    let dir = std::env::temp_dir().join("zaphyl-sites-load");
    let sites = dir.join("sites");
    fs::create_dir_all(&sites).unwrap();
    fs::write(
        dir.join("zaphyl.toml"),
        "listen = \"0.0.0.0:80\"\n\n[[route]]\nroot = \"/usr/share/zaphyl/html\"\n",
    )
    .unwrap();
    fs::write(
        sites.join("blog.example.com.toml"),
        "domain = \"blog.example.com\"\nroot = \"/var/www/blog\"\ntype = \"static\"\n",
    )
    .unwrap();

    let cfg = zaphyl_config::Config::load(&dir.join("zaphyl.toml")).unwrap();

    // Site route is first (host-specific wins over the catch-all default).
    assert_eq!(cfg.routes[0].host.as_deref(), Some("blog.example.com"));
    assert_eq!(cfg.routes[0].root.as_deref(), Some("/var/www/blog"));
    // The main catch-all default is still present, last.
    assert_eq!(cfg.routes.last().unwrap().host, None);
}
