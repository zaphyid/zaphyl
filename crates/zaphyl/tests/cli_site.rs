//! End-to-end CLI behaviour via the real binary.

use std::process::Command;

#[test]
fn help_lists_the_site_subcommand() {
    let out = Command::new(env!("CARGO_BIN_EXE_zaphyl"))
        .arg("--help")
        .output()
        .expect("run zaphyl --help");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        text.contains("site"),
        "help should mention the site command:\n{text}"
    );
}

#[test]
fn site_add_writes_a_static_site_file() {
    let base = std::env::temp_dir().join("zaphyl-cli-add");
    let sites = base.join("sites");
    let webroot = base.join("www");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&sites).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_zaphyl"))
        .args(["site", "add", "blog.test", "--root"])
        .arg(webroot.join("blog"))
        .env("ZAPHYL_SITES_DIR", &sites)
        .output()
        .expect("run site add");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let written = std::fs::read_to_string(sites.join("blog.test.toml")).unwrap();
    assert!(written.contains("domain = \"blog.test\""));
    assert!(written.contains("type = \"static\""));
    // ".test" is a local domain -> TLS off.
    assert!(written.contains("tls = \"off\""));
    assert!(webroot.join("blog").is_dir());
}
