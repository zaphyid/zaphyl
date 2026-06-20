//! End-to-end CLI behaviour via the real binary.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Helpers shared across tests in this file (mirror of proxy.rs patterns).
// ---------------------------------------------------------------------------

/// Kills the spawned child when dropped, even on panic.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Ask the OS for a free TCP port, then release it for the server to claim.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Poll until `port` accepts a TCP connection (or the timeout expires).
fn wait_for_port(port: u16) {
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "port {port} never started listening"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Send a raw HTTP/1.1 GET and return the full response text.
fn raw_http_get(port: u16, host: &str, path: &str) -> String {
    let start = Instant::now();
    let mut stream = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(s) => break s,
            Err(e) => {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "connect {port}: {e}"
                );
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

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

#[test]
fn site_disable_then_list_marks_it_disabled() {
    let base = std::env::temp_dir().join("zaphyl-cli-disable");
    let sites = base.join("sites");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&sites).unwrap();
    std::fs::write(
        sites.join("x.test.toml"),
        "domain = \"x.test\"\nroot = \"/var/www/x\"\ntype = \"static\"\ntls = \"off\"\n",
    )
    .unwrap();

    let run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_zaphyl"))
            .args(args)
            .env("ZAPHYL_SITES_DIR", &sites)
            .output()
            .unwrap()
    };

    assert!(run(&["site", "disable", "x.test"]).status.success());
    let body = std::fs::read_to_string(sites.join("x.test.toml")).unwrap();
    assert!(body.contains("enabled = false"));

    let listed = run(&["site", "list"]);
    let text = String::from_utf8_lossy(&listed.stdout);
    assert!(text.contains("x.test"));
    assert!(text.to_lowercase().contains("disabled"));
}

#[test]
fn added_static_site_is_served() {
    let port = free_port();

    // Set up a temp directory tree:
    //   <base>/zaphyl.toml   -- main config
    //   <base>/sites/        -- site files (read by Config::load)
    //   <base>/www/          -- web root for local.test
    let base = std::env::temp_dir().join(format!("zaphyl-e2e-{port}"));
    let sites_dir = base.join("sites");
    let webroot = base.join("www");
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&sites_dir).unwrap();
    std::fs::create_dir_all(&webroot).unwrap();

    // Write the main config. A catch-all static route is required so that
    // Config::from_toml validation passes (it checks routes.len() > 0).
    // The site file will prepend a host-specific route that matches first.
    let config_path = base.join("zaphyl.toml");
    let config_toml = format!(
        "listen = \"127.0.0.1:{port}\"\n\n[[route]]\nroot = \"{}\"\n",
        webroot.display()
    );
    std::fs::write(&config_path, &config_toml).unwrap();

    // Register the site via the real binary (writes <sites_dir>/local.test.toml).
    let add_out = Command::new(env!("CARGO_BIN_EXE_zaphyl"))
        .args(["site", "add", "local.test", "--root"])
        .arg(&webroot)
        .arg("--no-tls")
        .env("ZAPHYL_SITES_DIR", &sites_dir)
        .output()
        .expect("run site add");
    assert!(
        add_out.status.success(),
        "site add failed: {}",
        String::from_utf8_lossy(&add_out.stderr)
    );

    // Place an index.html in the web root.
    let body = "<h1>served by zaphyl</h1>";
    std::fs::write(webroot.join("index.html"), body).unwrap();

    // Start the server against the config that now includes the site route.
    let child = Command::new(env!("CARGO_BIN_EXE_zaphyl"))
        .arg("--config")
        .arg(&config_path)
        .spawn()
        .expect("failed to spawn zaphyl");
    let _guard = ChildGuard(child);
    wait_for_port(port);

    // A GET with Host: local.test must return 200 and the file body.
    let response = raw_http_get(port, "local.test", "/");
    assert!(
        response.starts_with("HTTP/1.1 200"),
        "expected 200, got:\n{response}"
    );
    assert!(
        response.contains(body),
        "expected file body in response:\n{response}"
    );
}
