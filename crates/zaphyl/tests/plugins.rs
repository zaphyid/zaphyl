//! Integration test: a route with a WASM plugin chain. The sample plugin
//! (`test-plugins/filter`) short-circuits `/blocked` with a `403`, lets other
//! paths through to the upstream, and stamps `x-plugin: ran` on the response.
//!
//! The plugin is a build artifact, so the test skips (with instructions) when it
//! has not been built. CI builds it, so the test runs there. Build locally with:
//!   cd test-plugins/filter && cargo component build --release

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Kills the spawned proxy when the test ends, even on panic.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Start a dummy upstream that always replies with `body`. Returns its address.
fn spawn_upstream(body: &'static str) -> SocketAddr {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let _ = request.respond(tiny_http::Response::from_string(body));
        }
    });
    addr
}

/// The compiled sample plugin component, or `None` if it has not been built.
fn sample_plugin() -> Option<PathBuf> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-plugins/filter/target/wasm32-wasip1/release/zaphyl_test_filter.wasm");
    path.exists().then_some(path)
}

fn spawn_proxy(config: &str, port: u16) -> ChildGuard {
    let dir = std::env::temp_dir().join(format!("zaphyl-plugins-it-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("zaphyl.toml");
    std::fs::write(&config_path, config).unwrap();

    let child = Command::new(env!("CARGO_BIN_EXE_zaphyl"))
        .arg("--config")
        .arg(&config_path)
        .spawn()
        .expect("failed to spawn zaphyl");
    let guard = ChildGuard(child);

    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "proxy port {port} never started listening"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    guard
}

/// Send a raw HTTP/1.1 GET through the proxy and return the full response text.
fn http_get(port: u16, path: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let request = format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
}

#[test]
fn plugin_chain_blocks_and_stamps() {
    let Some(plugin) = sample_plugin() else {
        eprintln!(
            "skipping plugin_chain_blocks_and_stamps: build the sample plugin first \
             (cd test-plugins/filter && cargo component build --release)"
        );
        return;
    };

    let port = free_port();
    let upstream = spawn_upstream("hello from upstream");
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [[route]]\npath = \"/\"\nupstream = \"{upstream}\"\nplugins = [\"{}\"]\n",
        plugin.to_string_lossy().replace('\\', "/")
    );
    let _proxy = spawn_proxy(&config, port);

    // The plugin short-circuits `/blocked` with a 403 (no upstream hit).
    let blocked = http_get(port, "/blocked");
    assert!(
        blocked.starts_with("HTTP/1.1 403"),
        "expected 403 for /blocked, got:\n{blocked}"
    );

    // Other paths reach the upstream and come back stamped by the plugin.
    let allowed = http_get(port, "/allowed");
    assert!(
        allowed.starts_with("HTTP/1.1 200"),
        "expected 200 for /allowed, got:\n{allowed}"
    );
    assert!(
        allowed.to_ascii_lowercase().contains("x-plugin: ran"),
        "expected x-plugin header, got:\n{allowed}"
    );
    assert!(
        allowed.contains("hello from upstream"),
        "expected upstream body, got:\n{allowed}"
    );
}
