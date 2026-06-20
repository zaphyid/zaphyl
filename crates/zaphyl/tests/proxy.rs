//! Integration tests: run the real `zaphyl` binary in front of dummy upstreams
//! and confirm requests are proxied, routed, and (over TLS) terminated.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Kills the spawned proxy when the test ends, even on panic.
struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Ask the OS for a free TCP port, then release it for the proxy to claim.
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

/// Start an upstream that echoes the request headers it received in the body.
fn spawn_echo_upstream() -> SocketAddr {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let dump = request
                .headers()
                .iter()
                .map(|h| format!("{}: {}", h.field, h.value))
                .collect::<Vec<_>>()
                .join("\n");
            let _ = request.respond(tiny_http::Response::from_string(dump));
        }
    });
    addr
}

/// Start an upstream that echoes back the request path (and query) it received.
fn spawn_path_echo_upstream() -> SocketAddr {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let path = request.url().to_owned();
            let _ = request.respond(tiny_http::Response::from_string(path));
        }
    });
    addr
}

/// Start an upstream that replies with a large, compressible body.
fn spawn_large_upstream() -> SocketAddr {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let body = "zaphyl ".repeat(1000);
            let _ = request.respond(tiny_http::Response::from_string(body));
        }
    });
    addr
}

/// Start an upstream that accepts connections but never replies (to trigger an
/// upstream read timeout).
fn spawn_silent_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        // Hold every accepted connection open without ever responding.
        let mut held = Vec::new();
        for stream in listener.incoming().flatten() {
            held.push(stream);
        }
    });
    addr
}

/// Start an upstream that numbers each response and sets the given
/// `Cache-Control` (and optional `Vary`), so callers can tell a cached reply
/// from a fresh one.
fn spawn_counting_upstream(cache_control: &'static str, vary: Option<&'static str>) -> SocketAddr {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    std::thread::spawn(move || {
        let mut n = 0;
        for request in server.incoming_requests() {
            n += 1;
            let mut response = tiny_http::Response::from_string(format!("response {n}"))
                .with_header(
                    tiny_http::Header::from_bytes("Cache-Control", cache_control).unwrap(),
                );
            if let Some(vary) = vary {
                response.add_header(tiny_http::Header::from_bytes("Vary", vary).unwrap());
            }
            let _ = request.respond(response);
        }
    });
    addr
}

/// Start an upstream that returns `304` to a matching `If-None-Match: "v1"`, and
/// otherwise a numbered body with `ETag: "v1"` and a 1-second freshness.
fn spawn_revalidating_upstream() -> SocketAddr {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    std::thread::spawn(move || {
        let mut n = 0;
        for request in server.incoming_requests() {
            let inm = request
                .headers()
                .iter()
                .find(|h| {
                    h.field
                        .as_str()
                        .as_str()
                        .eq_ignore_ascii_case("if-none-match")
                })
                .map(|h| h.value.as_str().to_owned());
            if inm.as_deref() == Some("\"v1\"") {
                let _ = request.respond(tiny_http::Response::empty(304));
            } else {
                n += 1;
                let response = tiny_http::Response::from_string(format!("response {n}"))
                    .with_header(
                        tiny_http::Header::from_bytes("Cache-Control", "max-age=1").unwrap(),
                    )
                    .with_header(tiny_http::Header::from_bytes("ETag", "\"v1\"").unwrap());
                let _ = request.respond(response);
            }
        }
    });
    addr
}

/// Write the config, spawn `zaphyl`, and wait until it is listening.
fn spawn_proxy(config: &str, port: u16) -> ChildGuard {
    let dir = std::env::temp_dir().join(format!("zaphyl-it-{port}"));
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

/// Generate a self-signed cert + key for `localhost` and write them as PEM.
fn write_self_signed(dir: &Path) -> (PathBuf, PathBuf) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    (cert_path, key_path)
}

/// Generate a fresh self-signed cert + key for `localhost`, write them to the
/// given paths, and return the certificate PEM (usable as a `--cacert` root).
fn generate_localhost_cert(cert_path: &Path, key_path: &Path) -> String {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_pem = cert.pem();
    std::fs::write(cert_path, &cert_pem).unwrap();
    std::fs::write(key_path, signing_key.serialize_pem()).unwrap();
    cert_pem
}

/// HTTPS GET that *verifies* the server certificate against `ca` (no `-k`).
/// Returns whether curl trusted the presented certificate.
fn https_trusts(port: u16, ca: &Path) -> bool {
    Command::new("curl")
        .args([
            "-s",
            "--max-time",
            "10",
            "--cacert",
            &ca.to_string_lossy(),
            "--resolve",
            &format!("localhost:{port}:127.0.0.1"),
            &format!("https://localhost:{port}/"),
        ])
        .status()
        .expect("failed to run curl")
        .success()
}

/// Send a raw HTTP/1.1 GET through the proxy and return the full response text.
fn http_get(port: u16, host: &str, path: &str) -> String {
    // Retry the connect: under heavy parallel load a freshly-bound listener can
    // briefly refuse connections.
    let start = Instant::now();
    let mut stream = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
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

/// Send an HTTP/1.1 GET with one extra request header line.
fn http_get_with_header(port: u16, path: &str, header_line: &str) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\n{header_line}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
}

/// Send an HTTP/1.1 POST with `body` and return the full response text.
fn http_post(port: u16, path: &str, body: &str) -> String {
    let start = Instant::now();
    let mut stream = loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => break stream,
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
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    let _ = stream.read_to_string(&mut response);
    response
}

/// Same as `http_get`, but over TLS. Uses the system `curl -k` so we don't pull
/// a second TLS stack into a test binary that already links BoringSSL via
/// Pingora (the `openssl`/`native-tls` route fails to link against BoringSSL).
fn https_get(port: u16, path: &str) -> String {
    let url = format!("https://127.0.0.1:{port}{path}");
    let output = Command::new("curl")
        .args(["-sk", "--max-time", "10", &url])
        .output()
        .expect("failed to run curl");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn forwards_request_to_upstream() {
    let upstream = spawn_upstream("hello from upstream");
    let port = free_port();
    let config = format!("listen = \"127.0.0.1:{port}\"\n\n[[route]]\nupstream = \"{upstream}\"\n");
    let _proxy = spawn_proxy(&config, port);

    let response = http_get(port, "localhost", "/");
    assert!(
        response.contains("hello from upstream"),
        "response was:\n{response}"
    );
}

#[test]
fn strips_path_prefix_before_forwarding() {
    let upstream = spawn_path_echo_upstream();
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [[route]]\npath = \"/api\"\nupstream = \"{upstream}\"\nstrip_prefix = true\n"
    );
    let _proxy = spawn_proxy(&config, port);

    // `/api/users?x=1` reaches the upstream as `/users?x=1`.
    let response = http_get(port, "localhost", "/api/users?x=1");
    assert!(
        response.contains("/users?x=1"),
        "expected stripped path, got:\n{response}"
    );
}

#[test]
fn caches_cacheable_responses() {
    let upstream = spawn_counting_upstream("max-age=60", None);
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n[cache]\n\n[[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    assert!(http_get(port, "localhost", "/thing").contains("response 1"));
    // The second request is served from cache: same body, X-Cache: HIT.
    let second = http_get(port, "localhost", "/thing").to_lowercase();
    assert!(
        second.contains("response 1"),
        "expected cached body:\n{second}"
    );
    assert!(
        second.contains("x-cache: hit"),
        "expected cache hit:\n{second}"
    );
}

#[test]
fn does_not_cache_no_store_responses() {
    let upstream = spawn_counting_upstream("no-store", None);
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n[cache]\n\n[[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    assert!(http_get(port, "localhost", "/x").contains("response 1"));
    // Not cacheable: the second request reaches the upstream again.
    assert!(http_get(port, "localhost", "/x").contains("response 2"));
}

#[test]
fn returns_304_for_matching_if_none_match() {
    // Upstream that sets an ETag and is cacheable.
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let upstream = server.server_addr().to_ip().unwrap();
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let response = tiny_http::Response::from_string("the body")
                .with_header(tiny_http::Header::from_bytes("Cache-Control", "max-age=60").unwrap())
                .with_header(tiny_http::Header::from_bytes("ETag", "\"v1\"").unwrap());
            let _ = request.respond(response);
        }
    });

    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n[cache]\n\n[[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    // Populate the cache.
    assert!(http_get(port, "localhost", "/r").contains("the body"));
    // A matching If-None-Match gets a bodyless 304.
    let revalidated = http_get_with_header(port, "/r", "If-None-Match: \"v1\"");
    assert!(
        revalidated.contains("304"),
        "expected 304, got:\n{revalidated}"
    );
    assert!(
        !revalidated.contains("the body"),
        "304 must not include a body:\n{revalidated}"
    );
}

#[test]
fn cache_persists_to_disk_across_restart() {
    let upstream = spawn_counting_upstream("max-age=60", None);
    let disk = std::env::temp_dir().join(format!("zaphyl-diskcache-{}", free_port()));
    let _ = std::fs::remove_dir_all(&disk);

    // First proxy caches the response to disk, then is shut down.
    let port1 = free_port();
    let config1 = format!(
        "listen = \"127.0.0.1:{port1}\"\n\n\
         [cache]\ndisk_path = \"{}\"\n\n\
         [[route]]\nupstream = \"{upstream}\"\n",
        disk.display()
    );
    {
        let _proxy = spawn_proxy(&config1, port1);
        assert!(http_get(port1, "localhost", "/d").contains("response 1"));
    }

    // A fresh proxy with a cold memory cache but the same disk directory serves
    // the persisted entry instead of hitting the upstream (which would count 2).
    let port2 = free_port();
    let config2 = format!(
        "listen = \"127.0.0.1:{port2}\"\n\n\
         [cache]\ndisk_path = \"{}\"\n\n\
         [[route]]\nupstream = \"{upstream}\"\n",
        disk.display()
    );
    let _proxy2 = spawn_proxy(&config2, port2);
    assert!(
        http_get(port2, "localhost", "/d").contains("response 1"),
        "expected the response to be served from the disk cache"
    );
}

#[test]
fn revalidates_stale_entry_with_origin() {
    let upstream = spawn_revalidating_upstream();
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n[cache]\n\n[[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    // Populate the cache (fresh for 1 second).
    assert!(http_get(port, "localhost", "/r").contains("response 1"));
    // Let it go stale, then request again: the proxy revalidates and the origin
    // replies 304, so the cached body is served - not a fresh "response 2".
    std::thread::sleep(Duration::from_millis(1500));
    let revalidated = http_get(port, "localhost", "/r");
    assert!(
        revalidated.contains("response 1"),
        "revalidation should serve the cached body, got:\n{revalidated}"
    );
}

#[test]
fn does_not_cache_unsupported_vary() {
    // Vary on something other than Accept-Encoding must not be cached, or the
    // wrong variant could be served.
    let upstream = spawn_counting_upstream("max-age=60", Some("Accept-Language"));
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n[cache]\n\n[[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    assert!(http_get(port, "localhost", "/v").contains("response 1"));
    assert!(http_get(port, "localhost", "/v").contains("response 2"));
}

#[test]
fn serves_static_files() {
    let www = std::env::temp_dir().join(format!("zaphyl-www-{}", free_port()));
    std::fs::create_dir_all(&www).unwrap();
    std::fs::write(www.join("index.html"), "<h1>home</h1>").unwrap();
    std::fs::write(www.join("app.css"), "body{color:red}").unwrap();
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n[[route]]\npath = \"/\"\nroot = \"{}\"\n",
        www.display()
    );
    let _proxy = spawn_proxy(&config, port);

    // `/` serves index.html.
    assert!(http_get(port, "localhost", "/").contains("<h1>home</h1>"));

    // A CSS file is served with the right Content-Type.
    let css = http_get(port, "localhost", "/app.css").to_lowercase();
    assert!(
        css.contains("content-type: text/css"),
        "css headers:\n{css}"
    );
    assert!(css.contains("body{color:red}"));

    // Missing file and path traversal both 404.
    assert!(http_get(port, "localhost", "/nope.txt").contains("404"));
    assert!(http_get(port, "localhost", "/../proxy.rs").contains("404"));
}

#[test]
fn routes_by_host() {
    let api = spawn_upstream("from-api");
    let web = spawn_upstream("from-web");
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [[route]]\nhost = \"api.local\"\nupstream = \"{api}\"\n\n\
         [[route]]\nhost = \"web.local\"\nupstream = \"{web}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    assert!(http_get(port, "api.local", "/").contains("from-api"));
    assert!(http_get(port, "web.local", "/").contains("from-web"));
}

#[test]
fn logs_requests_to_stdout() {
    let upstream = spawn_upstream("logged response");
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("zaphyl-log-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("zaphyl.toml");
    std::fs::write(
        &config_path,
        format!("listen = \"127.0.0.1:{port}\"\n\n[[route]]\nupstream = \"{upstream}\"\n"),
    )
    .unwrap();

    let log_path = dir.join("stdout.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_zaphyl"))
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::from(log))
        .spawn()
        .expect("failed to spawn zaphyl");
    let _guard = ChildGuard(child);

    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "proxy port {port} never started listening"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    let _ = http_get(port, "localhost", "/hello");
    std::thread::sleep(Duration::from_millis(300)); // let the log line flush

    let logs = std::fs::read_to_string(&log_path).unwrap();
    assert!(logs.contains("status=200"), "logs were:\n{logs}");
    assert!(logs.contains("path=/hello"), "logs were:\n{logs}");
}

#[test]
fn exposes_prometheus_metrics() {
    let upstream = spawn_upstream("ok");
    let port = free_port();
    let metrics_port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [metrics]\nlisten = \"127.0.0.1:{metrics_port}\"\n\n\
         [[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    // Wait for the metrics listener to come up too.
    let start = Instant::now();
    while TcpStream::connect(("127.0.0.1", metrics_port)).is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "metrics port {metrics_port} never started listening"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // Drive a request so a metric is recorded, then scrape.
    let _ = http_get(port, "localhost", "/");
    std::thread::sleep(Duration::from_millis(200));

    let metrics = http_get(metrics_port, "localhost", "/metrics");
    assert!(
        metrics.contains("zaphyl_requests_total"),
        "metrics were:\n{metrics}"
    );
}

#[test]
fn rate_limits_bursts_with_429() {
    let upstream = spawn_upstream("ok");
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [rate_limit]\nrequests_per_second = 3\n\n\
         [[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    // Eight quick requests from the same client; with a limit of 3/s, several
    // should be rejected with 429.
    let limited = (0..8)
        .filter(|_| http_get(port, "localhost", "/").contains("429"))
        .count();
    assert!(
        limited > 0,
        "expected some requests to be rate-limited (429)"
    );
}

#[test]
fn denies_blocked_ip_with_403() {
    let upstream = spawn_upstream("ok");
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [access]\ndeny = [\"127.0.0.1\"]\n\n\
         [[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    let response = http_get(port, "localhost", "/");
    assert!(response.contains("403"), "expected 403, got:\n{response}");
}

#[test]
fn allow_list_blocks_unlisted_ip() {
    let upstream = spawn_upstream("ok");

    // 127.0.0.1 is on the allow list -> served.
    let port = free_port();
    let allowed = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [access]\nallow = [\"127.0.0.1\"]\n\n\
         [[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&allowed, port);
    assert!(http_get(port, "localhost", "/").contains("ok"));

    // A different allow list excludes 127.0.0.1 -> 403.
    let port2 = free_port();
    let blocked = format!(
        "listen = \"127.0.0.1:{port2}\"\n\n\
         [access]\nallow = [\"10.0.0.0/8\"]\n\n\
         [[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy2 = spawn_proxy(&blocked, port2);
    assert!(http_get(port2, "localhost", "/").contains("403"));
}

#[test]
fn rejects_oversized_body_with_413() {
    let upstream = spawn_upstream("ok");
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [limits]\nmax_request_body_bytes = 10\n\n\
         [[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    // A 100-byte body exceeds the 10-byte limit.
    let response = http_post(port, "/", &"x".repeat(100));
    assert!(response.contains("413"), "expected 413, got:\n{response}");

    // A small body is forwarded normally.
    let ok = http_post(port, "/", "tiny");
    assert!(ok.contains("ok"), "small body should pass, got:\n{ok}");
}

#[test]
fn upstream_read_timeout_returns_504() {
    let upstream = spawn_silent_upstream();
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [limits]\nupstream_read_timeout_seconds = 1\n\n\
         [[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    // The upstream never responds; the proxy gives up after ~1s with a 504.
    let response = http_get(port, "localhost", "/");
    assert!(response.contains("504"), "expected 504, got:\n{response}");
}

#[test]
fn load_balances_round_robin() {
    let a = spawn_upstream("from-a");
    let b = spawn_upstream("from-b");
    let port = free_port();
    let config =
        format!("listen = \"127.0.0.1:{port}\"\n\n[[route]]\nupstream = [\"{a}\", \"{b}\"]\n");
    let _proxy = spawn_proxy(&config, port);

    let mut seen_a = false;
    let mut seen_b = false;
    for _ in 0..6 {
        let body = http_get(port, "localhost", "/");
        seen_a |= body.contains("from-a");
        seen_b |= body.contains("from-b");
    }
    assert!(seen_a && seen_b, "expected both upstreams to be used");
}

#[test]
fn compresses_response_when_requested() {
    let upstream = spawn_large_upstream();
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [compression]\nlevel = 6\n\n\
         [[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    // A gzip-capable client gets a gzip-encoded response.
    let output = Command::new("curl")
        .args([
            "-si",
            "--max-time",
            "10",
            "-H",
            "Accept-Encoding: gzip",
            &format!("http://127.0.0.1:{port}/"),
        ])
        .output()
        .expect("run curl");
    let response = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(
        response.contains("content-encoding: gzip"),
        "expected gzip encoding, got headers:\n{}",
        response.lines().take(15).collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn adds_configured_response_headers() {
    let upstream = spawn_upstream("ok");
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [response_headers]\n\"X-Zaphyl\" = \"yes\"\n\n\
         [[route]]\nupstream = \"{upstream}\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    let response = http_get(port, "localhost", "/").to_lowercase();
    assert!(response.contains("x-zaphyl"), "response:\n{response}");
    assert!(response.contains("yes"), "response:\n{response}");
}

#[test]
fn injects_per_route_headers() {
    let upstream = spawn_echo_upstream();
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [[route]]\nupstream = \"{upstream}\"\n\
         [route.request_headers]\n\"X-Api-Key\" = \"secret\"\n\
         [route.response_headers]\n\"X-Served-By\" = \"zaphyl\"\n"
    );
    let _proxy = spawn_proxy(&config, port);

    let response = http_get(port, "localhost", "/");
    let lower = response.to_lowercase();
    // The upstream (echo) saw the injected request header.
    assert!(
        lower.contains("x-api-key: secret"),
        "request header missing:\n{response}"
    );
    // The client sees the injected response header.
    assert!(
        lower.contains("x-served-by: zaphyl"),
        "response header missing:\n{response}"
    );
}

#[test]
fn forwards_client_info_to_upstream() {
    let upstream = spawn_echo_upstream();
    let port = free_port();
    let config = format!("listen = \"127.0.0.1:{port}\"\n\n[[route]]\nupstream = \"{upstream}\"\n");
    let _proxy = spawn_proxy(&config, port);

    let response = http_get(port, "localhost", "/").to_lowercase();
    assert!(
        response.contains("x-forwarded-for"),
        "response:\n{response}"
    );
    assert!(response.contains("127.0.0.1"), "response:\n{response}");
    assert!(
        response.contains("x-forwarded-proto: http"),
        "response:\n{response}"
    );
}

#[test]
fn health_check_skips_dead_upstream() {
    let live = spawn_upstream("alive");
    let dead = free_port(); // nothing is listening here
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [health_check]\ninterval_seconds = 1\n\n\
         [[route]]\nupstream = [\"{live}\", \"127.0.0.1:{dead}\"]\n"
    );
    let _proxy = spawn_proxy(&config, port);

    // Wait until the prober has marked the dead upstream unhealthy and traffic is
    // consistently served by the live one (robust to slow startup under load).
    let start = Instant::now();
    loop {
        let all_alive = (0..4).all(|_| http_get(port, "localhost", "/").contains("alive"));
        if all_alive {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(15),
            "dead upstream still receiving traffic"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn advertises_alt_svc_when_http3_enabled() {
    let upstream = spawn_upstream("ok");
    let port = free_port();
    let h3_port = free_port();
    let dir = std::env::temp_dir().join(format!("zaphyl-altsvc-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = write_self_signed(&dir);
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [tls]\ncert = \"{}\"\nkey = \"{}\"\n\n\
         [http3]\nlisten = \"127.0.0.1:{h3_port}\"\n\n\
         [[route]]\nupstream = \"{upstream}\"\n",
        cert.display(),
        key.display()
    );
    let _proxy = spawn_proxy(&config, port);

    // -i includes response headers so we can see the Alt-Svc advertisement.
    let output = Command::new("curl")
        .args([
            "-sik",
            "--max-time",
            "10",
            &format!("https://127.0.0.1:{port}/"),
        ])
        .output()
        .expect("run curl");
    let response = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(response.contains("alt-svc"), "response:\n{response}");
    assert!(
        response.contains(&format!("h3=\":{h3_port}\"")),
        "response:\n{response}"
    );
}

#[test]
fn reloads_tls_certificate_without_restart() {
    let upstream = spawn_upstream("hot reload");
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("zaphyl-reload-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let ca_a = dir.join("ca_a.pem");
    let ca_b = dir.join("ca_b.pem");

    // Start serving certificate A.
    std::fs::write(&ca_a, generate_localhost_cert(&cert, &key)).unwrap();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [tls]\ncert = \"{}\"\nkey = \"{}\"\n\n\
         [[route]]\nupstream = \"{upstream}\"\n",
        cert.display(),
        key.display()
    );
    let _proxy = spawn_proxy(&config, port);

    assert!(
        https_trusts(port, &ca_a),
        "certificate A should be served and trusted by CA A"
    );

    // Rotate to a brand-new certificate B (sleep so the file mtime differs).
    std::thread::sleep(Duration::from_millis(1100));
    std::fs::write(&ca_b, generate_localhost_cert(&cert, &key)).unwrap();

    // The new certificate is served without restarting the proxy.
    assert!(
        https_trusts(port, &ca_b),
        "rotated certificate B should now be served"
    );
    assert!(
        !https_trusts(port, &ca_a),
        "old certificate A should no longer be served"
    );
}

#[test]
fn redirects_http_to_https() {
    let upstream = spawn_upstream("ok");
    let port = free_port();
    let http_port = free_port();
    let dir = std::env::temp_dir().join(format!("zaphyl-redirect-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = write_self_signed(&dir);
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [tls]\ncert = \"{}\"\nkey = \"{}\"\n\n\
         [http]\nlisten = \"127.0.0.1:{http_port}\"\n\n\
         [[route]]\nupstream = \"{upstream}\"\n",
        cert.display(),
        key.display()
    );
    let _proxy = spawn_proxy(&config, port);

    // A plain-HTTP request is 308-redirected to HTTPS on the same host and path.
    let output = Command::new("curl")
        .args([
            "-si",
            "--max-redirs",
            "0",
            "--max-time",
            "10",
            &format!("http://127.0.0.1:{http_port}/foo?x=1"),
        ])
        .output()
        .expect("run curl");
    let response = String::from_utf8_lossy(&output.stdout).to_lowercase();
    assert!(response.contains("308"), "expected a 308, got:\n{response}");
    assert!(
        response.contains(&format!("location: https://127.0.0.1:{port}/foo?x=1")),
        "expected redirect to HTTPS, got:\n{response}"
    );
}

#[test]
fn serves_http2_over_tls() {
    let upstream = spawn_upstream("h2 body");
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("zaphyl-h2-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = write_self_signed(&dir);
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [tls]\ncert = \"{}\"\nkey = \"{}\"\n\n\
         [[route]]\nupstream = \"{upstream}\"\n",
        cert.display(),
        key.display()
    );
    let _proxy = spawn_proxy(&config, port);

    // An HTTP/2-capable client negotiates h2 over TLS.
    let output = Command::new("curl")
        .args([
            "-sik",
            "--http2",
            "--max-time",
            "10",
            &format!("https://127.0.0.1:{port}/"),
        ])
        .output()
        .expect("run curl");
    let response = String::from_utf8_lossy(&output.stdout);
    assert!(
        response.contains("HTTP/2"),
        "expected HTTP/2 status line, got:\n{response}"
    );
}

#[test]
fn terminates_tls_and_forwards() {
    let upstream = spawn_upstream("hello over tls");
    let port = free_port();
    let dir = std::env::temp_dir().join(format!("zaphyl-tls-{port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let (cert, key) = write_self_signed(&dir);
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n\
         [tls]\ncert = \"{}\"\nkey = \"{}\"\n\n\
         [[route]]\nupstream = \"{upstream}\"\n",
        cert.display(),
        key.display()
    );
    let _proxy = spawn_proxy(&config, port);

    let response = https_get(port, "/");
    assert!(
        response.contains("hello over tls"),
        "response was:\n{response}"
    );
}
