//! Live ACME integration tests against Pebble (Let's Encrypt's test CA).
//!
//! Ignored by default: they need the `pebble` and `pebble-challtestsrv` binaries
//! (install with `go install github.com/letsencrypt/pebble/v2/cmd/...@latest`).
//! Run locally with:  `cargo test --test acme -- --ignored --nocapture`

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

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

fn wait_for_port(port: u16, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

fn go_bin(name: &str) -> PathBuf {
    let home = std::env::var("HOME").expect("HOME not set");
    PathBuf::from(home).join("go/bin").join(name)
}

fn spawn_upstream(body: &'static str) -> std::net::SocketAddr {
    let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let addr = server.server_addr().to_ip().unwrap();
    std::thread::spawn(move || {
        for request in server.incoming_requests() {
            let _ = request.respond(tiny_http::Response::from_string(body));
        }
    });
    addr
}

/// Generate a self-signed cert + key for `localhost` (Pebble's ACME endpoint).
fn write_self_signed(dir: &Path) -> (PathBuf, PathBuf) {
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = dir.join("pebble-cert.pem");
    let key_path = dir.join("pebble-key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, signing_key.serialize_pem()).unwrap();
    (cert_path, key_path)
}

/// A running Pebble CA plus its DNS/challenge helper. Kept alive via the guards.
struct Pebble {
    acme_port: u16,
    challenge_port: u16,
    pebble_cert: PathBuf,
    _challtestsrv: ChildGuard,
    _pebble: ChildGuard,
}

/// Start Pebble + pebble-challtestsrv (DNS maps every name to 127.0.0.1).
fn start_pebble(dir: &Path) -> Pebble {
    let dns_port = free_port();
    let acme_port = free_port();
    let mgmt_port = free_port();
    let challenge_port = free_port();
    let tlsalpn_port = free_port();

    let (pebble_cert, pebble_key) = write_self_signed(dir);

    let config = format!(
        r#"{{
  "pebble": {{
    "listenAddress": "127.0.0.1:{acme_port}",
    "managementListenAddress": "127.0.0.1:{mgmt_port}",
    "certificate": "{cert}",
    "privateKey": "{key}",
    "httpPort": {challenge_port},
    "tlsPort": {tlsalpn_port},
    "ocspResponderURL": "",
    "externalAccountBindingRequired": false
  }}
}}"#,
        cert = pebble_cert.display(),
        key = pebble_key.display(),
    );
    let pebble_config = dir.join("pebble-config.json");
    std::fs::write(&pebble_config, config).unwrap();

    let challtestsrv = ChildGuard(
        Command::new(go_bin("pebble-challtestsrv"))
            .args([
                "-dnsserver",
                &format!(":{dns_port}"),
                "-defaultIPv4",
                "127.0.0.1",
                "-defaultIPv6",
                "",
                "-http01",
                "",
                "-https01",
                "",
                "-tlsalpn01",
                "",
                "-doh",
                "",
                "-management",
                &format!(":{}", free_port()),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn pebble-challtestsrv"),
    );

    let pebble = ChildGuard(
        Command::new(go_bin("pebble"))
            .args([
                "-config",
                pebble_config.to_str().unwrap(),
                "-dnsserver",
                &format!("127.0.0.1:{dns_port}"),
            ])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn pebble"),
    );
    assert!(
        wait_for_port(acme_port, Duration::from_secs(15)),
        "pebble did not start listening on {acme_port}"
    );

    Pebble {
        acme_port,
        challenge_port,
        pebble_cert,
        _challtestsrv: challtestsrv,
        _pebble: pebble,
    }
}

/// Spawn `zaphyl` pointed at Pebble, with the given extra `[acme]` lines.
fn spawn_zaphyl(
    dir: &Path,
    pebble: &Pebble,
    https_port: u16,
    upstream: std::net::SocketAddr,
    extra_acme: &str,
) -> ChildGuard {
    let cache_dir = dir.join("cache");
    let zaphyl_config = format!(
        "listen = \"127.0.0.1:{https_port}\"\n\n\
         [acme]\n\
         domains = [\"zaphyl.test\"]\n\
         email = \"admin@zaphyl.test\"\n\
         directory = \"https://localhost:{acme_port}/dir\"\n\
         cache_dir = \"{cache}\"\n{extra_acme}\n\
         [[route]]\nupstream = \"{upstream}\"\n",
        acme_port = pebble.acme_port,
        cache = cache_dir.display(),
    );
    let config_path = dir.join("zaphyl.toml");
    std::fs::write(&config_path, zaphyl_config).unwrap();

    ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_zaphyl"))
            .arg("--config")
            .arg(&config_path)
            .env(
                "ZAPHYL_ACME_HTTP_ADDR",
                format!("127.0.0.1:{}", pebble.challenge_port),
            )
            .env("ZAPHYL_ACME_ROOT_CERT", &pebble.pebble_cert)
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn zaphyl"),
    )
}

/// The serial number of the certificate currently served on `port`.
fn served_cert_serial(port: u16) -> String {
    let output = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "echo | openssl s_client -connect 127.0.0.1:{port} 2>/dev/null \
             | openssl x509 -noout -serial"
        ))
        .output()
        .expect("run openssl");
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

#[test]
#[ignore = "requires pebble + pebble-challtestsrv binaries"]
fn obtains_certificate_via_acme_and_serves_https() {
    let dir = std::env::temp_dir().join(format!("zaphyl-acme-{}", free_port()));
    std::fs::create_dir_all(&dir).unwrap();

    let pebble = start_pebble(&dir);
    let upstream = spawn_upstream("hello via acme");
    let https_port = free_port();
    let _zaphyl = spawn_zaphyl(&dir, &pebble, https_port, upstream, "");

    // zaphyl opens its HTTPS port only after the certificate is obtained.
    assert!(
        wait_for_port(https_port, Duration::from_secs(60)),
        "zaphyl never served HTTPS (ACME likely failed)"
    );

    let output = Command::new("curl")
        .args([
            "-sk",
            "--max-time",
            "10",
            &format!("https://127.0.0.1:{https_port}/"),
        ])
        .output()
        .expect("run curl");
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(body.contains("hello via acme"), "body was: {body}");
}

#[test]
#[ignore = "requires pebble + pebble-challtestsrv binaries"]
fn renews_certificate_while_serving() {
    let dir = std::env::temp_dir().join(format!("zaphyl-renew-{}", free_port()));
    std::fs::create_dir_all(&dir).unwrap();

    let pebble = start_pebble(&dir);
    let upstream = spawn_upstream("hello via acme");
    let https_port = free_port();

    // Force renewal immediately and often: a huge renewal window means the cert
    // is always "due", and the loop checks every second. The renewal is served
    // by the still-running HTTP-01 responder, and applied without a restart.
    let _zaphyl = spawn_zaphyl(
        &dir,
        &pebble,
        https_port,
        upstream,
        "renew_before_days = 36500\ncheck_interval_seconds = 1\n",
    );

    assert!(
        wait_for_port(https_port, Duration::from_secs(60)),
        "zaphyl never served HTTPS (ACME likely failed)"
    );

    let initial = served_cert_serial(https_port);
    assert!(!initial.is_empty(), "could not read the served certificate");

    // Within a few renewal cycles the served certificate should change to a
    // freshly issued one, all without restarting the process.
    let start = Instant::now();
    let renewed = loop {
        let current = served_cert_serial(https_port);
        if !current.is_empty() && current != initial {
            break current;
        }
        assert!(
            start.elapsed() < Duration::from_secs(45),
            "served certificate never rotated (renewal did not take effect)"
        );
        std::thread::sleep(Duration::from_millis(500));
    };

    // The proxy still serves traffic on the renewed certificate.
    let output = Command::new("curl")
        .args([
            "-sk",
            "--max-time",
            "10",
            &format!("https://127.0.0.1:{https_port}/"),
        ])
        .output()
        .expect("run curl");
    let body = String::from_utf8_lossy(&output.stdout);
    assert!(
        body.contains("hello via acme"),
        "after renewal to serial {renewed}, body was: {body}"
    );
}
