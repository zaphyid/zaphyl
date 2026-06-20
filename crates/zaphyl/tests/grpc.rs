//! gRPC / HTTP-2-upstream pass-through: a route with `grpc = true` must forward
//! to the upstream over HTTP/2 (here h2c, cleartext). We assert the upstream
//! actually received an HTTP/2 request.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// An h2c (cleartext HTTP/2) upstream that replies with the HTTP version it saw.
async fn spawn_h2c_upstream() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            tokio::spawn(async move {
                let service = service_fn(|req: Request<Incoming>| async move {
                    let body = format!("upstream saw {:?}", req.version());
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from(body))))
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(tcp), service)
                    .await;
            });
        }
    });
    addr
}

/// Spawn `zaphyl` with the given config and wait until it is listening.
async fn spawn_proxy(config: &str, port: u16) -> ChildGuard {
    let dir = std::env::temp_dir().join(format!("zaphyl-grpc-{port}"));
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
    while TcpStream::connect(("127.0.0.1", port)).await.is_err() {
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "proxy port {port} never started listening"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    guard
}

/// Minimal HTTP/1.1 GET over a raw socket; returns the response text.
async fn http_get(port: u16) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    stream
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await.unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

#[tokio::test]
async fn forwards_to_grpc_upstream_over_http2() {
    let upstream = spawn_h2c_upstream().await;
    let port = free_port();
    let config = format!(
        "listen = \"127.0.0.1:{port}\"\n\n[[route]]\nupstream = \"{upstream}\"\ngrpc = true\n"
    );
    let _proxy = spawn_proxy(&config, port).await;

    // The client speaks HTTP/1.1; the proxy must upgrade to HTTP/2 upstream.
    let response = http_get(port).await;
    assert!(
        response.contains("upstream saw HTTP/2.0"),
        "expected the upstream to receive HTTP/2, got:\n{response}"
    );
}
