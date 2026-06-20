//! WebSocket pass-through: the proxy must tunnel an HTTP/1.1 `Upgrade` so a
//! client and an upstream can exchange WebSocket frames through it.

use futures_util::{SinkExt, StreamExt};
use std::net::TcpListener as StdTcpListener;
use std::process::{Child, Command};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio_tungstenite::tungstenite::Message;

/// Kills the spawned proxy when the test ends, even on panic.
struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    StdTcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Spawn a WebSocket echo upstream; returns its address.
async fn spawn_ws_echo_upstream() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut ws = match tokio_tungstenite::accept_async(stream).await {
                    Ok(ws) => ws,
                    Err(_) => return,
                };
                while let Some(Ok(msg)) = ws.next().await {
                    if msg.is_text() || msg.is_binary() {
                        let _ = ws.send(msg).await;
                    }
                }
            });
        }
    });
    addr
}

/// Spawn `zaphyl` with the given config and wait until it is listening.
async fn spawn_proxy(config: &str, port: u16) -> ChildGuard {
    let dir = std::env::temp_dir().join(format!("zaphyl-ws-{port}"));
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

#[tokio::test]
#[allow(clippy::result_large_err)]
async fn proxies_websocket_upgrade() {
    // The Pingora 0.8.1 HTTP/1.1 duplex path has a race that closes a
    // WebSocket tunnel right after the 101 for a no-body upgrade request. A
    // single upgrade does not reliably catch it, so run many back-to-back
    // upgrade+echo cycles through one proxy. The race is timing-dependent, so a
    // single run of this test catches a regression only probabilistically; CI
    // runs the whole file in a loop (see the plan) to make the guard reliable.
    // With the fix in place, every cycle passes deterministically.
    let upstream = spawn_ws_echo_upstream().await;
    let port = free_port();
    let config = format!("listen = \"127.0.0.1:{port}\"\n\n[[route]]\nupstream = \"{upstream}\"\n");
    let _proxy = spawn_proxy(&config, port).await;

    for cycle in 0..50 {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let url = format!("ws://127.0.0.1:{port}/");
        let (mut ws, _response) = tokio_tungstenite::client_async(url, tcp)
            .await
            .unwrap_or_else(|e| panic!("cycle {cycle}: upgrade failed: {e:?}"));

        ws.send(Message::text("hello")).await.unwrap();
        let reply = ws
            .next()
            .await
            .unwrap_or_else(|| panic!("cycle {cycle}: no reply"))
            .unwrap_or_else(|e| panic!("cycle {cycle}: reply error: {e:?}"));
        assert_eq!(
            reply.into_text().unwrap().to_string(),
            "hello",
            "cycle {cycle}"
        );

        ws.close(None).await.unwrap();
    }
}

#[tokio::test]
async fn proxies_websocket_sustained_messages() {
    // One upgrade, several echo round-trips, proving the tunnel stays
    // bidirectional past the first frame.
    let upstream = spawn_ws_echo_upstream().await;
    let port = free_port();
    let config = format!("listen = \"127.0.0.1:{port}\"\n\n[[route]]\nupstream = \"{upstream}\"\n");
    let _proxy = spawn_proxy(&config, port).await;

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let url = format!("ws://127.0.0.1:{port}/");
    let (mut ws, _response) = tokio_tungstenite::client_async(url, tcp)
        .await
        .expect("websocket upgrade through the proxy");

    for i in 0..4 {
        let msg = format!("msg-{i}");
        ws.send(Message::text(msg.clone())).await.unwrap();
        let reply = ws.next().await.expect("a reply").unwrap();
        assert_eq!(reply.into_text().unwrap().to_string(), msg, "round {i}");
    }
}
