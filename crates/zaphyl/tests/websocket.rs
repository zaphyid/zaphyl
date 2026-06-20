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
async fn proxies_websocket_upgrade() {
    let upstream = spawn_ws_echo_upstream().await;
    let port = free_port();
    let config = format!("listen = \"127.0.0.1:{port}\"\n\n[[route]]\nupstream = \"{upstream}\"\n");
    let _proxy = spawn_proxy(&config, port).await;

    // Open a WebSocket through the proxy and echo a couple of messages.
    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let url = format!("ws://127.0.0.1:{port}/");
    let (mut ws, _response) = tokio_tungstenite::client_async(url, tcp)
        .await
        .expect("websocket upgrade through the proxy");

    ws.send(Message::text("hello")).await.unwrap();
    let reply = ws.next().await.expect("a reply").unwrap();
    assert_eq!(reply.into_text().unwrap().to_string(), "hello");

    ws.send(Message::text("again")).await.unwrap();
    let reply = ws.next().await.expect("a second reply").unwrap();
    assert_eq!(reply.into_text().unwrap().to_string(), "again");
}
