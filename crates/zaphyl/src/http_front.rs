//! Plain-HTTP front listener (typically port 80).
//!
//! Answers ACME HTTP-01 challenges from the shared [`ChallengeStore`] and, for
//! every other request, either redirects to HTTPS or replies 404. Runs as a
//! proper concurrent HTTP/1.1 server so it can sit in front of real traffic,
//! not just occasional ACME validations.

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use zaphyl_core::acme::ChallengeStore;

/// A boxed, thread-safe error.
type DynError = Box<dyn std::error::Error + Send + Sync>;

/// What to do with a request that is not an ACME challenge.
#[derive(Clone, Copy)]
pub enum NonChallenge {
    /// Redirect to HTTPS on this port (omitted from the URL when it is 443).
    RedirectToHttps(u16),
    /// Reply 404 - used when the front exists only to answer ACME challenges.
    NotFound,
}

/// Serve the plain-HTTP front on `listen` until the process exits.
///
/// # Errors
/// Fails if the listener cannot bind to `listen`.
pub async fn serve(
    listen: SocketAddr,
    store: Arc<ChallengeStore>,
    behavior: NonChallenge,
) -> Result<(), DynError> {
    let listener = TcpListener::bind(listen).await?;
    eprintln!("zaphyl: HTTP front listening on {listen}");
    loop {
        let (stream, _) = listener.accept().await?;
        let store = Arc::clone(&store);
        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let store = Arc::clone(&store);
                async move { Ok::<_, Infallible>(respond(&req, &store, behavior)) }
            });
            let _ = http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}

/// Build the response for one request: ACME challenge, redirect, or 404.
fn respond(
    req: &Request<Incoming>,
    store: &ChallengeStore,
    behavior: NonChallenge,
) -> Response<Full<Bytes>> {
    if let Some(body) = store.response_for(req.uri().path()) {
        return Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from(body)))
            .expect("valid challenge response");
    }
    match behavior {
        NonChallenge::RedirectToHttps(port) => redirect_to_https(req, port),
        NonChallenge::NotFound => Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::new()))
            .expect("valid 404 response"),
    }
}

/// A 308 redirect to the same host and path over HTTPS.
fn redirect_to_https(req: &Request<Incoming>, https_port: u16) -> Response<Full<Bytes>> {
    let host = req
        .headers()
        .get(hyper::header::HOST)
        .and_then(|value| value.to_str().ok())
        .map_or("", |value| value.split(':').next().unwrap_or(value));
    let path_and_query = req.uri().path_and_query().map_or("/", |p| p.as_str());
    let location = if https_port == 443 {
        format!("https://{host}{path_and_query}")
    } else {
        format!("https://{host}:{https_port}{path_and_query}")
    };
    Response::builder()
        .status(StatusCode::PERMANENT_REDIRECT)
        .header(hyper::header::LOCATION, location)
        .body(Full::new(Bytes::new()))
        .expect("valid redirect response")
}
