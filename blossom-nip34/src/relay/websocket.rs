//! WebSocket upgrade handler — passes raw upgraded connection to nostr-relay-builder.
//!
//! Uses hyper's raw upgrade (not axum's message-based WebSocket) because
//! `nostr-relay-builder` expects `AsyncRead + AsyncWrite`.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::http::header::{CONNECTION, SEC_WEBSOCKET_ACCEPT, UPGRADE};
use axum::http::{Request, Response, StatusCode};
use base64::prelude::*;
use hyper_util::rt::TokioIo;
use nostr::hashes::{sha1::Hash as Sha1Hash, Hash, HashEngine};

use crate::Nip34State;

/// Derive the `Sec-WebSocket-Accept` header value from the request key.
fn derive_accept_key(request_key: &[u8]) -> String {
    const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    let mut engine = Sha1Hash::engine();
    engine.input(request_key);
    engine.input(WS_GUID);
    let hash = Sha1Hash::from_engine(engine);
    BASE64_STANDARD.encode(hash)
}

/// Check if a request is a WebSocket upgrade.
pub fn is_websocket_upgrade(req: &Request<Body>) -> bool {
    req.headers()
        .get("upgrade")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false)
}

/// Handle a WebSocket upgrade request.
///
/// Performs the HTTP 101 handshake and spawns a task to pass the raw
/// upgraded connection to `relay.take_connection()`.
pub fn handle_ws_upgrade(
    state: Arc<Nip34State>,
    req: Request<Body>,
    addr: SocketAddr,
) -> Response<Body> {
    let key = req
        .headers()
        .get("sec-websocket-key")
        .map(|k| derive_accept_key(k.as_bytes()));

    let relay = state.relay.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let io = TokioIo::new(upgraded);
                if let Err(e) = relay.take_connection(io, addr).await {
                    tracing::error!(error = %e, %addr, "relay connection error");
                }
            }
            Err(e) => tracing::error!(error = %e, "WebSocket upgrade failed"),
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(CONNECTION, "upgrade")
        .header(UPGRADE, "websocket")
        .header(SEC_WEBSOCKET_ACCEPT, key.unwrap_or_default())
        .body(Body::empty())
        .unwrap()
}
