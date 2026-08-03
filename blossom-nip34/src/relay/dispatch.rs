//! Main handler — dispatches between WebSocket, NIP-11, and fallback.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::{Request, StatusCode};
use axum::response::{IntoResponse, Response};

use crate::Nip34State;

/// Main handler for `GET /` and `POST /`.
///
/// Dispatches based on request headers:
/// 1. WebSocket upgrade → Nostr relay (raw hyper upgrade)
/// 2. Accept: application/nostr+json → NIP-11 info
/// 3. Default → 200 with relay name
pub async fn main_handler(
    State(state): State<Arc<Nip34State>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<Body>,
) -> Response {
    // 1. WebSocket upgrade
    if super::websocket::is_websocket_upgrade(&req) {
        return super::websocket::handle_ws_upgrade(state, req, addr);
    }

    let headers = req.headers().clone();

    // 2. NIP-11 info document
    if let Some(accept) = headers.get("accept") {
        if let Ok(accept_str) = accept.to_str() {
            if accept_str.contains("application/nostr+json") {
                return super::nip11::handle_nip11(state).into_response();
            }
        }
    }

    // 3. Default: simple relay info
    (
        StatusCode::OK,
        format!(
            "{} — NIP-34 relay + GRASP git server",
            state.config.nip11.name
        ),
    )
        .into_response()
}
