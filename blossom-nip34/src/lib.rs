//! blossom-nip34 — NIP-34 Nostr relay + GRASP git server library.
//!
//! Provides a mountable axum [`Router`] that adds NIP-34 relay capabilities
//! and GRASP-compatible git HTTP smart protocol to any application.

pub mod config;
pub mod git_server;
pub mod nip34_types;
pub mod relay;
mod state;

pub use config::Nip34Config;
pub use state::Nip34State;

use std::sync::Arc;

/// Build an axum Router with NIP-34 relay + GRASP git server.
///
/// The returned router handles:
/// - `GET/POST /` — WebSocket upgrade (Nostr relay), NIP-11 info, or default page
/// - `GET /{npub}/{repo}/info/refs` — git smart HTTP ref advertisement
/// - `POST /{npub}/{repo}/git-upload-pack` — git fetch
/// - `POST /{npub}/{repo}/git-receive-pack` — git push
pub async fn build_nip34_router(
    config: Nip34Config,
) -> Result<axum::Router, Box<dyn std::error::Error>> {
    let state = Arc::new(Nip34State::new(config).await?);

    let app = axum::Router::new()
        .route(
            "/",
            axum::routing::get(relay::dispatch::main_handler).post(relay::dispatch::main_handler),
        )
        .merge(git_server::git_router())
        .with_state(state);

    Ok(app)
}
