pub mod cli;
pub mod config;
pub mod crypto;
pub mod db;
pub mod host;
pub mod locks;
pub mod logging;
pub mod oidc;
pub mod redirect;
pub mod routes;
pub mod server;
pub mod session;
pub mod state;
pub mod templates;

use std::collections::HashMap;

use axum_extra::extract::cookie::Key;
use openidconnect::RedirectUrl;

use crate::config::Config;
use crate::crypto::RefreshTokenCipher;
use crate::locks::SessionLocks;
use crate::state::{AppState, AppStateInner};

/// Builds the full application state from a resolved config: discovers
/// every configured base domain's OIDC provider, opens the SQLite pool
/// (running migrations), and derives the crypto keys. Split out from
/// `main` so integration tests can build a real `AppState` against a
/// mock IdP without going through the CLI/process entry point.
pub async fn build_state(cfg: Config) -> anyhow::Result<AppState> {
    let http_client = oidc::build_http_client()?;

    let mut oidc_clients = HashMap::new();
    for (name, base_domain) in &cfg.base_domains {
        let redirect_uri =
            RedirectUrl::new(format!("https://{}/callback", base_domain.auth_subdomain))?;
        tracing::info!(base_domain = name, discovery_url = %base_domain.provider.discovery_url, "discovering OIDC provider");
        let client = oidc::discover(&http_client, &base_domain.provider, redirect_uri).await?;
        oidc_clients.insert(name.clone(), client);
    }

    let db = db::connect(&cfg.global.sqlite_path).await?;

    let cookie_key = Key::derive_from(cfg.global.cookie_signing_key.as_bytes());
    let refresh_cipher = RefreshTokenCipher::new(&crypto::derive_key(
        &cfg.global.refresh_token_encryption_key,
    ));

    Ok(AppState::new(AppStateInner {
        config: cfg,
        db,
        cookie_key,
        refresh_cipher,
        oidc_clients,
        http_client,
        session_locks: SessionLocks::new(),
    }))
}
