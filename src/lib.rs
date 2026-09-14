pub mod authz;
pub mod bearer;
pub mod bypass;
pub mod cli;
pub mod config;
pub mod crypto;
pub mod db;
pub mod host;
pub mod jwks_cache;
pub mod locks;
pub mod logging;
pub mod oidc;
pub mod ratelimit;
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
use crate::jwks_cache::JwksCache;
use crate::locks::SessionLocks;
use crate::ratelimit::{LOGIN_RATE_LIMIT_CAPACITY, LOGIN_RATE_LIMIT_REFILL_PER_SEC, RateLimiter};
use crate::state::{AppState, AppStateInner};

/// Builds the full application state from a resolved config: discovers
/// every configured base domain's OIDC provider, opens the SQLite pool
/// (running migrations), and derives the crypto keys. Split out from
/// `main` so integration tests can build a real `AppState` against a
/// mock IdP without going through the CLI/process entry point.
pub async fn build_state(cfg: Config) -> anyhow::Result<AppState> {
    let http_client = oidc::build_http_client()?;

    let mut providers = HashMap::new();
    let mut oidc_clients = HashMap::new();
    let mut jwks_caches = HashMap::new();
    let mut end_session_endpoints = HashMap::new();
    // One discovery per distinct provider: each base domain's default plus
    // every host-level override. All clients of a base domain share its
    // auth subdomain's /callback as redirect URI — that's what gets
    // registered at each IdP.
    for (key, provider, base_domain) in cfg.providers() {
        let redirect_uri =
            RedirectUrl::new(format!("https://{}/callback", base_domain.auth_subdomain))?;
        tracing::info!(provider_key = %key, discovery_url = %provider.discovery_url, "discovering OIDC provider");
        let discovered = oidc::discover(&http_client, provider, redirect_uri).await?;
        jwks_caches.insert(
            key.clone(),
            JwksCache::new(discovered.issuer, discovered.jwks_uri, discovered.jwks),
        );
        end_session_endpoints.insert(key.clone(), discovered.end_session_endpoint);
        oidc_clients.insert(key.clone(), discovered.client);
        providers.insert(key, provider.clone());
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
        providers,
        oidc_clients,
        jwks_caches,
        end_session_endpoints,
        http_client,
        session_locks: SessionLocks::new(),
        login_rate_limiter: RateLimiter::new(
            LOGIN_RATE_LIMIT_CAPACITY,
            LOGIN_RATE_LIMIT_REFILL_PER_SEC,
        ),
    }))
}
