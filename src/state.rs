use std::collections::HashMap;
use std::ops::Deref;
use std::sync::Arc;

use axum::extract::FromRef;
use axum_extra::extract::cookie::Key;
use sqlx::SqlitePool;

use crate::config::Config;
use crate::crypto::RefreshTokenCipher;
use crate::jwks_cache::JwksCache;
use crate::locks::SessionLocks;
use crate::oidc::DiscoveredClient;
use crate::ratelimit::RateLimiter;

#[derive(Clone)]
pub struct AppState(Arc<AppStateInner>);

pub struct AppStateInner {
    pub config: Config,
    pub db: SqlitePool,
    pub cookie_key: Key,
    pub refresh_cipher: RefreshTokenCipher,
    /// Keyed by base domain name (see `config::BaseDomain::name`).
    pub oidc_clients: HashMap<String, DiscoveredClient>,
    /// Keyed by base domain name too, but refreshable independently of
    /// `oidc_clients` — see `jwks_cache` module docs (Phase 5).
    pub jwks_caches: HashMap<String, JwksCache>,
    /// Keyed by base domain name; `None` for a provider with no
    /// RP-Initiated Logout support (Phase 8).
    pub end_session_endpoints: HashMap<String, Option<url::Url>>,
    pub http_client: openidconnect::reqwest::Client,
    pub session_locks: SessionLocks,
    /// Shared across `/login` and `/callback` — a token-bucket burst
    /// covers a normal three-hop login (redirect to IdP, then callback)
    /// without the two endpoints needing separate budgets.
    pub login_rate_limiter: RateLimiter,
}

impl AppState {
    pub fn new(inner: AppStateInner) -> Self {
        Self(Arc::new(inner))
    }
}

impl Deref for AppState {
    type Target = AppStateInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.cookie_key.clone()
    }
}
