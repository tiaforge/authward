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
    /// All keyed by provider key (see `config::ResolvedHost::provider_key`):
    /// the provider's static config, its OIDC client, its JWKS cache
    /// (refreshable independently of the client — see `jwks_cache` module
    /// docs), and its `end_session_endpoint` (`None` when it has no
    /// RP-Initiated Logout support).
    pub providers: HashMap<String, crate::config::Provider>,
    pub oidc_clients: HashMap<String, DiscoveredClient>,
    pub jwks_caches: HashMap<String, JwksCache>,
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
