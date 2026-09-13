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
    pub http_client: openidconnect::reqwest::Client,
    pub session_locks: SessionLocks,
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
