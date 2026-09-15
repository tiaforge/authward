use std::collections::HashMap;
use std::ops::Deref;
use std::sync::{Arc, RwLock};

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
    /// The discovered, ready-to-use side of each `[idp]`, keyed by its
    /// name (see `config::ResolvedHost::provider_key`). A provider whose IdP was unreachable at startup has no entry
    /// until the background retry (`crate::spawn_discovery_retry`)
    /// succeeds; its hosts answer "provider unavailable" in the meantime.
    /// Written only by discovery, read on every request — a `std` lock
    /// is fine, nothing holds it across an `.await`.
    provider_runtimes: RwLock<HashMap<String, Arc<ProviderRuntime>>>,
    pub http_client: openidconnect::reqwest::Client,
    pub session_locks: SessionLocks,
    /// Shared across `/login` and `/callback` — a token-bucket burst
    /// covers a normal three-hop login (redirect to IdP, then callback)
    /// without the two endpoints needing separate budgets.
    pub login_rate_limiter: RateLimiter,
}

/// What discovery produces for one provider: the OIDC client for the
/// browser login/refresh flows, the JWKS cache for bearer-token
/// validation (refreshable independently of the client — see the
/// `jwks_cache` module docs), and the `end_session_endpoint` (`None`
/// when the provider has no RP-Initiated Logout support).
pub struct ProviderRuntime {
    pub client: DiscoveredClient,
    pub jwks: JwksCache,
    pub end_session_endpoint: Option<url::Url>,
    /// See `oidc::DiscoveredProvider::supports_groups_scope`.
    pub supports_groups_scope: bool,
}

impl AppState {
    pub fn new(inner: AppStateInner) -> Self {
        Self(Arc::new(inner))
    }
}

impl AppStateInner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Config,
        db: SqlitePool,
        cookie_key: Key,
        refresh_cipher: RefreshTokenCipher,
        provider_runtimes: HashMap<String, ProviderRuntime>,
        http_client: openidconnect::reqwest::Client,
        login_rate_limiter: RateLimiter,
    ) -> Self {
        Self {
            config,
            db,
            cookie_key,
            refresh_cipher,
            provider_runtimes: RwLock::new(
                provider_runtimes
                    .into_iter()
                    .map(|(k, v)| (k, Arc::new(v)))
                    .collect(),
            ),
            http_client,
            session_locks: SessionLocks::new(),
            login_rate_limiter,
        }
    }

    /// The discovered runtime for `provider_key`, or `None` while its IdP
    /// is still unreachable (or the key is unknown).
    pub fn provider_runtime(&self, provider_key: &str) -> Option<Arc<ProviderRuntime>> {
        self.provider_runtimes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(provider_key)
            .cloned()
    }

    /// Every provider that has been discovered so far.
    pub fn provider_runtimes(&self) -> Vec<(String, Arc<ProviderRuntime>)> {
        self.provider_runtimes
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }

    /// Makes a late-discovered provider available to requests.
    pub fn install_provider_runtime(&self, provider_key: String, runtime: ProviderRuntime) {
        self.provider_runtimes
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(provider_key, Arc::new(runtime));
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
