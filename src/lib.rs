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

use crate::config::Config;
use crate::crypto::RefreshTokenCipher;
use crate::jwks_cache::JwksCache;
use crate::ratelimit::{LOGIN_RATE_LIMIT_CAPACITY, LOGIN_RATE_LIMIT_REFILL_PER_SEC, RateLimiter};
use crate::state::{AppState, AppStateInner, ProviderRuntime};

/// Builds the full application state from a resolved config: discovers
/// every configured `[idp]`, opens the SQLite pool (running
/// migrations), and derives the crypto keys. Split out from `main` so
/// integration tests can build a real `AppState` against a mock IdP
/// without going through the CLI/process entry point.
///
/// A provider whose IdP can't be reached is logged and left for
/// [`spawn_discovery_retry`] to pick up; its hosts answer "provider
/// unavailable" until then, and every other provider serves normally —
/// one IdP's outage during a restart doesn't take down the rest. If
/// *no* provider can be discovered there's nothing to serve, and the
/// most likely cause is a config mistake rather than an outage, so that
/// case still fails startup with every error listed.
pub async fn build_state(cfg: Config) -> anyhow::Result<AppState> {
    let http_client = oidc::build_http_client()?;

    let mut runtimes = HashMap::new();
    let mut failures = Vec::new();
    for (key, idp) in &cfg.idps {
        match discover_provider(&http_client, key, idp).await {
            Ok(runtime) => {
                runtimes.insert(key.clone(), runtime);
            }
            Err(err) => {
                tracing::error!(provider_key = %key, discovery_url = %idp.discovery_url, err = %format!("{err:#}"), "OIDC provider discovery failed; will retry in the background");
                failures.push(format!("{key} ({}): {err:#}", idp.discovery_url));
            }
        }
    }
    if runtimes.is_empty() && !cfg.idps.is_empty() {
        anyhow::bail!(
            "no OIDC provider could be discovered:\n  - {}",
            failures.join("\n  - ")
        );
    }

    let db = db::connect(&cfg.global.sqlite_path).await?;

    let cookie_key = Key::derive_from(cfg.global.cookie_signing_key.as_bytes());
    let refresh_cipher = RefreshTokenCipher::new(&crypto::derive_key(
        &cfg.global.refresh_token_encryption_key,
    ));

    Ok(AppState::new(AppStateInner::new(
        cfg,
        db,
        cookie_key,
        refresh_cipher,
        runtimes,
        http_client,
        RateLimiter::new(LOGIN_RATE_LIMIT_CAPACITY, LOGIN_RATE_LIMIT_REFILL_PER_SEC),
    )))
}

/// One IdP's discovery. The redirect URI isn't fixed here: every domain
/// using this IdP applies its own `https://<auth_subdomain>/callback` per
/// request, and each of those must be registered at the IdP.
async fn discover_provider(
    http_client: &openidconnect::reqwest::Client,
    key: &str,
    provider: &config::Idp,
) -> anyhow::Result<ProviderRuntime> {
    tracing::info!(provider_key = %key, discovery_url = %provider.discovery_url, "discovering OIDC provider");
    let discovered = oidc::discover(http_client, provider).await?;
    Ok(ProviderRuntime {
        client: discovered.client,
        jwks: JwksCache::new(discovered.issuer, discovered.jwks_uri, discovered.jwks),
        end_session_endpoint: discovered.end_session_endpoint,
        supports_groups_scope: discovered.supports_groups_scope,
    })
}

/// Retries discovery for every configured provider that doesn't have a
/// runtime yet. Returns how many are still missing afterwards.
pub async fn discover_missing_providers(state: &AppState) -> usize {
    let mut missing = 0;
    for (key, idp) in &state.config.idps {
        if state.provider_runtime(key).is_some() {
            continue;
        }
        match discover_provider(&state.http_client, key, idp).await {
            Ok(runtime) => {
                tracing::info!(provider_key = %key, "OIDC provider discovered after earlier failure; now serving");
                state.install_provider_runtime(key.clone(), runtime);
            }
            Err(err) => {
                tracing::warn!(provider_key = %key, discovery_url = %idp.discovery_url, err = %format!("{err:#}"), "OIDC provider discovery still failing");
                missing += 1;
            }
        }
    }
    missing
}

/// Spawns the background loop that keeps retrying discovery for
/// providers that were unreachable at startup, until none are missing.
pub fn spawn_discovery_retry(
    state: AppState,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            if discover_missing_providers(&state).await == 0 {
                return;
            }
        }
    })
}
