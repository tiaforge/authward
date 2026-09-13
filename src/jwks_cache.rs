//! Per-base-domain JWKS cache for resource-scoped bearer-token validation
//! (Phase 5). Independent of the OIDC client used for browser login/
//! refresh, whose JWKS is baked in at construction and never changes —
//! bearer-token validation needs to survive the IdP rotating its signing
//! keys without a service restart.

use openidconnect::core::CoreJsonWebKey;
use openidconnect::{IssuerUrl, JsonWebKeySet, JsonWebKeySetUrl};
use tokio::sync::RwLock;

pub struct JwksCache {
    pub issuer: IssuerUrl,
    jwks_uri: JsonWebKeySetUrl,
    keys: RwLock<JsonWebKeySet<CoreJsonWebKey>>,
}

impl JwksCache {
    pub fn new(
        issuer: IssuerUrl,
        jwks_uri: JsonWebKeySetUrl,
        initial: JsonWebKeySet<CoreJsonWebKey>,
    ) -> Self {
        Self {
            issuer,
            jwks_uri,
            keys: RwLock::new(initial),
        }
    }

    pub async fn current(&self) -> JsonWebKeySet<CoreJsonWebKey> {
        self.keys.read().await.clone()
    }

    /// Re-fetches the JWKS from the provider and replaces the cached copy.
    /// Called both periodically (background refresh) and on-demand after a
    /// signature-verification failure, so a key rotation at the IdP is
    /// picked up without waiting for the next scheduled refresh.
    pub async fn refresh(
        &self,
        http_client: &openidconnect::reqwest::Client,
    ) -> anyhow::Result<()> {
        let fresh = crate::oidc::fetch_jwks(http_client, &self.jwks_uri).await?;
        *self.keys.write().await = fresh;
        Ok(())
    }
}

/// Spawns the background JWKS refresh loop, sweeping every cached
/// provider on a timer — independent of the on-demand refresh triggered
/// by a signature-verification failure in `bearer::validate`.
pub fn spawn_periodic_refresh(
    state: crate::state::AppState,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // The first tick fires immediately; skip it so we don't refetch on startup.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            for (base_domain, cache) in &state.jwks_caches {
                if let Err(err) = cache.refresh(&state.http_client).await {
                    tracing::warn!(base_domain, %err, "periodic JWKS refresh failed");
                }
            }
        }
    })
}
