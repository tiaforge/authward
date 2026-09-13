//! OIDC provider client setup. Discovery happens once per base domain at
//! startup (Phase 1 scope); the resource-scoped-token JWKS refresh loop in
//! Phase 5 is a separate concern from this.
//!
//! `config::Provider::discovery_url` is the *full* discovery-document URL
//! (e.g. `https://idp.example.com/.well-known/openid-configuration`), not
//! a bare issuer — that's what operators are used to pasting from their
//! IdP's docs. We fetch it directly with `reqwest` and parse the resulting
//! provider metadata ourselves, rather than going through
//! `CoreProviderMetadata::discover_async` (which re-derives the discovery
//! URL from an issuer via `Url::join`, and mishandles issuers that have a
//! path component, e.g. Keycloak realms — joining a relative path onto a
//! base URL without a trailing slash replaces the URL's last path segment
//! instead of appending to it).

use anyhow::Context;
use openidconnect::core::{CoreClient, CoreProviderMetadata};
use openidconnect::{
    ClientId, ClientSecret, EndpointMaybeSet, EndpointNotSet, EndpointSet, JsonWebKeySet,
    RedirectUrl,
};

use crate::config::Provider as ProviderConfig;

/// Clock-skew leeway applied to ID token `exp`/`iat` validation, per the
/// plan's locked-in decision.
pub const CLOCK_SKEW_LEEWAY_SECS: i64 = 60;

/// The concrete type `CoreClient` resolves to once built from discovered
/// provider metadata: auth URL is always set, token/userinfo URLs are
/// "maybe set" (discovery makes them optional at the type level even
/// though every real-world provider returns them), and device-auth /
/// introspection / revocation URLs are never set (we don't use them).
pub type DiscoveredClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

pub async fn discover(
    http_client: &openidconnect::reqwest::Client,
    provider: &ProviderConfig,
    redirect_uri: RedirectUrl,
) -> anyhow::Result<DiscoveredClient> {
    let response = http_client
        .get(provider.discovery_url.clone())
        .send()
        .await
        .with_context(|| {
            format!(
                "fetching OIDC discovery document from {}",
                provider.discovery_url
            )
        })?
        .error_for_status()
        .with_context(|| {
            format!(
                "OIDC discovery document at {} returned an error status",
                provider.discovery_url
            )
        })?;

    let bytes = response.bytes().await?;
    let metadata: CoreProviderMetadata = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parsing OIDC discovery document from {}",
            provider.discovery_url
        )
    })?;

    let jwks = JsonWebKeySet::fetch_async(metadata.jwks_uri(), http_client)
        .await
        .with_context(|| format!("fetching JWKS for provider at {}", provider.discovery_url))?;
    let metadata = metadata.set_jwks(jwks);

    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(provider.client_secret.clone())),
    )
    .set_redirect_uri(redirect_uri);

    Ok(client)
}

/// Builds the shared HTTP client used for discovery, token exchange, and
/// JWKS fetches. Redirects are disabled per the crate's own SSRF guidance.
pub fn build_http_client() -> anyhow::Result<openidconnect::reqwest::Client> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .context("failed to build HTTP client")
}
