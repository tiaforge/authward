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
use openidconnect::core::{CoreClient, CoreJsonWebKey, CoreProviderMetadata};
use openidconnect::{
    ClientId, ClientSecret, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl,
    JsonWebKeySet, JsonWebKeySetUrl, RedirectUrl,
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

/// Everything a base domain's discovery step produces: the OIDC client
/// used for the browser login/refresh flows, plus the issuer and JWKS
/// separately, since bearer-token validation (Phase 5) needs its *own*,
/// independently-refreshable copy of the JWKS — the client's is baked in
/// at construction and never changes.
pub struct DiscoveredProvider {
    pub client: DiscoveredClient,
    pub issuer: IssuerUrl,
    pub jwks_uri: JsonWebKeySetUrl,
    pub jwks: JsonWebKeySet<CoreJsonWebKey>,
    /// RP-Initiated Logout 1.0's `end_session_endpoint` (Phase 8) — not
    /// part of OIDC Core, so read directly out of the raw discovery JSON
    /// rather than through `CoreProviderMetadata`, which doesn't model it.
    /// `None` means the provider doesn't support it; logout then just
    /// clears the local session, no IdP round trip.
    pub end_session_endpoint: Option<url::Url>,
}

pub async fn discover(
    http_client: &openidconnect::reqwest::Client,
    provider: &ProviderConfig,
    redirect_uri: RedirectUrl,
) -> anyhow::Result<DiscoveredProvider> {
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
    let end_session_endpoint = serde_json::from_slice::<serde_json::Value>(&bytes)
        .ok()
        .and_then(|v| v.get("end_session_endpoint")?.as_str().map(str::to_string))
        .and_then(|s| url::Url::parse(&s).ok());

    let issuer = metadata.issuer().clone();
    let jwks_uri = metadata.jwks_uri().clone();
    let jwks = JsonWebKeySet::fetch_async(&jwks_uri, http_client)
        .await
        .with_context(|| format!("fetching JWKS for provider at {}", provider.discovery_url))?;
    let metadata = metadata.set_jwks(jwks.clone());

    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(provider.client_id.clone()),
        Some(ClientSecret::new(provider.client_secret.clone())),
    )
    .set_redirect_uri(redirect_uri);

    Ok(DiscoveredProvider {
        client,
        issuer,
        jwks_uri,
        jwks,
        end_session_endpoint,
    })
}

/// Re-fetches just the JWKS for a provider, using its already-known
/// `jwks_uri` (from the initial [`discover`] call) — no need to re-fetch
/// or re-parse the discovery document itself.
pub async fn fetch_jwks(
    http_client: &openidconnect::reqwest::Client,
    jwks_uri: &JsonWebKeySetUrl,
) -> anyhow::Result<JsonWebKeySet<CoreJsonWebKey>> {
    JsonWebKeySet::fetch_async(jwks_uri, http_client)
        .await
        .with_context(|| format!("fetching JWKS from {}", jwks_uri.url()))
}

/// Builds the shared HTTP client used for discovery, token exchange, and
/// JWKS fetches. Redirects are disabled per the crate's own SSRF guidance.
pub fn build_http_client() -> anyhow::Result<openidconnect::reqwest::Client> {
    openidconnect::reqwest::ClientBuilder::new()
        .redirect(openidconnect::reqwest::redirect::Policy::none())
        .build()
        .context("failed to build HTTP client")
}

/// Decodes the raw claims payload out of an ID token's compact JWT
/// representation (`header.payload.signature`), as plain JSON.
///
/// This is *not* itself a signature check — call it only on a token whose
/// signature/issuer/audience/expiry have already been verified via
/// [`openidconnect::IdToken::claims`]. It exists because that verified,
/// strongly-typed `IdTokenClaims` only models OIDC's standard claims;
/// group/role claims live under a provider-specific, per-host-configurable
/// key (`group_claim_name`) that no static Rust type can name in advance.
/// Reading an extra field out of a payload whose signature was already
/// checked doesn't introduce a new trust boundary — the whole payload is
/// covered by that one signature.
pub fn decode_claims_json(compact_jwt: &str) -> anyhow::Result<serde_json::Value> {
    use base64::Engine;

    let payload = compact_jwt
        .split('.')
        .nth(1)
        .context("malformed JWT: expected header.payload.signature")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .context("failed to base64url-decode JWT payload")?;
    serde_json::from_slice(&bytes).context("failed to parse JWT payload as JSON")
}
