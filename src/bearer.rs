//! Resource-scoped API token validation (Phase 5) — the non-browser-client
//! bypass. `/verify` falls back to this when no valid session cookie is
//! present: if the host has a `resource` configured, an
//! `Authorization: Bearer <token>` is validated locally and statelessly
//! against the provider's JWKS (no session, no SQLite row). If the host
//! has no `resource` configured, this bypass is simply unavailable —
//! falls through to the normal 401 → login redirect, never a hard error.
//!
//! This validates an OAuth2 *access* token (RFC 9068 JWT profile), not an
//! OIDC ID token, so it deliberately doesn't go through
//! `openidconnect::IdTokenVerifier` — that hardcodes the expected audience
//! to the client_id, whereas a resource-scoped token's audience is the
//! resource identifier instead.

use base64::Engine;
use openidconnect::JsonWebKey;
use openidconnect::core::{CoreJsonWebKey, CoreJwsSigningAlgorithm};

use crate::jwks_cache::JwksCache;

#[derive(Debug)]
pub enum BearerError {
    Malformed(String),
    SignatureInvalid,
    IssuerMismatch,
    AudienceMismatch,
    Expired,
    MissingScope,
}

impl std::fmt::Display for BearerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(msg) => write!(f, "malformed bearer token: {msg}"),
            Self::SignatureInvalid => write!(f, "signature verification failed"),
            Self::IssuerMismatch => write!(f, "issuer does not match this provider"),
            Self::AudienceMismatch => write!(f, "audience does not include the required resource"),
            Self::Expired => write!(f, "token is expired"),
            Self::MissingScope => write!(f, "token is missing the required scope"),
        }
    }
}

/// Validates `token` as a resource-scoped access token for `resource`,
/// refreshing the JWKS cache and retrying once if the initial signature
/// check fails — handles the IdP having rotated its signing keys since
/// the cache was last populated, without waiting for the periodic sweep.
pub async fn validate(
    cache: &JwksCache,
    http_client: &openidconnect::reqwest::Client,
    resource: &str,
    required_scope: Option<&str>,
    token: &str,
) -> Result<serde_json::Value, BearerError> {
    let jwks = cache.current().await;
    match try_validate(&jwks, cache, resource, required_scope, token) {
        Err(BearerError::SignatureInvalid) => {}
        result => return result,
    }

    if cache.refresh(http_client).await.is_err() {
        return Err(BearerError::SignatureInvalid);
    }
    let jwks = cache.current().await;
    try_validate(&jwks, cache, resource, required_scope, token)
}

fn try_validate(
    jwks: &openidconnect::JsonWebKeySet<CoreJsonWebKey>,
    cache: &JwksCache,
    resource: &str,
    required_scope: Option<&str>,
    token: &str,
) -> Result<serde_json::Value, BearerError> {
    let mut parts = token.split('.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| BearerError::Malformed("missing header".into()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| BearerError::Malformed("missing payload".into()))?;
    let signature_b64 = parts
        .next()
        .ok_or_else(|| BearerError::Malformed("missing signature".into()))?;
    if parts.next().is_some() {
        return Err(BearerError::Malformed("too many segments".into()));
    }

    let header: serde_json::Value = decode_json_segment(header_b64)?;
    let alg_str = header
        .get("alg")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BearerError::Malformed("missing header.alg".into()))?;
    let alg: CoreJwsSigningAlgorithm =
        serde_json::from_value(serde_json::Value::String(alg_str.to_string()))
            .map_err(|_| BearerError::Malformed(format!("unsupported alg {alg_str}")))?;
    let kid = header.get("kid").and_then(|v| v.as_str());

    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(signature_b64)
        .map_err(|_| BearerError::Malformed("invalid signature encoding".into()))?;
    let signing_input = format!("{header_b64}.{payload_b64}");

    let candidates: Vec<&CoreJsonWebKey> = match kid {
        Some(kid) => jwks
            .keys()
            .iter()
            .filter(|k| k.key_id().is_some_and(|k_id| k_id.as_str() == kid))
            .collect(),
        None => jwks.keys().iter().collect(),
    };
    let verified = candidates.iter().any(|key| {
        key.verify_signature(&alg, signing_input.as_bytes(), &signature)
            .is_ok()
    });
    if !verified {
        return Err(BearerError::SignatureInvalid);
    }

    let claims: serde_json::Value = decode_json_segment(payload_b64)?;

    let iss = claims.get("iss").and_then(|v| v.as_str());
    if iss != Some(cache.issuer.as_str()) {
        return Err(BearerError::IssuerMismatch);
    }

    let aud_matches = match claims.get("aud") {
        Some(serde_json::Value::String(s)) => s == resource,
        Some(serde_json::Value::Array(items)) => items.iter().any(|v| v.as_str() == Some(resource)),
        _ => false,
    };
    if !aud_matches {
        return Err(BearerError::AudienceMismatch);
    }

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or_else(|| BearerError::Malformed("missing exp".into()))?;
    let now = chrono::Utc::now().timestamp();
    if now - crate::oidc::CLOCK_SKEW_LEEWAY_SECS > exp {
        return Err(BearerError::Expired);
    }

    if let Some(required_scope) = required_scope {
        let has_scope = claims
            .get("scope")
            .and_then(|v| v.as_str())
            .map(|s| s.split_whitespace().any(|scope| scope == required_scope))
            .unwrap_or(false);
        if !has_scope {
            return Err(BearerError::MissingScope);
        }
    }

    Ok(claims)
}

fn decode_json_segment(segment: &str) -> Result<serde_json::Value, BearerError> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| BearerError::Malformed("invalid base64url".into()))?;
    serde_json::from_slice(&bytes).map_err(|_| BearerError::Malformed("invalid JSON".into()))
}
