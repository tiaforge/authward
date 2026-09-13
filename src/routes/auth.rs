//! `/login`, `/callback`, `/verify` — Phase 1's OIDC core, scoped to a
//! single provider/base domain per the plan (multi-host resolution for
//! `/verify` lands in Phase 3; silent refresh in Phase 2).
//!
//! PKCE state (verifier, nonce, CSRF state, `rd`) lives entirely in a
//! short-lived, encrypted flow cookie on the user's own browser — never in
//! shared server-side memory. That's what makes the "two concurrent login
//! flows never cross-contaminate" property structural rather than
//! incidental (see the plan's security-review pass re: tinyauth
//! CVE-2026-33544).

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::{Cookie, PrivateCookieJar, SameSite};
use chrono::{Duration as ChronoDuration, Utc};
use cookie::time::Duration as CookieDuration;
use openidconnect::core::CoreAuthenticationFlow;
use openidconnect::{
    AuthorizationCode, CsrfToken, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    Scope, TokenResponse,
};
use serde::{Deserialize, Serialize};

use crate::db;
use crate::host::{cookies_should_be_secure, resolve_incoming_host};
use crate::oidc::CLOCK_SKEW_LEEWAY_SECS;
use crate::redirect::validate_redirect_target;
use crate::state::AppState;
use crate::templates::ErrorPage;

const SESSION_COOKIE_NAME: &str = "fa_session";
const FLOW_COOKIE_NAME: &str = "fa_flow";
const FLOW_COOKIE_MAX_AGE_MINUTES: i64 = 10;

#[derive(Deserialize)]
pub struct LoginParams {
    rd: Option<String>,
}

#[derive(Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct FlowState {
    csrf_state: String,
    nonce: String,
    pkce_verifier: String,
    rd: String,
    base_domain: String,
}

fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    (status, ErrorPage { title, message }).into_response()
}

/// `auth.<base_domain>` requests resolve to a base domain by matching the
/// incoming `Host`/`X-Forwarded-Host` against each configured base
/// domain's `auth_subdomain` — this is *not* the per-app host lookup
/// (`X-Forwarded-Host` of the protected app), which is Phase 3.
fn base_domain_for_auth_host<'a>(
    state: &'a AppState,
    host: &str,
) -> Option<&'a crate::config::BaseDomain> {
    state
        .config
        .base_domains
        .values()
        .find(|bd| bd.auth_subdomain.eq_ignore_ascii_case(host))
}

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<LoginParams>,
    jar: PrivateCookieJar,
) -> Response {
    let Some(host) = resolve_incoming_host(&headers) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "Missing Host header.",
        );
    };
    let Some(base_domain) = base_domain_for_auth_host(&state, &host) else {
        return error_page(
            StatusCode::BAD_GATEWAY,
            "Unknown auth host",
            "This host isn't configured as an auth subdomain for any base domain.",
        );
    };
    let Some(oidc_client) = state.oidc_clients.get(&base_domain.name) else {
        return error_page(
            StatusCode::BAD_GATEWAY,
            "Provider unavailable",
            "The identity provider for this domain could not be reached at startup.",
        );
    };

    let rd = params
        .rd
        .as_deref()
        .and_then(|rd| validate_redirect_target(rd, &base_domain.name))
        .unwrap_or_else(|| format!("https://{}/", base_domain.auth_subdomain));

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token, nonce) = oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let flow = FlowState {
        csrf_state: csrf_token.secret().clone(),
        nonce: nonce.secret().clone(),
        pkce_verifier: pkce_verifier.secret().clone(),
        rd,
        base_domain: base_domain.name.clone(),
    };
    let flow_json = match serde_json::to_string(&flow) {
        Ok(json) => json,
        Err(_) => {
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal error",
                "Failed to start login.",
            );
        }
    };

    let flow_cookie = Cookie::build((FLOW_COOKIE_NAME, flow_json))
        .path("/")
        .http_only(true)
        .secure(cookies_should_be_secure(&headers))
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::minutes(FLOW_COOKIE_MAX_AGE_MINUTES))
        .build();
    let jar = jar.add(flow_cookie);

    (jar, Redirect::to(auth_url.as_str())).into_response()
}

pub async fn callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
    jar: PrivateCookieJar,
) -> Response {
    let Some(flow_cookie) = jar.get(FLOW_COOKIE_NAME) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Login expired",
            "Your login session expired or was already used. Please try logging in again.",
        );
    };
    let jar = jar.clone().remove(Cookie::from(FLOW_COOKIE_NAME));

    let flow: FlowState = match serde_json::from_str(flow_cookie.value()) {
        Ok(flow) => flow,
        Err(_) => {
            return error_page(
                StatusCode::BAD_REQUEST,
                "Login expired",
                "Please try logging in again.",
            );
        }
    };

    if let Some(error) = params.error {
        tracing::warn!(error, description = ?params.error_description, "identity provider returned an error");
        return error_page(
            StatusCode::BAD_GATEWAY,
            "Login failed",
            "The identity provider declined the login request.",
        );
    }

    let Some(returned_state) = params.state else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Login failed",
            "Missing state parameter.",
        );
    };
    if returned_state != flow.csrf_state {
        tracing::warn!("callback state mismatch — possible CSRF or stale flow cookie");
        return error_page(
            StatusCode::BAD_REQUEST,
            "Login failed",
            "Invalid login state.",
        );
    }

    let Some(code) = params.code else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Login failed",
            "Missing authorization code.",
        );
    };

    let Some(oidc_client) = state.oidc_clients.get(&flow.base_domain) else {
        return error_page(
            StatusCode::BAD_GATEWAY,
            "Provider unavailable",
            "Unknown provider for this login.",
        );
    };

    let token_request = match oidc_client.exchange_code(AuthorizationCode::new(code)) {
        Ok(req) => req,
        Err(err) => {
            tracing::error!(%err, "failed to build token exchange request");
            return error_page(
                StatusCode::BAD_GATEWAY,
                "Login failed",
                "Could not contact the identity provider.",
            );
        }
    };

    let token_response = match token_request
        .set_pkce_verifier(PkceCodeVerifier::new(flow.pkce_verifier.clone()))
        .request_async(&state.http_client)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(%err, "token exchange failed");
            return error_page(
                StatusCode::BAD_GATEWAY,
                "Login failed",
                "The identity provider rejected the login or could not be reached.",
            );
        }
    };

    let Some(id_token) = token_response.id_token() else {
        return error_page(
            StatusCode::BAD_GATEWAY,
            "Login failed",
            "The identity provider did not return an ID token.",
        );
    };

    let verifier = oidc_client
        .id_token_verifier()
        .set_time_fn(|| Utc::now() - ChronoDuration::seconds(CLOCK_SKEW_LEEWAY_SECS))
        .set_issue_time_verifier_fn(|iat| {
            if iat > Utc::now() + ChronoDuration::seconds(CLOCK_SKEW_LEEWAY_SECS) {
                Err(
                    "id_token issued too far in the future (clock skew beyond allowed leeway)"
                        .to_string(),
                )
            } else {
                Ok(())
            }
        });

    let claims = match id_token.claims(&verifier, &Nonce::new(flow.nonce.clone())) {
        Ok(claims) => claims,
        Err(err) => {
            tracing::warn!(?err, "id_token claims verification failed");
            return error_page(
                StatusCode::BAD_GATEWAY,
                "Login failed",
                "Could not verify the identity provider's response.",
            );
        }
    };

    let subject = claims.subject().as_str().to_string();
    let email = claims.email().as_ref().map(|e| e.as_str().to_string());
    let claims_json = crate::oidc::decode_claims_json(&id_token.to_string()).unwrap_or_else(|err| {
        tracing::warn!(%err, "failed to decode id_token claims for group checks; treating as empty");
        serde_json::Value::Null
    });

    let session_id = crate::crypto::random_hex(32);
    let refresh_token = token_response
        .refresh_token()
        .map(|t| state.refresh_cipher.encrypt(t.secret()));
    let ttl = token_response
        .expires_in()
        .unwrap_or(state.config.global.session_ttl_fallback);
    let expires_at = Utc::now()
        + ChronoDuration::from_std(ttl).unwrap_or_else(|_| {
            ChronoDuration::seconds(state.config.global.session_ttl_fallback.as_secs() as i64)
        });
    let user_agent = headers.get("user-agent").and_then(|v| v.to_str().ok());

    if let Err(err) = db::create_session(
        &state.db,
        &session_id,
        &flow.base_domain,
        &subject,
        email.as_deref(),
        refresh_token,
        expires_at,
        user_agent,
        &claims_json,
    )
    .await
    {
        tracing::error!(%err, "failed to persist session");
        return error_page(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Login failed",
            "Could not create a session.",
        );
    }

    tracing::info!(subject, base_domain = flow.base_domain, "login succeeded");

    let session_cookie = Cookie::build((SESSION_COOKIE_NAME, session_id))
        .domain(format!(".{}", flow.base_domain))
        .path("/")
        .http_only(true)
        .secure(cookies_should_be_secure(&headers))
        .same_site(SameSite::Lax)
        .build();
    let jar = jar.add(session_cookie);

    (jar, Redirect::to(&flow.rd)).into_response()
}

pub async fn verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: PrivateCookieJar,
) -> Response {
    let Some(host) = resolve_incoming_host(&headers) else {
        tracing::error!("verify: request has no Host or X-Forwarded-Host header");
        return StatusCode::BAD_GATEWAY.into_response();
    };
    let Some(resolved_host) = state.config.resolve_host(&host) else {
        tracing::error!(
            host,
            "verify: no per-host config and no fallback provider configured"
        );
        return StatusCode::BAD_GATEWAY.into_response();
    };

    let Some(cookie) = jar.get(SESSION_COOKIE_NAME) else {
        return StatusCode::UNAUTHORIZED.into_response();
    };

    let session =
        match crate::session::verify_session(&state, cookie.value(), &resolved_host.base_domain)
            .await
        {
            crate::session::VerifyOutcome::Valid(session) => session,
            crate::session::VerifyOutcome::Invalid => {
                return StatusCode::UNAUTHORIZED.into_response();
            }
        };

    // Group-membership authorization (Phase 4): no `required_group`
    // configured on this host means no check, any valid login passes.
    if let Some(required_group) = &resolved_host.required_group
        && !crate::authz::has_required_group(
            &session.claims_json,
            &resolved_host.group_claim_name,
            required_group,
        )
    {
        tracing::info!(subject = %session.subject, host, required_group, "denied: missing required group");
        return error_page(
            StatusCode::FORBIDDEN,
            "Not authorized",
            "You're signed in, but you don't have access to this application.",
        );
    }

    StatusCode::OK.into_response()
}
