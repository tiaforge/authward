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

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
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

const SESSION_COOKIE_NAME: &str = "authgate_session";
const FLOW_COOKIE_NAME: &str = "authgate_flow";
const FLOW_COOKIE_MAX_AGE_MINUTES: i64 = 10;

#[derive(Deserialize)]
pub struct LoginParams {
    rd: Option<String>,
}

#[derive(Deserialize)]
pub struct TokenParams {
    /// Which configured host's resource to request a token for.
    host: String,
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
    /// Which provider this login runs against (see
    /// `config::ResolvedHost::provider_key`) — the host named by `rd`'s,
    /// or the `/token` target host's, falling back to the base domain's
    /// default. Recorded on the resulting session.
    provider_key: String,
    /// Set only for a `/token` flow (Phase 5): on success, `/callback`
    /// displays the access token once instead of creating a session.
    resource: Option<String>,
}

fn error_page(status: StatusCode, title: &str, message: &str) -> Response {
    (status, ErrorPage { title, message }).into_response()
}

/// `/callback`'s error responses carry the jar so the flow cookie's
/// removal actually reaches the browser; otherwise a failed callback
/// leaves the (still-valid) flow state sitting there for ten minutes.
fn error_page_clearing_flow(
    jar: PrivateCookieJar,
    status: StatusCode,
    title: &str,
    message: &str,
) -> Response {
    (jar, error_page(status, title, message)).into_response()
}

/// CSRF guard for the state-changing POST routes, on top of SameSite=Lax —
/// which is no help against a compromised sibling app on the same base
/// domain, since that's same-*site*. Browsers send `Sec-Fetch-Site` and
/// `Origin` on cross-origin POSTs; either one with a foreign value is
/// refused. A request with neither is a non-browser client and passes:
/// CSRF is a browser problem. Returns the 403 to send when refused.
fn same_origin_denial(headers: &HeaderMap, auth_subdomain: &str) -> Option<Response> {
    let denied = || {
        tracing::warn!("cross-origin POST to a state-changing route refused");
        error_page(
            StatusCode::FORBIDDEN,
            "Request refused",
            "This action can only be taken from the account page itself.",
        )
    };
    if let Some(site) = headers.get("sec-fetch-site").and_then(|v| v.to_str().ok())
        && !matches!(site, "same-origin" | "none")
    {
        return Some(denied());
    }
    if let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        let same_origin = url::Url::parse(origin)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.eq_ignore_ascii_case(auth_subdomain)))
            .unwrap_or(false);
        if !same_origin {
            return Some(denied());
        }
    }
    None
}

/// `/verify`'s 401, carrying the login URL Caddy should redirect to as
/// `X-Login-Url`. Built here, with the original request URL properly
/// query-encoded inside `rd` — a Caddyfile `redir ...?rd={scheme}://{host}{uri}`
/// embeds the original URI raw, so any `&` in its query string truncates
/// `rd`. The Caddyfile reads it back as `{http.reverse_proxy.header.X-Login-Url}`.
fn unauthorized(
    state: &AppState,
    headers: &HeaderMap,
    host: &str,
    resolved_host: &crate::config::ResolvedHost,
) -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    let Some(base_domain) = state.config.base_domains.get(&resolved_host.base_domain) else {
        return response;
    };
    let proto = match headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        Some(p) if p.eq_ignore_ascii_case("http") => "http",
        _ => "https",
    };
    let uri = headers
        .get("x-forwarded-uri")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("/");
    let Ok(mut login) = url::Url::parse(&format!("https://{}/login", base_domain.auth_subdomain))
    else {
        return response;
    };
    login
        .query_pairs_mut()
        .append_pair("rd", &format!("{proto}://{host}{uri}"));
    if let Ok(value) = HeaderValue::from_str(login.as_str()) {
        response.headers_mut().insert("x-login-url", value);
    }
    response
}

/// Per-IP rate limit on `/login`/`/token` and `/callback` (Phase 9).
/// Returns `Some(response)` when the request should be rejected; `None`
/// means proceed. Fails open (no limiting) when the client IP can't be
/// determined — an unavailable `X-Forwarded-For` is treated as
/// "can't rate-limit this one" rather than a reason to block everyone.
fn rate_limit_check(state: &AppState, headers: &HeaderMap) -> Option<Response> {
    let ip = crate::ratelimit::client_ip(headers)?;
    if state.login_rate_limiter.check(ip) {
        None
    } else {
        tracing::info!(%ip, "rate limit exceeded on login/callback");
        Some(error_page(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many requests",
            "Please wait a moment before trying again.",
        ))
    }
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
    start_authorization(&state, &headers, jar, params.rd, None, None).await
}

/// The provider a `/login` should run against: whichever the host in the
/// (already validated, same-base-domain) `rd` uses, so a redirect from a
/// host with a provider override logs in at *that* IdP. Anything else —
/// no `rd`, an unconfigured host, the auth subdomain itself — is the base
/// domain's default.
fn provider_key_for_redirect(
    state: &AppState,
    rd: &str,
    base_domain: &crate::config::BaseDomain,
) -> String {
    url::Url::parse(rd)
        .ok()
        .and_then(|url| url.host_str().map(str::to_ascii_lowercase))
        .and_then(|host| state.config.resolve_host(&host))
        .filter(|resolved| resolved.base_domain == base_domain.name)
        .map(|resolved| resolved.provider_key.clone())
        .unwrap_or_else(|| base_domain.name.clone())
}

/// `/token` helper (Phase 5): authenticates the user exactly like `/login`,
/// but adds `resource=<host's resource>` to the authorization request so
/// the IdP scopes the issued access token to it, and displays that token
/// once on `/callback` instead of creating a session.
pub async fn token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<TokenParams>,
    jar: PrivateCookieJar,
) -> Response {
    let Some(host) = resolve_incoming_host(&headers) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "Missing Host header.",
        );
    };
    let Some(auth_base_domain) = base_domain_for_auth_host(&state, &host) else {
        return error_page(
            StatusCode::BAD_GATEWAY,
            "Unknown auth host",
            "This host isn't configured as an auth subdomain for any base domain.",
        );
    };

    let Some(target_host) = state.config.hosts.get(&params.host.to_ascii_lowercase()) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Unknown host",
            "That host isn't configured on this service.",
        );
    };
    if target_host.base_domain != auth_base_domain.name {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Wrong auth domain",
            "That host belongs to a different base domain than this auth subdomain.",
        );
    }
    let Some(resource) = target_host.resource.clone() else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "No API resource configured",
            "This host has no `resource` configured, so no API token can be issued for it.",
        );
    };

    start_authorization(
        &state,
        &headers,
        jar,
        None,
        Some(resource),
        Some(target_host.provider_key.clone()),
    )
    .await
}

/// Shared by `/login` and `/token`: resolves the auth subdomain to its
/// base domain, builds the authorization URL (with PKCE/state/nonce, and
/// `resource` when requesting an API token), and stashes everything the
/// eventual `/callback` needs in an encrypted flow cookie.
async fn start_authorization(
    state: &AppState,
    headers: &HeaderMap,
    jar: PrivateCookieJar,
    rd: Option<String>,
    resource: Option<String>,
    provider_key: Option<String>,
) -> Response {
    if let Some(response) = rate_limit_check(state, headers) {
        return response;
    }

    let Some(host) = resolve_incoming_host(headers) else {
        return error_page(
            StatusCode::BAD_REQUEST,
            "Bad request",
            "Missing Host header.",
        );
    };
    let Some(base_domain) = base_domain_for_auth_host(state, &host) else {
        return error_page(
            StatusCode::BAD_GATEWAY,
            "Unknown auth host",
            "This host isn't configured as an auth subdomain for any base domain.",
        );
    };

    let rd = rd
        .as_deref()
        .and_then(|rd| validate_redirect_target(rd, &base_domain.name))
        .unwrap_or_else(|| format!("https://{}/", base_domain.auth_subdomain));

    let provider_key =
        provider_key.unwrap_or_else(|| provider_key_for_redirect(state, &rd, base_domain));
    let Some(oidc_client) = state.oidc_clients.get(&provider_key) else {
        return error_page(
            StatusCode::BAD_GATEWAY,
            "Provider unavailable",
            "The identity provider for this domain could not be reached at startup.",
        );
    };

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let mut request = oidc_client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .set_pkce_challenge(pkce_challenge);
    if let Some(resource) = &resource {
        // RFC 8707 resource indicator, so the IdP scopes the issued
        // access token's audience to this specific resource.
        request = request.add_extra_param("resource", resource.clone());
    }
    let (auth_url, csrf_token, nonce) = request.url();

    let flow = FlowState {
        csrf_state: csrf_token.secret().clone(),
        nonce: nonce.secret().clone(),
        pkce_verifier: pkce_verifier.secret().clone(),
        rd,
        base_domain: base_domain.name.clone(),
        provider_key,
        resource,
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
        .secure(cookies_should_be_secure(headers))
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
    if let Some(response) = rate_limit_check(&state, &headers) {
        return response;
    }

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
            return error_page_clearing_flow(
                jar,
                StatusCode::BAD_REQUEST,
                "Login expired",
                "Please try logging in again.",
            );
        }
    };

    if let Some(error) = params.error {
        tracing::warn!(error, description = ?params.error_description, "identity provider returned an error");
        return error_page_clearing_flow(
            jar,
            StatusCode::BAD_GATEWAY,
            "Login failed",
            "The identity provider declined the login request.",
        );
    }

    let Some(returned_state) = params.state else {
        return error_page_clearing_flow(
            jar,
            StatusCode::BAD_REQUEST,
            "Login failed",
            "Missing state parameter.",
        );
    };
    // Constant-time: the state value is compared against attacker-
    // influenceable input (the callback query string), so a naive `!=`
    // could in principle leak timing information about the real value —
    // standard JWT/cookie-signing libraries already do this internally
    // for their own comparisons, but this one is ours (Phase 11).
    use subtle::ConstantTimeEq;
    if returned_state
        .as_bytes()
        .ct_eq(flow.csrf_state.as_bytes())
        .unwrap_u8()
        != 1
    {
        tracing::warn!("callback state mismatch — possible CSRF or stale flow cookie");
        return error_page_clearing_flow(
            jar,
            StatusCode::BAD_REQUEST,
            "Login failed",
            "Invalid login state.",
        );
    }

    let Some(code) = params.code else {
        return error_page_clearing_flow(
            jar,
            StatusCode::BAD_REQUEST,
            "Login failed",
            "Missing authorization code.",
        );
    };

    let Some(oidc_client) = state.oidc_clients.get(&flow.provider_key) else {
        return error_page_clearing_flow(
            jar,
            StatusCode::BAD_GATEWAY,
            "Provider unavailable",
            "Unknown provider for this login.",
        );
    };

    let token_request = match oidc_client.exchange_code(AuthorizationCode::new(code)) {
        Ok(req) => req,
        Err(err) => {
            tracing::error!(%err, "failed to build token exchange request");
            return error_page_clearing_flow(
                jar,
                StatusCode::BAD_GATEWAY,
                "Login failed",
                "Could not contact the identity provider.",
            );
        }
    };

    let mut token_request =
        token_request.set_pkce_verifier(PkceCodeVerifier::new(flow.pkce_verifier.clone()));
    if let Some(resource) = &flow.resource {
        // RFC 8707: include the resource indicator on the token request
        // too, not just the authorization request.
        token_request = token_request.add_extra_param("resource", resource.clone());
    }

    let token_response = match token_request.request_async(&state.http_client).await {
        Ok(response) => response,
        Err(err) => {
            tracing::error!(%err, "token exchange failed");
            return error_page_clearing_flow(
                jar,
                StatusCode::BAD_GATEWAY,
                "Login failed",
                "The identity provider rejected the login or could not be reached.",
            );
        }
    };

    let Some(id_token) = token_response.id_token() else {
        return error_page_clearing_flow(
            jar,
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
            return error_page_clearing_flow(
                jar,
                StatusCode::BAD_GATEWAY,
                "Login failed",
                "Could not verify the identity provider's response.",
            );
        }
    };

    if let Some(resource) = &flow.resource {
        // /token flow (Phase 5): show the access token once, no session.
        let access_token = token_response.access_token().secret().clone();
        return (
            jar,
            [(axum::http::header::CACHE_CONTROL, "no-store")],
            crate::templates::TokenPage {
                resource,
                access_token: &access_token,
            },
        )
            .into_response();
    }

    let subject = claims.subject().as_str().to_string();
    // An unverified email is whatever the user typed into their profile;
    // forwarding it as X-Auth-Email would let them impersonate anyone at a
    // backend that keys on email. Verified or nothing.
    let email = match (claims.email(), claims.email_verified()) {
        (Some(email), Some(true)) => Some(email.as_str().to_string()),
        (Some(_), _) => {
            tracing::debug!(
                subject,
                "id_token email is not marked verified; not storing it"
            );
            None
        }
        (None, _) => None,
    };
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
        &flow.provider_key,
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
        return error_page_clearing_flow(
            jar,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Login failed",
            "Could not create a session.",
        );
    }

    tracing::info!(
        subject,
        base_domain = flow.base_domain,
        provider_key = flow.provider_key,
        "login succeeded"
    );

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

    // Bypass paths (Phase 9) skip auth entirely — checked before touching
    // the session/bearer-token logic at all. Caddy carries the original
    // app request's path+query in X-Forwarded-Uri; its absence just means
    // no bypass can apply (fails closed into normal auth, not open).
    if let Some(uri) = headers.get("x-forwarded-uri").and_then(|v| v.to_str().ok())
        && crate::bypass::matches_bypass(uri, &resolved_host.bypass_paths)
    {
        return ok_with_identity("", "", "");
    }

    // No usable session — no cookie at all, or one that no longer names a
    // valid session for this host — falls back to a resource-scoped bearer
    // token (Phase 5), for non-browser clients. A stale cookie must not
    // shadow a good bearer token: a script on a machine whose browser
    // profile once logged in would otherwise get 401s until that cookie
    // expired. Unavailable for this host (no `resource` configured, or
    // provider has no JWKS cache) is not an error — it just means there's
    // nothing left to try, and `bearer_auth` answers with the same 401.
    let Some(cookie) = jar.get(SESSION_COOKIE_NAME) else {
        return bearer_auth(&state, &headers, &host, resolved_host).await;
    };

    let session = match crate::session::verify_session(
        &state,
        cookie.value(),
        &resolved_host.base_domain,
        Some(&resolved_host.provider_key),
    )
    .await
    {
        crate::session::VerifyOutcome::Valid(session) => session,
        crate::session::VerifyOutcome::Invalid => {
            return bearer_auth(&state, &headers, &host, resolved_host).await;
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

    ok_response(
        resolved_host,
        &session.subject,
        session.email.as_deref(),
        &session.claims_json,
    )
}

/// Resource-scoped bearer-token bypass (Phase 5) for non-browser clients.
/// Reached when `/verify` found no session cookie, or one that doesn't
/// name a valid session for this host.
async fn bearer_auth(
    state: &AppState,
    headers: &HeaderMap,
    host: &str,
    resolved_host: &crate::config::ResolvedHost,
) -> Response {
    let Some(resource) = &resolved_host.resource else {
        return unauthorized(state, headers, host, resolved_host);
    };
    let Some(cache) = state.jwks_caches.get(&resolved_host.provider_key) else {
        return unauthorized(state, headers, host, resolved_host);
    };
    // RFC 9110 §11.1: the auth scheme is case-insensitive, so `bearer`
    // and `BEARER` are the same scheme as `Bearer`.
    let Some(token) = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            let (scheme, rest) = v.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| rest.trim_start())
        })
    else {
        return unauthorized(state, headers, host, resolved_host);
    };

    match crate::bearer::validate(
        cache,
        &state.http_client,
        resource,
        resolved_host.required_scope.as_deref(),
        token,
    )
    .await
    {
        Ok(claims) => {
            // Group-membership authorization applies to resource-scoped
            // tokens too (Phase 11 decision), not just browser sessions —
            // a host that requires a group shouldn't be reachable via an
            // API token just because that path skipped the check. If the
            // IdP's access tokens don't carry the group claim at all,
            // this fails closed (denies) rather than silently skipping
            // the check, consistent with the rest of this codebase.
            if let Some(required_group) = &resolved_host.required_group
                && !crate::authz::has_required_group(
                    &claims,
                    &resolved_host.group_claim_name,
                    required_group,
                )
            {
                tracing::info!(host = ?resolved_host.host, required_group, "bearer token denied: missing required group");
                return StatusCode::FORBIDDEN.into_response();
            }

            let subject = claims
                .get("sub")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            // Same rule as the login path: verified email or nothing.
            let email = claims
                .get("email")
                .and_then(|v| v.as_str())
                .filter(|_| claims.get("email_verified").and_then(|v| v.as_bool()) == Some(true));
            ok_response(resolved_host, subject, email, &claims)
        }
        Err(err) => {
            tracing::info!(%err, host = ?resolved_host.host, "bearer token rejected");
            unauthorized(state, headers, host, resolved_host)
        }
    }
}

const IDENTITY_HEADER_NAMES: [&str; 3] = ["x-auth-user", "x-auth-email", "x-auth-groups"];

/// Every successful `/verify` response carries all three identity headers,
/// even when there's nothing to forward (host has `forward_identity_headers`
/// off, bypass path, no email claim) — as empty values in that case.
///
/// Caddy's `copy_headers` only overwrites a client-supplied header when this
/// response actually carries it; on Caddy 2.10.0–2.11.1 (GHSA-7r4p-vjf4-gxv4)
/// an absent header leaves the client's own `X-Auth-User` in place and
/// forwards it to the backend. Emitting the header unconditionally makes
/// the overwrite happen on every Caddy version. A value that can't be
/// encoded as a header is a hard failure rather than a silently dropped
/// header, for the same reason.
fn ok_with_identity(user: &str, email: &str, groups: &str) -> Response {
    let mut headers = HeaderMap::new();
    for (name, value) in IDENTITY_HEADER_NAMES.iter().zip([user, email, groups]) {
        match HeaderValue::from_str(value) {
            Ok(value) => {
                headers.insert(*name, value);
            }
            Err(_) => {
                tracing::error!(
                    header = name,
                    "identity value is not a valid HTTP header value; refusing to forward"
                );
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    }
    (StatusCode::OK, headers).into_response()
}

/// Successful `/verify` response with verified identity (Phase 7) when the
/// host has `forward_identity_headers` enabled. The backend must still be
/// unreachable except through the proxy (see the plan's trust-boundary
/// decision) — the overwrite is Caddy's job, not something this response
/// can enforce by itself.
fn ok_response(
    resolved_host: &crate::config::ResolvedHost,
    subject: &str,
    email: Option<&str>,
    claims_json: &serde_json::Value,
) -> Response {
    if !resolved_host.forward_identity_headers {
        return ok_with_identity("", "", "");
    }

    let groups = match claims_json.get(&resolved_host.group_claim_name) {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|v| v.as_str())
            .collect::<Vec<_>>()
            .join(","),
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => String::new(),
    };
    ok_with_identity(subject, email.unwrap_or(""), &groups)
}

#[derive(Deserialize)]
pub struct RevokeParams {
    /// A `session::session_handle`, never a raw session ID.
    session: String,
}

/// `/` overview page (Phase 6): who's logged in, their other active
/// sessions on this base domain, and links to request an API token for
/// any host that has one configured. Behind normal auth, exactly like a
/// protected app — redirects to `/login` if there's no valid session.
pub async fn overview(
    State(state): State<AppState>,
    headers: HeaderMap,
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

    let Some(session) = current_session(&state, &jar, &base_domain.name).await else {
        return redirect_to_login(&base_domain.auth_subdomain);
    };

    let sessions = match db::list_sessions_for_subject(
        &state.db,
        &base_domain.name,
        &session.provider_key,
        &session.subject,
    )
    .await
    {
        Ok(sessions) => sessions,
        Err(err) => {
            tracing::error!(%err, "failed to list sessions for dashboard");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error",
                "Could not load your sessions.",
            );
        }
    };

    let session_rows = sessions
        .iter()
        .map(|s| crate::templates::SessionRow {
            handle: crate::session::session_handle(&s.id),
            created_at: s.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            user_agent: s
                .user_agent
                .clone()
                .unwrap_or_else(|| "unknown device".to_string()),
            is_current: s.id == session.id,
        })
        .collect();

    let token_hosts: Vec<&str> = state
        .config
        .hosts
        .values()
        .filter(|h| h.base_domain == base_domain.name && h.resource.is_some())
        .filter_map(|h| h.host.as_deref())
        .collect();

    crate::templates::DashboardPage {
        subject: &session.subject,
        email: session.email.as_deref(),
        sessions: session_rows,
        token_hosts,
    }
    .into_response()
}

/// Logs out a *different* device (Phase 6) — deletes one session row,
/// named by its opaque handle. POST-only (see the router), same-origin
/// only, and the handle is only ever matched against the caller's own
/// sessions on this base domain, so a valid session lets you manage your
/// own other sessions but never anyone else's.
pub async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    jar: PrivateCookieJar,
    Form(params): Form<RevokeParams>,
) -> Response {
    let Some(host) = resolve_incoming_host(&headers) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Some(base_domain) = base_domain_for_auth_host(&state, &host) else {
        return StatusCode::BAD_GATEWAY.into_response();
    };
    if let Some(response) = same_origin_denial(&headers, &base_domain.auth_subdomain) {
        return response;
    }

    let Some(session) = current_session(&state, &jar, &base_domain.name).await else {
        return redirect_to_login(&base_domain.auth_subdomain);
    };

    match db::list_sessions_for_subject(
        &state.db,
        &base_domain.name,
        &session.provider_key,
        &session.subject,
    )
    .await
    {
        Ok(own_sessions) => {
            match own_sessions
                .iter()
                .find(|s| crate::session::session_handle(&s.id) == params.session)
            {
                Some(target) => {
                    if let Err(err) = db::delete_session(&state.db, &target.id).await {
                        tracing::error!(%err, "failed to revoke session");
                    }
                }
                None => {
                    tracing::warn!(subject = %session.subject, "attempted to revoke a session that isn't theirs; ignoring");
                }
            }
        }
        Err(err) => tracing::error!(%err, "failed to look up sessions to revoke"),
    }

    Redirect::to(&format!("https://{}/", base_domain.auth_subdomain)).into_response()
}

fn redirect_to_login(auth_subdomain: &str) -> Response {
    Redirect::to(&format!("https://{auth_subdomain}/login")).into_response()
}

/// Looks up the caller's own current session from their cookie, requiring
/// it to be valid for `base_domain`. Used by the dashboard routes, which
/// live on the auth subdomain itself rather than behind `forward_auth`.
async fn current_session(
    state: &AppState,
    jar: &PrivateCookieJar,
    base_domain: &str,
) -> Option<crate::db::Session> {
    let cookie = jar.get(SESSION_COOKIE_NAME)?;
    match crate::session::verify_session(state, cookie.value(), base_domain, None).await {
        crate::session::VerifyOutcome::Valid(session) => Some(session),
        crate::session::VerifyOutcome::Invalid => None,
    }
}

#[derive(Deserialize)]
pub struct LogoutParams {
    rd: Option<String>,
}

/// `/logout` (Phase 8), POST-only (see the router — CSRF hardening,
/// matching `/sessions/revoke`). Always clears the local session
/// regardless of whether the provider supports RP-Initiated Logout;
/// when it does (`end_session_endpoint` from discovery), the browser is
/// sent there afterward so the IdP's own session ends too, rather than
/// just ours.
pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<LogoutParams>,
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
    if let Some(response) = same_origin_denial(&headers, &base_domain.auth_subdomain) {
        return response;
    }

    // The IdP to log out of is the one that logged this session in — read
    // before deleting. No session (or a foreign one) means the base
    // domain's default, which is where a stray browser most likely was.
    let mut provider_key = base_domain.name.clone();
    if let Some(cookie) = jar.get(SESSION_COOKIE_NAME) {
        if let Ok(Some(session)) = db::get_session(&state.db, cookie.value()).await
            && session.base_domain == base_domain.name
        {
            provider_key = session.provider_key;
        }
        if let Err(err) = db::delete_session(&state.db, cookie.value()).await {
            tracing::error!(%err, "failed to delete session on logout");
        }
    }

    // Must match the Domain/Path the session cookie was originally set
    // with, or the browser treats this as removing an unrelated
    // host-only cookie and leaves the real one in place.
    let removal_cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .domain(format!(".{}", base_domain.name))
        .path("/")
        .build();
    let jar = jar.remove(removal_cookie);

    // Same open-redirect validation as /login's rd — no separate, less
    // strict path for logout's redirect target (Phase 8's locked-in
    // decision, extending Phase 3's).
    let local_logged_out_url = format!("https://{}/logged-out", base_domain.auth_subdomain);
    let post_logout_target = params
        .rd
        .as_deref()
        .and_then(|rd| validate_redirect_target(rd, &base_domain.name))
        .unwrap_or(local_logged_out_url);

    let redirect_url = match (
        state.end_session_endpoints.get(&provider_key),
        state.providers.get(&provider_key),
    ) {
        (Some(Some(end_session_endpoint)), Some(provider)) => {
            let mut url = end_session_endpoint.clone();
            url.query_pairs_mut()
                .append_pair("client_id", &provider.client_id)
                .append_pair("post_logout_redirect_uri", &post_logout_target);
            url.to_string()
        }
        _ => post_logout_target,
    };

    (jar, Redirect::to(&redirect_url)).into_response()
}

/// Local "logged out" confirmation page (Phase 8) — the default
/// post-logout redirect target when the provider has no RP-Initiated
/// Logout support, or when `/logout` itself was reached without one.
pub async fn logged_out() -> Response {
    error_page(StatusCode::OK, "Logged out", "You have been signed out.")
}
