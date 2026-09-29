//! End-to-end test of Phase 1's OIDC core against an in-process mock IdP,
//! since a real IdP isn't available in CI. Exercises: discovery, the
//! `/login` -> IdP -> `/callback` round trip, session creation, and
//! `/verify`. Also covers the plan's explicit Phase 1 test: two concurrent
//! login flows never cross-contaminate identity, because PKCE/nonce/state
//! live only in each browser's own encrypted flow cookie, never in shared
//! server state.
//!
//! Real hostnames (`auth.test.local` etc.) are never actually resolved —
//! every hop is driven manually against literal `127.0.0.1` addresses with
//! a spoofed `Host` header, and cookies are relayed by hand rather than via
//! a real cookie jar, since a `Domain=.test.local` cookie set by a response
//! that (as far as any real HTTP stack is concerned) came from `127.0.0.1`
//! would be rejected by normal cookie-jar domain-matching. That rejection
//! would be correct browser behavior for this test harness's IP-literal
//! addressing, not a bug in the service under test.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use authward::bypass;
use authward::config;
use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
use openidconnect::core::{
    CoreGenderClaim, CoreHmacKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreTokenResponse, CoreTokenType,
};
use openidconnect::{
    AccessToken, EmptyAdditionalClaims, EmptyExtraTokenFields, IdToken, IdTokenFields,
    JsonWebKeySet, PrivateSigningKey, RefreshToken,
};
use serde::Deserialize;
use serde_json::json;

const CLIENT_ID: &str = "authward-test-client";
/// Per the OIDC Core spec, HS256/384/512 ID token signatures are verified
/// using the UTF-8 bytes of the client_secret directly as the HMAC key —
/// there's no published JWKS entry for it (publishing a symmetric signing
/// key would defeat the point). So the mock IdP signs with this same
/// value that `spawn_app` configures as the client's `client_secret`.
const CLIENT_SECRET: &str = "mock-idp-shared-test-secret";

// ---- Mock IdP -------------------------------------------------------

#[derive(Clone)]
struct PendingAuth {
    nonce: String,
    subject: String,
    email: String,
    email_verified: bool,
    groups: Vec<String>,
}

#[derive(Clone)]
struct MockIdp {
    base_url: String,
    hmac_key: Arc<Mutex<CoreHmacKey>>,
    pending: Arc<Mutex<HashMap<String, PendingAuth>>>,
    /// Refresh tokens issued so far, keyed by token value. The mock
    /// *rotates* refresh tokens on every use (removing the consumed one
    /// and issuing a new one) — mirroring the "strict IdP" behavior the
    /// plan's per-session lock is specifically designed to survive: two
    /// concurrent refreshes racing to use the same now-single-use token
    /// would otherwise have one of them fail.
    refresh_tokens: Arc<Mutex<HashMap<String, PendingAuth>>>,
    /// Number of refresh_token-grant requests this mock has received —
    /// used to assert exactly one refresh call reaches the IdP even when
    /// many concurrent requests observe the same expired session.
    refresh_grant_count: Arc<AtomicUsize>,
    access_token_ttl: Duration,
    /// Artificial delay applied to refresh-token-grant requests only, to
    /// give tests a window in which a refresh is provably in-flight.
    refresh_delay: Duration,
    /// Whether this mock advertises RP-Initiated Logout support (Phase
    /// 8) via `end_session_endpoint` in its discovery document.
    supports_end_session: bool,
}

#[derive(Deserialize)]
struct AuthorizeParams {
    redirect_uri: String,
    state: String,
    nonce: String,
    /// Doubles as "which test identity is logging in" — a real IdP would
    /// show a login form; we skip straight to picking an identity.
    login_hint: Option<String>,
    /// Comma-separated group membership for this login, standing in for
    /// whatever a real IdP's admin UI would configure per user.
    groups: Option<String>,
    /// "false" makes the mock mark this login's email as unverified.
    email_verified: Option<String>,
}

#[derive(Deserialize)]
struct TokenParams {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
}

async fn discovery(State(idp): State<MockIdp>) -> Json<serde_json::Value> {
    let mut doc = json!({
        "issuer": idp.base_url,
        "authorization_endpoint": format!("{}/authorize", idp.base_url),
        "token_endpoint": format!("{}/token", idp.base_url),
        "jwks_uri": format!("{}/jwks", idp.base_url),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
    });
    if idp.supports_end_session {
        doc["end_session_endpoint"] =
            serde_json::Value::String(format!("{}/end-session", idp.base_url));
    }
    Json(doc)
}

#[derive(Deserialize)]
struct EndSessionParams {
    post_logout_redirect_uri: String,
}

/// A real IdP would end its own session here; the mock just honors the
/// redirect. The test itself inspects /logout's own Location header
/// (which points here) to confirm client_id was included, rather than
/// asserting inside a background task where a panic wouldn't fail the test.
async fn end_session(Query(params): Query<EndSessionParams>) -> impl IntoResponse {
    Redirect::to(&params.post_logout_redirect_uri)
}

async fn jwks(
    State(idp): State<MockIdp>,
) -> Json<JsonWebKeySet<openidconnect::core::CoreJsonWebKey>> {
    Json(JsonWebKeySet::new(vec![
        idp.hmac_key.lock().unwrap().as_verification_key(),
    ]))
}

async fn authorize(
    State(idp): State<MockIdp>,
    Query(params): Query<AuthorizeParams>,
) -> impl IntoResponse {
    let code = authward::crypto::random_hex(16);
    let subject = params
        .login_hint
        .unwrap_or_else(|| "default-user".to_string());
    let groups = params
        .groups
        .map(|g| g.split(',').map(str::to_string).collect())
        .unwrap_or_default();
    idp.pending.lock().unwrap().insert(
        code.clone(),
        PendingAuth {
            nonce: params.nonce,
            email: format!("{subject}@example.test"),
            email_verified: params.email_verified.as_deref() != Some("false"),
            subject,
            groups,
        },
    );

    let mut redirect_url = url::Url::parse(&params.redirect_uri).expect("valid redirect_uri");
    redirect_url
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &params.state);
    Redirect::to(redirect_url.as_str())
}

fn issue_tokens(
    idp: &MockIdp,
    identity: PendingAuth,
    nonce: Option<String>,
    refresh_token: String,
) -> CoreTokenResponse {
    // Built by hand (JSON + HMAC-SHA256) rather than via `IdTokenClaims` /
    // `IdToken::new`, so the mock can embed a `groups` claim without
    // fighting openidconnect's `AdditionalClaims` generic — the app on
    // the other end reads it back via raw JSON too (`decode_claims_json`),
    // not through any typed claims struct, so there's no mismatch.
    use base64::Engine;
    let now = Utc::now();
    let exp = now + ChronoDuration::from_std(idp.access_token_ttl).unwrap();
    let mut payload = serde_json::json!({
        "iss": idp.base_url,
        "aud": [CLIENT_ID],
        "sub": identity.subject,
        "email": identity.email,
        "email_verified": identity.email_verified,
        "iat": now.timestamp(),
        "exp": exp.timestamp(),
        "groups": identity.groups,
    });
    if let Some(nonce) = nonce {
        payload["nonce"] = serde_json::Value::String(nonce);
    }
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = idp
        .hmac_key
        .lock()
        .unwrap()
        .sign(
            &CoreJwsSigningAlgorithm::HmacSha256,
            signing_input.as_bytes(),
        )
        .expect("mock HMAC signing should not fail");
    let compact_jwt = format!(
        "{signing_input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    );

    let id_token = IdToken::<
        EmptyAdditionalClaims,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >::from_str(&compact_jwt)
    .expect("mock JWT should parse");

    idp.refresh_tokens
        .lock()
        .unwrap()
        .insert(refresh_token.clone(), identity);

    let mut response = CoreTokenResponse::new(
        AccessToken::new("mock-access-token".to_string()),
        CoreTokenType::Bearer,
        IdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    );
    response.set_expires_in(Some(&idp.access_token_ttl));
    response.set_refresh_token(Some(RefreshToken::new(refresh_token)));
    response
}

async fn token(State(idp): State<MockIdp>, Form(params): Form<TokenParams>) -> Response {
    match params.grant_type.as_str() {
        "authorization_code" => {
            let code = params.code.expect("authorization_code grant requires code");
            let pending = idp
                .pending
                .lock()
                .unwrap()
                .remove(&code)
                .expect("mock IdP received a code it never issued");
            let nonce = pending.nonce.clone();
            let refresh_token = authward::crypto::random_hex(16);
            Json(issue_tokens(&idp, pending, Some(nonce), refresh_token)).into_response()
        }
        "refresh_token" => {
            idp.refresh_grant_count.fetch_add(1, Ordering::SeqCst);
            if !idp.refresh_delay.is_zero() {
                tokio::time::sleep(idp.refresh_delay).await;
            }
            let old_token = params
                .refresh_token
                .expect("refresh_token grant requires refresh_token");
            let Some(identity) = idp.refresh_tokens.lock().unwrap().remove(&old_token) else {
                // Rotation means a refresh token is single-use; reuse (e.g.
                // from a racing duplicate request) looks like this.
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({"error": "invalid_grant"})),
                )
                    .into_response();
            };
            let new_refresh_token = authward::crypto::random_hex(16);
            Json(issue_tokens(&idp, identity, None, new_refresh_token)).into_response()
        }
        other => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "unsupported_grant_type", "grant_type": other})),
        )
            .into_response(),
    }
}

async fn spawn_mock_idp(
    access_token_ttl: Duration,
) -> (
    String,
    Arc<AtomicUsize>,
    Arc<Mutex<HashMap<String, PendingAuth>>>,
) {
    spawn_mock_idp_with_refresh_delay(access_token_ttl, Duration::ZERO).await
}

async fn spawn_mock_idp_with_refresh_delay(
    access_token_ttl: Duration,
    refresh_delay: Duration,
) -> (
    String,
    Arc<AtomicUsize>,
    Arc<Mutex<HashMap<String, PendingAuth>>>,
) {
    let (base_url, refresh_grant_count, refresh_tokens, _hmac_key) =
        spawn_mock_idp_full(access_token_ttl, refresh_delay, true).await;
    (base_url, refresh_grant_count, refresh_tokens)
}

/// Full form of `spawn_mock_idp`, also returning the mock's HMAC signing
/// key handle so a test can rotate it (Phase 5's key-rotation test) or
/// sign a hand-built bearer token directly without a real /token round
/// trip (`build_access_token`).
async fn spawn_mock_idp_full(
    access_token_ttl: Duration,
    refresh_delay: Duration,
    supports_end_session: bool,
) -> (
    String,
    Arc<AtomicUsize>,
    Arc<Mutex<HashMap<String, PendingAuth>>>,
    Arc<Mutex<CoreHmacKey>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    spawn_mock_idp_on(
        listener,
        access_token_ttl,
        refresh_delay,
        supports_end_session,
    )
    .await
}

/// `spawn_mock_idp_full` on a caller-supplied listener — for tests that
/// need the IdP to appear at an address authward already knows about
/// (a provider that was down at startup).
async fn spawn_mock_idp_on(
    listener: tokio::net::TcpListener,
    access_token_ttl: Duration,
    refresh_delay: Duration,
    supports_end_session: bool,
) -> (
    String,
    Arc<AtomicUsize>,
    Arc<Mutex<HashMap<String, PendingAuth>>>,
    Arc<Mutex<CoreHmacKey>>,
) {
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let refresh_grant_count = Arc::new(AtomicUsize::new(0));
    let hmac_key = Arc::new(Mutex::new(CoreHmacKey::new(
        CLIENT_SECRET.as_bytes().to_vec(),
    )));
    let idp = MockIdp {
        base_url: base_url.clone(),
        hmac_key: hmac_key.clone(),
        pending: Arc::new(Mutex::new(HashMap::new())),
        refresh_tokens: Arc::new(Mutex::new(HashMap::new())),
        refresh_grant_count: refresh_grant_count.clone(),
        access_token_ttl,
        refresh_delay,
        supports_end_session,
    };

    let refresh_tokens = idp.refresh_tokens.clone();
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/end-session", get(end_session))
        .with_state(idp);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (base_url, refresh_grant_count, refresh_tokens, hmac_key)
}

/// Builds a resource-scoped access token JWT by hand and signs it with
/// `hmac_key` directly — bypassing the mock's `/token` endpoint, since
/// these tests are about the app's bearer-validation logic, not a full
/// OAuth round trip.
fn build_access_token(
    hmac_key: &CoreHmacKey,
    issuer: &str,
    aud: &str,
    scope: Option<&str>,
    exp_offset_secs: i64,
) -> String {
    let now = Utc::now();
    let mut payload = serde_json::json!({
        "iss": issuer,
        "aud": aud,
        "sub": "test-user",
        "iat": now.timestamp(),
        "exp": now.timestamp() + exp_offset_secs,
    });
    if let Some(scope) = scope {
        payload["scope"] = serde_json::Value::String(scope.to_string());
    }
    sign_hs256(hmac_key, r#"{"alg":"HS256"}"#, &payload)
}

/// Signs an arbitrary header + payload — for tests that need a token the
/// app should *reject* on its claims/header, not just its signature.
fn sign_hs256(hmac_key: &CoreHmacKey, header_json: &str, payload: &serde_json::Value) -> String {
    use base64::Engine;
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(header_json);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(payload).unwrap());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature = hmac_key
        .sign(
            &CoreJwsSigningAlgorithm::HmacSha256,
            signing_input.as_bytes(),
        )
        .expect("mock HMAC signing should not fail");
    format!(
        "{signing_input}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signature)
    )
}

// ---- App under test ---------------------------------------------------

fn test_provider(idp_base_url: &str) -> config::Idp {
    config::Idp {
        discovery_url: url::Url::parse(&format!("{idp_base_url}/.well-known/openid-configuration"))
            .unwrap(),
        client_id: CLIENT_ID.to_string(),
        client_secret: CLIENT_SECRET.to_string(),
    }
}

/// The `[idp]` name every domain built by `add_domain` references.
const DEFAULT_IDP: &str = "default";

fn base_domain_block(name: &str, auth_subdomain: &str) -> config::BaseDomain {
    config::BaseDomain {
        name: name.to_string(),
        auth_subdomain: auth_subdomain.to_string(),
        callback_url: url::Url::parse(&format!("https://{auth_subdomain}/callback")).unwrap(),
        idp: DEFAULT_IDP.to_string(),
        fallback: None,
    }
}

/// Registers `idp_base_url` as `[idp."default"]` (idempotent, so several
/// domains can share it) and a domain that authenticates against it.
fn add_domain(cfg: &mut config::Config, name: &str, auth_subdomain: &str, idp_base_url: &str) {
    cfg.idps
        .insert(DEFAULT_IDP.to_string(), test_provider(idp_base_url));
    cfg.base_domains
        .insert(name.to_string(), base_domain_block(name, auth_subdomain));
}

fn resolved_host(host: &str, base_domain: &str) -> config::ResolvedHost {
    config::ResolvedHost {
        host: Some(host.to_string()),
        base_domain: base_domain.to_string(),
        provider_key: DEFAULT_IDP.to_string(),
        required_group: None,
        group_claim_name: "groups".to_string(),
        bypass_paths: Vec::new(),
        path_required_groups: Vec::new(),
        forward_identity_headers: false,
        resource: None,
        required_scope: None,
        token_header: "x-auth-token".to_string(),
    }
}

async fn spawn_app_with_config(cfg: config::Config) -> (String, authward::state::AppState) {
    let state = authward::build_state(cfg)
        .await
        .expect("build_state against mock IdP");
    let app = authward::server::build_router(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (format!("http://{addr}"), state)
}

fn base_config(db_path: &std::path::Path) -> config::Config {
    config::Config {
        global: config::Global {
            cookie_signing_key: "test-only-cookie-signing-key-32-bytes-min".to_string(),
            refresh_token_encryption_key: "test-only-refresh-key-32-bytes-minimum!!".to_string(),
            sqlite_path: db_path.to_path_buf(),
            session_ttl_fallback: Duration::from_secs(3600),
            session_max_age: Duration::from_secs(24 * 3600),
            verify_cache_max_age: Duration::ZERO,
            otel_endpoint: None,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
        },
        idps: HashMap::new(),
        base_domains: HashMap::new(),
        hosts: HashMap::new(),
    }
}

async fn spawn_app(
    idp_base_url: &str,
    db_path: &std::path::Path,
) -> (String, authward::state::AppState) {
    let mut cfg = base_config(db_path);
    add_domain(&mut cfg, "test.local", "auth.test.local", idp_base_url);
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local"),
    );
    spawn_app_with_config(cfg).await
}

// ---- Manual "browser": relays cookies by hand (see module docs) -------

struct Browser {
    client: reqwest::Client,
    cookies: HashMap<String, String>,
}

impl Browser {
    fn new() -> Self {
        Self {
            client: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            cookies: HashMap::new(),
        }
    }

    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn absorb_set_cookies(&mut self, resp: &reqwest::Response) {
        for value in resp.headers().get_all("set-cookie") {
            let value = value.to_str().unwrap();
            let pair = value.split(';').next().unwrap();
            if let Some((name, val)) = pair.split_once('=') {
                self.cookies
                    .insert(name.trim().to_string(), val.trim().to_string());
            }
        }
    }

    /// GETs `app_base_url + path`, spoofing the `Host` header (the app
    /// under test is only ever reached via its real 127.0.0.1 address;
    /// `host` is what it should believe the request was addressed to,
    /// exactly as Caddy's `X-Forwarded-Host` would convey in production).
    async fn get(&mut self, app_base_url: &str, host: &str, path: &str) -> reqwest::Response {
        let resp = self
            .client
            .get(format!("{app_base_url}{path}"))
            .header("host", host)
            .header("x-forwarded-proto", "http")
            .header("cookie", self.cookie_header())
            .send()
            .await
            .unwrap();
        self.absorb_set_cookies(&resp);
        resp
    }

    /// Like `get`, but for `/verify` with an explicit `X-Forwarded-Uri` —
    /// for tests that need to hit a specific app-side path (bypass_paths,
    /// path_required_groups) rather than authward's own `/verify` route.
    async fn get_verify_for_uri(
        &mut self,
        app_base_url: &str,
        host: &str,
        uri: &str,
    ) -> reqwest::Response {
        let resp = self
            .client
            .get(format!("{app_base_url}/verify"))
            .header("host", host)
            .header("x-forwarded-proto", "http")
            .header("x-forwarded-uri", uri)
            .header("cookie", self.cookie_header())
            .send()
            .await
            .unwrap();
        self.absorb_set_cookies(&resp);
        resp
    }

    async fn post_form(
        &mut self,
        app_base_url: &str,
        host: &str,
        path: &str,
        form: &[(&str, &str)],
    ) -> reqwest::Response {
        self.post_form_with_headers(app_base_url, host, path, form, &[])
            .await
    }

    async fn post_form_with_headers(
        &mut self,
        app_base_url: &str,
        host: &str,
        path: &str,
        form: &[(&str, &str)],
        extra_headers: &[(&str, &str)],
    ) -> reqwest::Response {
        let mut req = self
            .client
            .post(format!("{app_base_url}{path}"))
            .header("host", host)
            .header("x-forwarded-proto", "http")
            .header("cookie", self.cookie_header());
        for (name, value) in extra_headers {
            req = req.header(*name, *value);
        }
        let resp = req.form(form).send().await.unwrap();
        self.absorb_set_cookies(&resp);
        resp
    }
}

fn location(resp: &reqwest::Response) -> String {
    resp.headers()
        .get("location")
        .expect("expected a redirect")
        .to_str()
        .unwrap()
        .to_string()
}

/// Follows a redirect to an IdP endpoint that's actually reachable
/// (unlike `auth.test.local`, the mock IdP's own `127.0.0.1` address is
/// real), returning the response so its own `Location` can be parsed.
async fn follow_real_redirect(client: &reqwest::Client, url: &str) -> reqwest::Response {
    client.get(url).send().await.unwrap()
}

fn query_param(url: &str, key: &str) -> String {
    url::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.to_string())
        .expect("missing query param")
}

/// Drives a full login round trip and returns the final redirect target
/// `/callback` sent back — callers that pass a same-base-domain `rd`
/// generally just assert this equals it; `login_ignores_an_rd_pointing_at_a_foreign_host`
/// instead checks the open-redirect guard substituted a safe default.
async fn login_as(
    app: &str,
    idp_client: &reqwest::Client,
    browser: &mut Browser,
    login_hint: &str,
    rd: &str,
) -> String {
    login_as_with_groups(app, idp_client, browser, login_hint, "", rd).await
}

/// Like `login_as`, but also sets the mock IdP's `groups` claim for this
/// login (comma-separated; empty means no groups) — for Phase 4's
/// group-membership authorization tests.
async fn login_as_with_groups(
    app: &str,
    idp_client: &reqwest::Client,
    browser: &mut Browser,
    login_hint: &str,
    groups: &str,
    rd: &str,
) -> String {
    login_as_with(app, idp_client, browser, login_hint, groups, rd, &[]).await
}

/// Full form: `extra_authorize_params` are appended to the mock IdP's
/// `/authorize` URL (e.g. `("email_verified", "false")`).
async fn login_as_with(
    app: &str,
    idp_client: &reqwest::Client,
    browser: &mut Browser,
    login_hint: &str,
    groups: &str,
    rd: &str,
    extra_authorize_params: &[(&str, &str)],
) -> String {
    let resp = browser
        .get(
            app,
            "auth.test.local",
            &format!("/login?rd={}", urlencode(rd)),
        )
        .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SEE_OTHER,
        "expected /login to redirect to the IdP"
    );
    let authorize_url = location(&resp);

    // The mock IdP's /authorize would normally show a login form; we pass
    // the desired identity via login_hint instead of a real UI.
    let mut authorize_url = url::Url::parse(&authorize_url).unwrap();
    authorize_url
        .query_pairs_mut()
        .append_pair("login_hint", login_hint);
    if !groups.is_empty() {
        authorize_url
            .query_pairs_mut()
            .append_pair("groups", groups);
    }
    for (key, value) in extra_authorize_params {
        authorize_url.query_pairs_mut().append_pair(key, value);
    }

    let idp_resp = follow_real_redirect(idp_client, authorize_url.as_str()).await;
    assert_eq!(idp_resp.status(), reqwest::StatusCode::SEE_OTHER);
    let callback_location = location(&idp_resp);

    let code = query_param(&callback_location, "code");
    let state = query_param(&callback_location, "state");

    let resp = browser
        .get(
            app,
            "auth.test.local",
            &format!("/callback?code={code}&state={state}"),
        )
        .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SEE_OTHER,
        "expected /callback to redirect somewhere"
    );
    assert!(
        browser.cookies.contains_key("authward_session"),
        "expected a session cookie after login"
    );
    location(&resp)
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[tokio::test]
async fn login_then_verify_succeeds() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    assert_eq!(
        login_as(
            &app,
            &idp_client,
            &mut browser,
            "alice",
            "https://app.test.local/dashboard"
        )
        .await,
        "https://app.test.local/dashboard"
    );

    let resp = browser.get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn verify_without_session_is_unauthorized() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;

    let mut browser = Browser::new();
    let resp = browser.get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// The plan's explicit Phase 1 test: two concurrent login flows against
/// the same provider must never cross-contaminate identity. PKCE/nonce/
/// state live only in each browser's own flow cookie, never in shared
/// server state, so interleaving the two flows should not let one
/// browser's session end up authenticated as the other's identity.
#[tokio::test]
async fn concurrent_logins_do_not_cross_contaminate() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut alice = Browser::new();
    let mut bob = Browser::new();

    // Start both flows, interleaved, before either completes.
    let alice_login_resp = alice
        .get(
            &app,
            "auth.test.local",
            "/login?rd=https%3A%2F%2Fapp.test.local%2Fa",
        )
        .await;
    let bob_login_resp = bob
        .get(
            &app,
            "auth.test.local",
            "/login?rd=https%3A%2F%2Fapp.test.local%2Fb",
        )
        .await;

    let mut alice_authorize = url::Url::parse(&location(&alice_login_resp)).unwrap();
    alice_authorize
        .query_pairs_mut()
        .append_pair("login_hint", "alice");
    let mut bob_authorize = url::Url::parse(&location(&bob_login_resp)).unwrap();
    bob_authorize
        .query_pairs_mut()
        .append_pair("login_hint", "bob");

    // Bob's authorize/token round trip happens first, then Alice's —
    // opposite order from how their /login calls started.
    let bob_idp_resp = follow_real_redirect(&idp_client, bob_authorize.as_str()).await;
    let bob_callback = location(&bob_idp_resp);
    let bob_resp = bob
        .get(
            &app,
            "auth.test.local",
            &format!(
                "/callback?code={}&state={}",
                query_param(&bob_callback, "code"),
                query_param(&bob_callback, "state")
            ),
        )
        .await;
    assert_eq!(location(&bob_resp), "https://app.test.local/b");

    let alice_idp_resp = follow_real_redirect(&idp_client, alice_authorize.as_str()).await;
    let alice_callback = location(&alice_idp_resp);
    let alice_resp = alice
        .get(
            &app,
            "auth.test.local",
            &format!(
                "/callback?code={}&state={}",
                query_param(&alice_callback, "code"),
                query_param(&alice_callback, "state")
            ),
        )
        .await;
    assert_eq!(location(&alice_resp), "https://app.test.local/a");

    // Both end up with distinct, valid sessions of their own.
    assert!(alice.cookies.contains_key("authward_session"));
    assert!(bob.cookies.contains_key("authward_session"));
    assert_ne!(
        alice.cookies["authward_session"],
        bob.cookies["authward_session"]
    );

    assert_eq!(
        alice.get(&app, "app.test.local", "/verify").await.status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        bob.get(&app, "app.test.local", "/verify").await.status(),
        reqwest::StatusCode::OK
    );
}

/// Phase 11 hardening checklist item: "load test N concurrent hosts/
/// sessions against SQLite, confirm no lock contention." Each login is a
/// session-creating write (`db::create_session`) against the single
/// shared SQLite pool; firing many at once is exactly the scenario a
/// naive SQLite setup (default rollback journal, no busy timeout) would
/// serialize into `SQLITE_BUSY` errors under write contention. This
/// asserts every login still succeeds, and that the whole batch completes
/// well within a generous deadline rather than stalling on lock waits.
#[tokio::test]
async fn concurrent_session_creation_does_not_error_under_sqlite_contention() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;

    const CONCURRENT_LOGINS: usize = 50;
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..CONCURRENT_LOGINS {
        let app = app.clone();
        tasks.spawn(async move {
            let idp_client = reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap();
            let mut browser = Browser::new();
            let login_hint = format!("user-{i}");
            login_as(
                &app,
                &idp_client,
                &mut browser,
                &login_hint,
                "https://app.test.local/dashboard",
            )
            .await;
            let resp = browser.get(&app, "app.test.local", "/verify").await;
            assert_eq!(
                resp.status(),
                reqwest::StatusCode::OK,
                "login {i} failed to verify after concurrent session creation"
            );
        });
    }

    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while let Some(result) = tasks.join_next().await {
            result.expect("concurrent login task panicked");
        }
    })
    .await
    .expect(
        "concurrent logins did not all complete within the deadline \
         — possible SQLite lock contention",
    );
}

// ---- Phase 2: silent refresh -------------------------------------------

async fn raw_verify(app: &str, cookie_header: &str) -> reqwest::StatusCode {
    reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("cookie", cookie_header)
        .send()
        .await
        .unwrap()
        .status()
}

#[tokio::test]
async fn silent_refresh_extends_an_expired_session() {
    let ttl = Duration::from_secs(2);
    let (idp_base_url, refresh_grant_count, _refresh_tokens) = spawn_mock_idp(ttl).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    assert_eq!(
        login_as(
            &app,
            &idp_client,
            &mut browser,
            "alice",
            "https://app.test.local/dashboard"
        )
        .await,
        "https://app.test.local/dashboard"
    );
    let session_cookie_before = browser.cookies["authward_session"].clone();

    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        refresh_grant_count.load(Ordering::SeqCst),
        0,
        "should not have refreshed yet"
    );

    tokio::time::sleep(ttl + Duration::from_millis(500)).await;

    // The access token has now expired; /verify should silently refresh
    // using the stored refresh token rather than rejecting the request.
    let resp = browser.get(&app, "app.test.local", "/verify").await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "expired session should have been silently refreshed"
    );
    assert_eq!(refresh_grant_count.load(Ordering::SeqCst), 1);

    // Same session identity throughout — refresh updates the existing
    // row/cookie rather than minting a new session.
    assert_eq!(browser.cookies["authward_session"], session_cookie_before);
}

#[tokio::test]
async fn refresh_failure_clears_the_session() {
    let ttl = Duration::from_secs(1);
    let (idp_base_url, _refresh_grant_count, refresh_tokens) = spawn_mock_idp(ttl).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    assert_eq!(
        login_as(
            &app,
            &idp_client,
            &mut browser,
            "alice",
            "https://app.test.local/dashboard"
        )
        .await,
        "https://app.test.local/dashboard"
    );

    tokio::time::sleep(ttl + Duration::from_millis(500)).await;
    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );

    // Simulate the IdP revoking the (now-rotated) refresh token: wipe the
    // mock's record of every refresh token it has issued, so the next
    // refresh attempt gets a genuine invalid_grant rejection, exactly as
    // a real IdP would return for a revoked/expired refresh token.
    refresh_tokens.lock().unwrap().clear();
    tokio::time::sleep(ttl + Duration::from_millis(500)).await;

    let resp = browser.get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn concurrent_verify_requests_collapse_into_one_refresh() {
    let ttl = Duration::from_secs(2);
    let (idp_base_url, refresh_grant_count, _refresh_tokens) = spawn_mock_idp(ttl).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    assert_eq!(
        login_as(
            &app,
            &idp_client,
            &mut browser,
            "alice",
            "https://app.test.local/dashboard"
        )
        .await,
        "https://app.test.local/dashboard"
    );
    let cookie_header = format!("authward_session={}", browser.cookies["authward_session"]);

    tokio::time::sleep(ttl + Duration::from_millis(500)).await;

    // Fire many concurrent requests against the one expiring session. The
    // per-session lock (Phase 2) should collapse them into exactly one
    // refresh call to the IdP, even though every one of them observes the
    // session as expired before any refresh has completed.
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let app = app.clone();
            let cookie_header = cookie_header.clone();
            tokio::spawn(async move { raw_verify(&app, &cookie_header).await })
        })
        .collect();

    for handle in handles {
        assert_eq!(handle.await.unwrap(), reqwest::StatusCode::OK);
    }

    assert_eq!(
        refresh_grant_count.load(Ordering::SeqCst),
        1,
        "concurrent requests against one expiring session should trigger exactly one IdP refresh call"
    );
}

// ---- Phase 2: expired-session reaper ------------------------------------

#[tokio::test]
async fn reaper_deletes_sessions_with_no_refresh_token_survivors() {
    // Build a session directly (no refresh token), bypassing login, then
    // confirm the reaper removes it once expired.
    let ttl = Duration::from_millis(50);
    let (idp_base_url, _count, _refresh_tokens) = spawn_mock_idp(ttl).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (_app, state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;

    authward::db::create_session(
        &state.db,
        "reaper-test-session",
        "test.local",
        "test.local",
        "alice",
        None,
        None,
        Utc::now() - ChronoDuration::seconds(1),
        None,
        &serde_json::Value::Null,
    )
    .await
    .unwrap();

    authward::session::reap_expired_sessions(&state).await;

    assert!(
        authward::db::get_session(&state.db, "reaper-test-session")
            .await
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn reaper_leaves_an_idle_session_that_can_still_refresh() {
    // A session whose access token has expired but which holds a refresh
    // token is idle, not dead: the next request silently refreshes it.
    // The reaper must not turn "idle for one access-token lifetime" into
    // a forced re-login.
    let ttl = Duration::from_secs(1);
    let (idp_base_url, refresh_grant_count, _refresh_tokens) = spawn_mock_idp(ttl).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;
    let cookie_header = format!("authward_session={}", browser.cookies["authward_session"]);

    tokio::time::sleep(ttl + Duration::from_millis(500)).await;
    authward::session::reap_expired_sessions(&state).await;

    assert_eq!(
        raw_verify(&app, &cookie_header).await,
        reqwest::StatusCode::OK,
        "an expired-but-refreshable session must survive the reaper"
    );
    assert_eq!(
        refresh_grant_count.load(Ordering::SeqCst),
        1,
        "and be silently refreshed on its next use"
    );
}

#[tokio::test]
async fn reaper_deletes_a_session_past_max_age_even_with_a_refresh_token() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.global.session_max_age = Duration::from_secs(1);
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local"),
    );
    let (app, state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;
    // The cookie carries the session ID encrypted, so find the row by
    // subject instead.
    let rows =
        authward::db::list_sessions_for_subject(&state.db, "test.local", DEFAULT_IDP, "alice")
            .await
            .unwrap();
    assert_eq!(rows.len(), 1);
    assert!(
        rows[0].refresh_token.is_some(),
        "mock IdP issues refresh tokens"
    );

    tokio::time::sleep(Duration::from_millis(1500)).await;
    authward::session::reap_expired_sessions(&state).await;

    assert!(
        authward::db::get_session(&state.db, &rows[0].id)
            .await
            .unwrap()
            .is_none(),
        "past session_max_age the row is dead regardless of its refresh token"
    );
}

#[tokio::test]
async fn reaper_does_not_delete_a_session_mid_refresh() {
    let ttl = Duration::from_secs(1);
    let refresh_delay = Duration::from_millis(3000);
    let (idp_base_url, refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp_with_refresh_delay(ttl, refresh_delay).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    assert_eq!(
        login_as(
            &app,
            &idp_client,
            &mut browser,
            "alice",
            "https://app.test.local/dashboard"
        )
        .await,
        "https://app.test.local/dashboard"
    );
    let cookie_header = format!("authward_session={}", browser.cookies["authward_session"]);

    tokio::time::sleep(ttl + Duration::from_millis(500)).await;

    // Kick off a /verify that will sit in the mock IdP's artificial delay
    // while mid-refresh, holding the session's lock the whole time.
    let app_clone = app.clone();
    let cookie_header_clone = cookie_header.clone();
    let verify_task =
        tokio::spawn(async move { raw_verify(&app_clone, &cookie_header_clone).await });

    // Give the refresh time to start (acquire the lock, reach the IdP)
    // but not to finish. Margin is generous relative to refresh_delay
    // above to stay robust when many tests run concurrently under CPU
    // contention (this specific timing relationship, not the 3s total,
    // is what the test needs).
    tokio::time::sleep(Duration::from_millis(1000)).await;

    // The reaper runs while that refresh is still in flight. It must not
    // delete the row out from under it: it can only proceed past the
    // per-session lock once the refresh releases it, at which point the
    // row's expiry has already been pushed into the future.
    authward::session::reap_expired_sessions(&state).await;

    assert_eq!(
        verify_task.await.unwrap(),
        reqwest::StatusCode::OK,
        "in-flight refresh should still succeed"
    );
    assert_eq!(refresh_grant_count.load(Ordering::SeqCst), 1);

    // If the reaper had deleted the session out from under the in-flight
    // refresh, this would either 401 (session gone) or trigger a second,
    // unnecessary refresh (session recreated from scratch isn't possible
    // here — there'd be nothing to refresh with). Neither happens: the
    // row survived with its refreshed, still-future expiry intact.
    assert_eq!(
        raw_verify(&app, &cookie_header).await,
        reqwest::StatusCode::OK
    );
    assert_eq!(
        refresh_grant_count.load(Ordering::SeqCst),
        1,
        "session should still be fresh from the earlier refresh, needing no second one"
    );
}

// ---- Phase 3: multi-host / multi-base-domain resolution -----------------

#[tokio::test]
async fn multiple_hosts_on_one_base_domain_share_sso() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();

    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "app-one.test.local".to_string(),
        resolved_host("app-one.test.local", "test.local"),
    );
    cfg.hosts.insert(
        "app-two.test.local".to_string(),
        resolved_host("app-two.test.local", "test.local"),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;

    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut browser = Browser::new();
    assert_eq!(
        login_as(
            &app,
            &idp_client,
            &mut browser,
            "alice",
            "https://app-one.test.local/"
        )
        .await,
        "https://app-one.test.local/"
    );

    assert_eq!(
        browser
            .get(&app, "app-one.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        browser
            .get(&app, "app-two.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK,
        "a second host on the same base domain should share the session (SSO)"
    );
}

#[tokio::test]
async fn a_different_base_domain_does_not_accept_the_session() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();

    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    add_domain(&mut cfg, "other.local", "auth.other.local", &idp_base_url);
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local"),
    );
    cfg.hosts.insert(
        "app.other.local".to_string(),
        resolved_host("app.other.local", "other.local"),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;

    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut browser = Browser::new();
    assert_eq!(
        login_as(
            &app,
            &idp_client,
            &mut browser,
            "alice",
            "https://app.test.local/"
        )
        .await,
        "https://app.test.local/"
    );

    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        browser
            .get(&app, "app.other.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a session for one base domain must not verify against a completely different base domain, even with the same (forged) cookie"
    );
}

/// A host-level `provider` override really does put that host on a
/// different IdP: logins bound for it go there, a session from the base
/// domain's default IdP isn't accepted for it (and vice versa), and
/// logout ends the session at the IdP that created it.
#[tokio::test]
async fn per_host_provider_override_is_honored() {
    let (idp_a, _count_a, _tokens_a) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let (idp_b, _count_b, _tokens_b) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_a);
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local"),
    );
    cfg.hosts.insert(
        "partner.test.local".to_string(),
        config::ResolvedHost {
            provider_key: "partner".to_string(),
            ..resolved_host("partner.test.local", "test.local")
        },
    );
    cfg.idps
        .insert("partner".to_string(), test_provider(&idp_b));
    let (app, _state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Bound for the default host: the login goes to IdP A...
    let mut browser = Browser::new();
    let resp = browser
        .get(
            &app,
            "auth.test.local",
            &format!("/login?rd={}", urlencode("https://app.test.local/")),
        )
        .await;
    assert!(
        location(&resp).starts_with(&idp_a),
        "a login for the default host must go to the base domain's IdP"
    );
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;
    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );
    // ...and that session is not a login at the partner host.
    assert_eq!(
        browser
            .get(&app, "partner.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a session from IdP A must not be accepted by a host configured for IdP B"
    );

    // Bound for the partner host: the login goes to IdP B, and the
    // resulting session works there but not at the default host.
    let mut browser = Browser::new();
    let resp = browser
        .get(
            &app,
            "auth.test.local",
            &format!("/login?rd={}", urlencode("https://partner.test.local/")),
        )
        .await;
    assert!(
        location(&resp).starts_with(&idp_b),
        "a login for an overridden host must go to that host's IdP, got {}",
        location(&resp)
    );
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "bob",
        "https://partner.test.local/",
    )
    .await;
    assert_eq!(
        browser
            .get(&app, "partner.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a session from IdP B must not be accepted by a host on the default IdP"
    );

    // The dashboard still works for this session, and logout ends it at
    // the IdP that created it.
    assert_eq!(
        browser.get(&app, "auth.test.local", "/").await.status(),
        reqwest::StatusCode::OK
    );
    let resp = browser
        .post_form(&app, "auth.test.local", "/logout", &[])
        .await;
    assert!(
        location(&resp).starts_with(&format!("{idp_b}/end-session")),
        "logout must go to the session's own IdP, got {}",
        location(&resp)
    );
}

/// A loopback address with nothing listening on it: bound to pick a free
/// port, then released. Connections to it are refused until a test
/// re-binds it.
async fn reserve_dead_address() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

#[tokio::test]
async fn startup_fails_when_no_provider_can_be_discovered() {
    let dead = reserve_dead_address().await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(
        &mut cfg,
        "test.local",
        "auth.test.local",
        &format!("http://{dead}"),
    );
    let err = authward::build_state(cfg)
        .await
        .err()
        .expect("startup must fail when the only provider is unreachable");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("no OIDC provider could be discovered") && msg.contains(DEFAULT_IDP),
        "error should say what failed: {msg}"
    );
}

#[tokio::test]
async fn a_down_provider_does_not_block_startup_and_is_picked_up_later() {
    let (idp_a, _count_a, _tokens_a) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let dead = reserve_dead_address().await;
    let idp_b = format!("http://{dead}");
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_a);
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local"),
    );
    cfg.hosts.insert(
        "partner.test.local".to_string(),
        config::ResolvedHost {
            provider_key: "partner".to_string(),
            ..resolved_host("partner.test.local", "test.local")
        },
    );
    cfg.idps
        .insert("partner".to_string(), test_provider(&idp_b));
    // IdP B is down: startup must still succeed for IdP A's hosts.
    let (app, state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    assert_eq!(
        login_as(
            &app,
            &idp_client,
            &mut browser,
            "alice",
            "https://app.test.local/"
        )
        .await,
        "https://app.test.local/",
        "hosts on the reachable provider work normally"
    );

    let partner_login = format!("/login?rd={}", urlencode("https://partner.test.local/"));
    let resp = browser.get(&app, "auth.test.local", &partner_login).await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_GATEWAY,
        "a login at the down provider is a clear error, not a hang or a crash"
    );
    assert!(resp.text().await.unwrap().contains("Provider unavailable"));

    // A bearer token for the partner host can't be validated either — its
    // JWKS was never fetched — and that's a plain 401, not a 500.
    assert_eq!(
        raw_verify_bearer(&app, "partner.test.local", "eyJhbGciOiJIUzI1NiJ9.e30.x").await,
        reqwest::StatusCode::UNAUTHORIZED
    );

    // IdP B comes up at the address authward was configured with; the
    // retry loop's body picks it up and partner logins start working.
    let listener = tokio::net::TcpListener::bind(dead).await.unwrap();
    let _idp_b = spawn_mock_idp_on(listener, Duration::from_secs(3600), Duration::ZERO, true).await;
    assert_eq!(authward::discover_missing_providers(&state).await, 0);

    let resp = browser.get(&app, "auth.test.local", &partner_login).await;
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    assert!(
        location(&resp).starts_with(&idp_b),
        "once discovered, the partner host's login goes to its own IdP"
    );
}

#[tokio::test]
async fn unconfigured_host_with_no_fallback_is_a_hard_failure() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;

    let mut browser = Browser::new();
    let resp = browser
        .get(&app, "nobody-configured-this-host.example", "/verify")
        .await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(
        resp.headers().get("x-login-url").is_none(),
        "an unconfigured host has no auth subdomain to redirect to, so this 401 must not \
         be mistaken for a normal login-required denial"
    );
}

#[tokio::test]
async fn fallback_provider_covers_hosts_with_no_explicit_config() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();

    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    // No entry in `hosts` at all — every host on this instance relies on
    // the fallback provider.
    cfg.base_domains.get_mut("test.local").unwrap().fallback = Some(config::ResolvedHost {
        host: None,
        ..resolved_host("*.test.local", "test.local")
    });
    let (app, _state) = spawn_app_with_config(cfg).await;

    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut browser = Browser::new();
    assert_eq!(
        login_as(
            &app,
            &idp_client,
            &mut browser,
            "alice",
            "https://some-unlisted-app.test.local/"
        )
        .await,
        "https://some-unlisted-app.test.local/"
    );

    assert_eq!(
        browser
            .get(&app, "some-unlisted-app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK,
        "a host with no explicit config should still work via the fallback provider"
    );
}

#[tokio::test]
async fn login_ignores_an_rd_pointing_at_a_foreign_host() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    // A malicious/buggy rd pointing off the base domain entirely.
    let landed_on = login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://evil.example/steal-session",
    )
    .await;

    assert_ne!(
        landed_on, "https://evil.example/steal-session",
        "must never honor an rd targeting a foreign host"
    );
    assert_eq!(
        landed_on, "https://auth.test.local/",
        "should fall back to the auth subdomain's own root"
    );
}

// ---- Phase 4: group-membership authorization -----------------------------

#[tokio::test]
async fn required_group_grants_or_denies_access() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();

    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut admin_host = resolved_host("admin.test.local", "test.local");
    admin_host.required_group = Some("admins".to_string());
    cfg.hosts.insert("admin.test.local".to_string(), admin_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut alice = Browser::new();
    login_as_with_groups(
        &app,
        &idp_client,
        &mut alice,
        "alice",
        "admins",
        "https://admin.test.local/",
    )
    .await;
    assert_eq!(
        alice
            .get(&app, "admin.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK,
        "member of the required group should be granted access"
    );

    let mut bob = Browser::new();
    login_as_with_groups(
        &app,
        &idp_client,
        &mut bob,
        "bob",
        "users",
        "https://admin.test.local/",
    )
    .await;
    assert_eq!(
        bob.get(&app, "admin.test.local", "/verify").await.status(),
        reqwest::StatusCode::FORBIDDEN,
        "authenticated but not a member of the required group should be denied, not just unauthenticated"
    );
}

#[tokio::test]
async fn no_required_group_means_any_valid_login_passes() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    // spawn_app's default host has no required_group configured at all.
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    // No groups at all — should still pass, since the host requires none.
    login_as_with_groups(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "",
        "https://app.test.local/",
    )
    .await;
    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );
}

#[tokio::test]
async fn path_required_group_override_replaces_host_level_check() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();

    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.required_group = Some("users".to_string());
    app_host.path_required_groups = vec![config::PathRequiredGroup {
        path: "/admin/*".to_string(),
        required_group: "admins".to_string(),
    }];
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Admin-only, NOT a member of "users" — must still pass under /admin/*
    // (the override replaces the host's check, it doesn't AND with it),
    // but must be denied everywhere else where the host's own "users"
    // check applies.
    let mut admin_only = Browser::new();
    login_as_with_groups(
        &app,
        &idp_client,
        &mut admin_only,
        "admin-only",
        "admins",
        "https://app.test.local/",
    )
    .await;
    assert_eq!(
        admin_only
            .get_verify_for_uri(&app, "app.test.local", "/admin/dashboard")
            .await
            .status(),
        reqwest::StatusCode::OK,
        "admins-only session should pass under /admin/* even without the host's `users` group"
    );
    assert_eq!(
        admin_only
            .get_verify_for_uri(&app, "app.test.local", "/other")
            .await
            .status(),
        reqwest::StatusCode::FORBIDDEN,
        "outside /admin/*, the host's own required_group (users) still applies"
    );

    // Regular user, NOT a member of "admins" — must be denied under
    // /admin/* even though they'd pass the host's default check.
    let mut user_only = Browser::new();
    login_as_with_groups(
        &app,
        &idp_client,
        &mut user_only,
        "user-only",
        "users",
        "https://app.test.local/",
    )
    .await;
    assert_eq!(
        user_only
            .get_verify_for_uri(&app, "app.test.local", "/admin/dashboard")
            .await
            .status(),
        reqwest::StatusCode::FORBIDDEN,
        "a `users` session must not pass /admin/* just because it satisfies the host's default"
    );
    assert_eq!(
        user_only
            .get_verify_for_uri(&app, "app.test.local", "/other")
            .await
            .status(),
        reqwest::StatusCode::OK,
        "outside /admin/*, the host's own required_group (users) is satisfied"
    );
}

#[tokio::test]
async fn bypass_path_wins_over_path_required_group_override() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.required_group = Some("admins".to_string());
    app_host.bypass_paths = vec![bypass::BypassEntry::unrestricted("/admin/public")];
    app_host.path_required_groups = vec![config::PathRequiredGroup {
        path: "/admin/*".to_string(),
        required_group: "admins".to_string(),
    }];
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    // No session cookie at all — if path_required_groups (or the host's
    // required_group) were checked, this would 401. bypass_paths must
    // win and skip auth entirely.
    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("x-forwarded-uri", "/admin/public")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "a path bypassed via bypass_paths must skip auth entirely, even though it also \
         matches a path_required_groups entry on the same host"
    );
}

#[tokio::test]
async fn path_required_group_first_match_in_list_order_wins() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();

    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.path_required_groups = vec![
        config::PathRequiredGroup {
            path: "/admin/*".to_string(),
            required_group: "admins".to_string(),
        },
        config::PathRequiredGroup {
            path: "/admin/reports/*".to_string(),
            required_group: "reporters".to_string(),
        },
    ];
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // Only a "reporters" member, not "admins" — the more specific SECOND
    // entry would grant access, but the FIRST matching entry in list
    // order ("/admin/*", requiring "admins") is the one that applies.
    let mut reporter = Browser::new();
    login_as_with_groups(
        &app,
        &idp_client,
        &mut reporter,
        "reporter",
        "reporters",
        "https://app.test.local/",
    )
    .await;
    assert_eq!(
        reporter
            .get_verify_for_uri(&app, "app.test.local", "/admin/reports/q1")
            .await
            .status(),
        reqwest::StatusCode::FORBIDDEN,
        "the first matching entry in list order (/admin/*, requiring admins) must win, \
         not the more specific later entry"
    );
}

#[tokio::test]
async fn revoking_group_membership_denies_access_on_next_refresh_without_relogin() {
    let ttl = Duration::from_secs(1);
    let (idp_base_url, _refresh_grant_count, refresh_tokens) = spawn_mock_idp(ttl).await;
    let db_dir = tempfile::tempdir().unwrap();

    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut admin_host = resolved_host("admin.test.local", "test.local");
    admin_host.required_group = Some("admins".to_string());
    cfg.hosts.insert("admin.test.local".to_string(), admin_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut browser = Browser::new();
    login_as_with_groups(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "admins",
        "https://admin.test.local/",
    )
    .await;
    assert_eq!(
        browser
            .get(&app, "admin.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );

    // Simulate the IdP admin removing alice from "admins" — the mock
    // reports this on the *next* token issuance (refresh), exactly like a
    // real IdP would, without alice's session being touched directly.
    for identity in refresh_tokens.lock().unwrap().values_mut() {
        identity.groups.clear();
    }

    tokio::time::sleep(ttl + Duration::from_millis(500)).await;

    assert_eq!(
        browser
            .get(&app, "admin.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::FORBIDDEN,
        "losing required group membership should deny access on the next silent refresh, without waiting for full re-login"
    );
}

// ---- Phase 5: resource-scoped bearer tokens ------------------------------

async fn raw_verify_bearer(app: &str, host: &str, token: &str) -> reqwest::StatusCode {
    reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", host)
        .header("x-auth-token", token)
        .send()
        .await
        .unwrap()
        .status()
}

fn api_host(resource: &str, required_scope: Option<&str>) -> config::ResolvedHost {
    config::ResolvedHost {
        resource: Some(resource.to_string()),
        required_scope: required_scope.map(str::to_string),
        token_header: "x-auth-token".to_string(),
        ..resolved_host("api.test.local", "test.local")
    }
}

#[tokio::test]
async fn bearer_token_grants_access_for_matching_resource_and_scope() {
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, true).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", Some("read")),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;

    let token = build_access_token(
        &hmac_key.lock().unwrap(),
        &idp_base_url,
        "https://api.test.local/",
        Some("read write"),
        3600,
    );
    assert_eq!(
        raw_verify_bearer(&app, "api.test.local", &token).await,
        reqwest::StatusCode::OK
    );
}

#[tokio::test]
async fn bearer_token_is_tried_when_the_session_cookie_is_stale_and_scheme_is_case_insensitive() {
    // A script running on a machine whose browser once logged in sends a
    // session cookie that may no longer be valid alongside its bearer
    // token. The stale cookie must not shadow the token.
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, true).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", Some("read")),
    );
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local"),
    );
    let (app, state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // A real, correctly encrypted session cookie whose row is then
    // deleted out from under it — the shape of a logged-out-elsewhere or
    // reaped session still sitting in a cookie jar.
    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;
    let rows =
        authward::db::list_sessions_for_subject(&state.db, "test.local", DEFAULT_IDP, "alice")
            .await
            .unwrap();
    authward::db::delete_session(&state.db, &rows[0].id)
        .await
        .unwrap();
    let stale_cookie = format!("authward_session={}", browser.cookies["authward_session"]);

    let token = build_access_token(
        &hmac_key.lock().unwrap(),
        &idp_base_url,
        "https://api.test.local/",
        Some("read"),
        3600,
    );
    let verify = |prefix: &'static str, with_cookie: bool| {
        let app = app.clone();
        let token = token.clone();
        let stale_cookie = stale_cookie.clone();
        async move {
            let mut req = reqwest::Client::new()
                .get(format!("{app}/verify"))
                .header("host", "api.test.local")
                .header("x-auth-token", format!("{prefix}{token}"));
            if with_cookie {
                req = req.header("cookie", stale_cookie);
            }
            req.send().await.unwrap().status()
        }
    };

    assert_eq!(
        verify("", true).await,
        reqwest::StatusCode::OK,
        "a stale session cookie must not shadow a valid API token"
    );
    assert_eq!(
        verify("Bearer ", false).await,
        reqwest::StatusCode::OK,
        "a pasted `Bearer ` prefix is tolerated in a non-Authorization header"
    );
    assert_eq!(
        verify("Basic ", false).await,
        reqwest::StatusCode::UNAUTHORIZED,
        "anything else in front of the token is not the token"
    );
}

#[tokio::test]
async fn token_header_is_configurable_and_authorization_requires_the_bearer_scheme() {
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, true).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "api.test.local".to_string(),
        config::ResolvedHost {
            token_header: "authorization".to_string(),
            ..api_host("https://api.test.local/", Some("read"))
        },
    );
    cfg.hosts.insert(
        "custom.test.local".to_string(),
        config::ResolvedHost {
            host: Some("custom.test.local".to_string()),
            token_header: "x-api-token".to_string(),
            ..api_host("https://api.test.local/", Some("read"))
        },
    );
    let (app, _state) = spawn_app_with_config(cfg).await;

    let token = build_access_token(
        &hmac_key.lock().unwrap(),
        &idp_base_url,
        "https://api.test.local/",
        Some("read"),
        3600,
    );
    let verify = |host: &'static str, header: &'static str, value: String| {
        let app = app.clone();
        async move {
            reqwest::Client::new()
                .get(format!("{app}/verify"))
                .header("host", host)
                .header(header, value)
                .send()
                .await
                .unwrap()
                .status()
        }
    };

    assert_eq!(
        verify("api.test.local", "authorization", format!("Bearer {token}")).await,
        reqwest::StatusCode::OK,
        "token_header = \"Authorization\" reads a Bearer credential"
    );
    assert_eq!(
        verify("api.test.local", "authorization", format!("bearer {token}")).await,
        reqwest::StatusCode::OK,
        "the auth scheme is case-insensitive (RFC 9110 §11.1)"
    );
    assert_eq!(
        verify("api.test.local", "authorization", token.clone()).await,
        reqwest::StatusCode::UNAUTHORIZED,
        "a bare token in Authorization has no scheme and is not a bearer credential"
    );
    assert_eq!(
        verify("api.test.local", "x-auth-token", token.clone()).await,
        reqwest::StatusCode::UNAUTHORIZED,
        "only the configured header is read"
    );
    assert_eq!(
        verify("custom.test.local", "x-api-token", token.clone()).await,
        reqwest::StatusCode::OK,
        "a custom header name carries the raw token"
    );
    assert_eq!(
        verify(
            "custom.test.local",
            "authorization",
            format!("Bearer {token}")
        )
        .await,
        reqwest::StatusCode::UNAUTHORIZED,
        "Authorization is ignored when another header is configured — it's the app's to use"
    );
}

#[tokio::test]
async fn bearer_token_for_a_different_resource_is_rejected() {
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, true).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", None),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;

    // Token minted for a *different* host's resource.
    let token = build_access_token(
        &hmac_key.lock().unwrap(),
        &idp_base_url,
        "https://other-api.test.local/",
        None,
        3600,
    );
    assert_eq!(
        raw_verify_bearer(&app, "api.test.local", &token).await,
        reqwest::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn bearer_token_missing_required_scope_is_rejected() {
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, true).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", Some("admin")),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;

    let token = build_access_token(
        &hmac_key.lock().unwrap(),
        &idp_base_url,
        "https://api.test.local/",
        Some("read"),
        3600,
    );
    assert_eq!(
        raw_verify_bearer(&app, "api.test.local", &token).await,
        reqwest::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn expired_bearer_token_is_rejected() {
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, true).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", None),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;

    let token = build_access_token(
        &hmac_key.lock().unwrap(),
        &idp_base_url,
        "https://api.test.local/",
        None,
        -3600,
    );
    assert_eq!(
        raw_verify_bearer(&app, "api.test.local", &token).await,
        reqwest::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn bearer_tokens_without_sub_or_not_yet_valid_or_wrong_typ_are_rejected() {
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, true).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", None),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;

    let now = Utc::now().timestamp();
    let good = serde_json::json!({
        "iss": idp_base_url,
        "aud": "https://api.test.local/",
        "sub": "test-user",
        "iat": now,
        "exp": now + 3600,
    });
    let key = hmac_key.lock().unwrap().clone();

    // Control: the same claims with an honest header are accepted.
    let token = sign_hs256(&key, r#"{"alg":"HS256","typ":"at+jwt"}"#, &good);
    assert_eq!(
        raw_verify_bearer(&app, "api.test.local", &token).await,
        reqwest::StatusCode::OK
    );

    let mut no_sub = good.clone();
    no_sub.as_object_mut().unwrap().remove("sub");
    let token = sign_hs256(&key, r#"{"alg":"HS256"}"#, &no_sub);
    assert_eq!(
        raw_verify_bearer(&app, "api.test.local", &token).await,
        reqwest::StatusCode::UNAUTHORIZED,
        "a token with no sub would be forwarded as an empty identity"
    );

    let mut future = good.clone();
    future["nbf"] = serde_json::json!(now + 3600);
    let token = sign_hs256(&key, r#"{"alg":"HS256"}"#, &future);
    assert_eq!(
        raw_verify_bearer(&app, "api.test.local", &token).await,
        reqwest::StatusCode::UNAUTHORIZED,
        "nbf in the future"
    );

    let token = sign_hs256(&key, r#"{"alg":"HS256","typ":"logout+jwt"}"#, &good);
    assert_eq!(
        raw_verify_bearer(&app, "api.test.local", &token).await,
        reqwest::StatusCode::UNAUTHORIZED,
        "some other JWT type from the same issuer is not an access token"
    );
}

#[tokio::test]
async fn bearer_token_survives_idp_key_rotation() {
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, true).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", None),
    );
    // build_state discovers and caches the JWKS for the *original* key here.
    let (app, _state) = spawn_app_with_config(cfg).await;

    // The IdP rotates its signing key — the app's cached JWKS (from
    // startup discovery) still reflects the old one.
    *hmac_key.lock().unwrap() = CoreHmacKey::new(b"a-brand-new-rotated-secret".to_vec());

    let token = build_access_token(
        &hmac_key.lock().unwrap(),
        &idp_base_url,
        "https://api.test.local/",
        None,
        3600,
    );
    assert_eq!(
        raw_verify_bearer(&app, "api.test.local", &token).await,
        reqwest::StatusCode::OK,
        "a signature failure against the stale cached JWKS should trigger an on-demand refresh and succeed on retry"
    );
}

// ---- Phase 5: /token helper end-to-end -----------------------------------

#[tokio::test]
async fn token_helper_scopes_the_request_to_the_selected_hosts_resource() {
    let (idp_base_url, _count, _tokens, _hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, true).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", None),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    let resp = browser
        .get(&app, "auth.test.local", "/token?host=api.test.local")
        .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SEE_OTHER,
        "expected /token to redirect to the IdP like /login"
    );
    let mut authorize_url = url::Url::parse(&location(&resp)).unwrap();

    // The authorization request must carry the resource indicator so the
    // IdP can scope the issued access token to it.
    assert_eq!(
        authorize_url
            .query_pairs()
            .find(|(k, _)| k == "resource")
            .map(|(_, v)| v.to_string()),
        Some("https://api.test.local/".to_string())
    );

    authorize_url
        .query_pairs_mut()
        .append_pair("login_hint", "alice");
    let idp_resp = follow_real_redirect(&idp_client, authorize_url.as_str()).await;
    let callback_location = location(&idp_resp);
    let code = query_param(&callback_location, "code");
    let state_param = query_param(&callback_location, "state");

    let resp = browser
        .get(
            &app,
            "auth.test.local",
            &format!("/callback?code={code}&state={state_param}"),
        )
        .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "the /token callback should render the token page directly, not redirect"
    );
    assert!(
        !browser.cookies.contains_key("authward_session"),
        "a /token flow must not create a browser session"
    );

    let cache_control = resp
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert_eq!(cache_control, "no-store");

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("api.test.local"),
        "page should name the host the token is for"
    );
    assert!(
        body.contains("X-Auth-Token"),
        "page should tell the user which header to send the token in"
    );
    assert!(
        !body.contains("Bearer"),
        "with the default header the value is the bare token, no scheme word"
    );
}

#[tokio::test]
async fn token_helper_rejects_a_host_with_no_resource_configured() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    // spawn_app's default host ("app.test.local") has no resource configured.
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;

    let mut browser = Browser::new();
    let resp = browser
        .get(&app, "auth.test.local", "/token?host=app.test.local")
        .await;
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

// ---- Phase 6: overview / dashboard ---------------------------------------

fn extract_hidden_input_value(html: &str, name: &str) -> Option<String> {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html.find(&marker)? + marker.len();
    let end = html[start..].find('"')? + start;
    Some(html[start..end].to_string())
}

#[tokio::test]
async fn dashboard_requires_authentication() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;

    let mut browser = Browser::new();
    let resp = browser.get(&app, "auth.test.local", "/").await;
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    assert!(
        location(&resp).contains("/login"),
        "unauthenticated dashboard access should redirect to /login, got {}",
        location(&resp)
    );
}

#[tokio::test]
async fn revoking_a_different_session_only_invalidates_that_one() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    // The same user, logged in from two separate "devices".
    let mut browser_a = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser_a,
        "alice",
        "https://app.test.local/",
    )
    .await;
    let mut browser_b = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser_b,
        "alice",
        "https://app.test.local/",
    )
    .await;

    assert_eq!(
        browser_a
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        browser_b
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );

    // From browser A's dashboard, find browser B's (the *other*, non-current)
    // session handle. The page must never contain a raw session ID — that's
    // the credential itself.
    let dashboard = browser_a.get(&app, "auth.test.local", "/").await;
    assert_eq!(dashboard.status(), reqwest::StatusCode::OK);
    assert_eq!(
        dashboard.headers().get("cache-control").unwrap(),
        "no-store",
        "a page naming sessions must not be cached"
    );
    let html = dashboard.text().await.unwrap();
    for (name, browser) in [("A", &browser_a), ("B", &browser_b)] {
        assert!(
            !html.contains(&browser.cookies["authward_session"]),
            "dashboard leaked browser {name}'s raw session ID"
        );
    }
    let other_session = extract_hidden_input_value(&html, "session")
        .expect("dashboard should list the other device's session");

    let resp = browser_a
        .post_form(
            &app,
            "auth.test.local",
            "/sessions/revoke",
            &[("session", &other_session)],
        )
        .await;
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);

    assert_eq!(
        browser_b
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the revoked device's session should no longer be valid"
    );
    assert_eq!(
        browser_a
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK,
        "revoking a different session must not affect the caller's own session"
    );
}

#[tokio::test]
async fn revoke_session_rejects_get() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;

    let resp = browser
        .get(&app, "auth.test.local", "/sessions/revoke")
        .await;
    assert_eq!(resp.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
}

// ---- Phase 7: identity header passthrough --------------------------------

#[tokio::test]
async fn identity_headers_forwarded_when_enabled() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.forward_identity_headers = true;
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as_with_groups(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "admins,users",
        "https://app.test.local/",
    )
    .await;

    let resp = browser.get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.headers().get("x-auth-user").unwrap(), "alice");
    assert_eq!(
        resp.headers().get("x-auth-email").unwrap(),
        "alice@example.test"
    );
    assert_eq!(resp.headers().get("x-auth-groups").unwrap(), "admins,users");
}

/// When forwarding is off the headers are still *present*, as empty
/// values: Caddy's `copy_headers` only overwrites a client-supplied header
/// when the auth response carries it (GHSA-7r4p-vjf4-gxv4), so an absent
/// header would let the client's own `X-Auth-User` reach the backend.
#[tokio::test]
async fn identity_headers_present_but_empty_when_disabled() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    // spawn_app's default host has forward_identity_headers = false.
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;

    let resp = browser.get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    for name in ["x-auth-user", "x-auth-email", "x-auth-groups"] {
        assert_eq!(
            resp.headers().get(name).map(|v| v.as_bytes()),
            Some(&b""[..]),
            "{name} must be present and empty so copy_headers overwrites any client-supplied value"
        );
    }
}

#[tokio::test]
async fn unverified_email_is_not_forwarded() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.forward_identity_headers = true;
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as_with(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "",
        "https://app.test.local/",
        &[("email_verified", "false")],
    )
    .await;

    let resp = browser.get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(resp.headers().get("x-auth-user").unwrap(), "alice");
    assert_eq!(
        resp.headers().get("x-auth-email").unwrap(),
        "",
        "an email the IdP hasn't verified is whatever the user typed — never forwarded"
    );
}

#[tokio::test]
async fn session_is_cut_off_at_its_absolute_max_age() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.global.session_max_age = Duration::from_secs(1);
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local"),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;
    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );

    // The access token is good for an hour, so only the absolute cap can
    // end this session.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a session must end at session_max_age no matter how fresh its tokens are"
    );
}

#[tokio::test]
async fn refresh_returning_a_different_subject_clears_the_session() {
    let (idp_base_url, _count, refresh_tokens) = spawn_mock_idp(Duration::from_secs(1)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;

    // A misbehaving IdP hands back someone else's identity on refresh.
    for identity in refresh_tokens.lock().unwrap().values_mut() {
        identity.subject = "mallory".to_string();
    }

    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a refreshed id_token whose sub differs from the session's must end the session (OIDC Core 12.2)"
    );
}

#[tokio::test]
async fn verify_401_carries_a_properly_encoded_login_url() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;

    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("x-forwarded-proto", "https")
        .header("x-forwarded-uri", "/page?a=1&b=2")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let login_url = resp
        .headers()
        .get("x-login-url")
        .expect("401 should tell Caddy where to send the browser")
        .to_str()
        .unwrap()
        .to_string();
    assert!(login_url.starts_with("https://auth.test.local/login?rd="));
    assert_eq!(
        query_param(&login_url, "rd"),
        "https://app.test.local/page?a=1&b=2",
        "the original URL must survive as one query-encoded rd value, `&` included"
    );
}

#[tokio::test]
async fn verify_401_for_a_non_get_is_a_resubmit_page_without_a_login_url() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let client = reqwest::Client::new();

    for method in ["POST", "PUT", "DELETE", "PATCH"] {
        let resp = client
            .get(format!("{app}/verify"))
            .header("host", "app.test.local")
            .header("x-forwarded-method", method)
            .header("x-forwarded-uri", "/submit")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED, "{method}");
        assert!(
            resp.headers().get("x-login-url").is_none(),
            "{method}: a non-GET must not be redirected through login"
        );
        assert!(resp.text().await.unwrap().contains("Session expired"));
    }

    for method in ["GET", "HEAD", "get"] {
        let resp = client
            .get(format!("{app}/verify"))
            .header("host", "app.test.local")
            .header("x-forwarded-method", method)
            .header("x-forwarded-uri", "/page")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED, "{method}");
        assert!(
            resp.headers().get("x-login-url").is_some(),
            "{method}: a GET/HEAD is redirected through login"
        );
    }
}

#[tokio::test]
async fn html_responses_carry_security_headers() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;

    let resp = Browser::new()
        .get(&app, "auth.test.local", "/logged-out")
        .await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let h = resp.headers();
    assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
    assert_eq!(
        h.get("content-security-policy").unwrap(),
        "frame-ancestors 'none'"
    );
    assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
    // Must not be `no-referrer`: that makes browsers send `Origin: null`
    // on the dashboard's own form POSTs, which the CSRF guard refuses.
    assert_eq!(h.get("referrer-policy").unwrap(), "same-origin");
    assert_eq!(h.get("cache-control").unwrap(), "no-store");
}

#[tokio::test]
async fn spoofed_identity_header_on_the_request_is_ignored() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.forward_identity_headers = true;
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;

    // A client (or a compromised, directly-reachable backend) trying to
    // smuggle a spoofed identity via the /verify request itself. Our
    // response must reflect the *real*, verified subject regardless.
    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header(
            "cookie",
            format!("authward_session={}", browser.cookies["authward_session"]),
        )
        .header("x-auth-user", "root")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-auth-user").unwrap(),
        "alice",
        "the response must never echo a client-supplied X-Auth-User"
    );
}

// ---- Phase 8: logout -----------------------------------------------------

#[tokio::test]
async fn logout_clears_session_with_no_idp_logout_support() {
    let (idp_base_url, _count, _tokens, _hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, false).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;
    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );

    let resp = browser
        .post_form(&app, "auth.test.local", "/logout", &[])
        .await;
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    assert_eq!(
        location(&resp),
        "https://auth.test.local/logged-out",
        "no IdP logout support should fall back to the local confirmation page"
    );

    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the session should be cleared after logout"
    );
}

#[tokio::test]
async fn logout_redirects_to_idp_end_session_endpoint_when_supported() {
    let (idp_base_url, _count, _tokens, _hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, true).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;

    let resp = browser
        .post_form(&app, "auth.test.local", "/logout", &[])
        .await;
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    let redirect = location(&resp);
    assert!(
        redirect.starts_with(&format!("{idp_base_url}/end-session")),
        "should redirect to the IdP's end_session_endpoint, got {redirect}"
    );
    assert_eq!(query_param(&redirect, "client_id"), CLIENT_ID);
    assert_eq!(
        query_param(&redirect, "post_logout_redirect_uri"),
        "https://auth.test.local/logged-out"
    );

    // Follow through to the mock IdP, which redirects back to our local
    // logged-out page, completing RP-initiated logout end to end.
    let idp_resp = follow_real_redirect(&idp_client, &redirect).await;
    assert_eq!(location(&idp_resp), "https://auth.test.local/logged-out");

    assert_eq!(
        browser
            .get(&app, "app.test.local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn logout_honors_a_valid_rd_and_rejects_a_foreign_one() {
    let (idp_base_url, _count, _tokens, _hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, false).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;
    let resp = browser
        .post_form(
            &app,
            "auth.test.local",
            &format!("/logout?rd={}", urlencode("https://app.test.local/bye")),
            &[],
        )
        .await;
    assert_eq!(location(&resp), "https://app.test.local/bye");

    let mut browser2 = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser2,
        "alice",
        "https://app.test.local/",
    )
    .await;
    let resp = browser2
        .post_form(
            &app,
            "auth.test.local",
            &format!("/logout?rd={}", urlencode("https://evil.example/")),
            &[],
        )
        .await;
    assert_eq!(
        location(&resp),
        "https://auth.test.local/logged-out",
        "a foreign rd must fall back to the local page, same as /login's guard"
    );
}

#[tokio::test]
async fn state_changing_posts_refuse_cross_origin_browsers() {
    let (idp_base_url, _count, _tokens, _hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, false).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;

    // A sibling app on the same base domain is same-*site* (SameSite=Lax
    // sends the cookie) but not same-origin: refused, session untouched.
    // `Origin: null` is what a browser sends for a cross-origin form POST
    // under our `Referrer-Policy: same-origin` (and, under `no-referrer`,
    // for *every* form POST — see `security_headers`), so it must be
    // refused too.
    for headers in [
        &[("origin", "https://evil.test.local")][..],
        &[("sec-fetch-site", "same-site")][..],
        &[("origin", "null")][..],
    ] {
        let resp = browser
            .post_form_with_headers(&app, "auth.test.local", "/logout", &[], headers)
            .await;
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::FORBIDDEN,
            "{headers:?} should be refused"
        );
        assert_eq!(
            browser
                .get(&app, "app.test.local", "/verify")
                .await
                .status(),
            reqwest::StatusCode::OK,
            "a refused logout must not touch the session"
        );
    }

    // The account page itself is fine.
    let resp = browser
        .post_form_with_headers(
            &app,
            "auth.test.local",
            "/logout",
            &[],
            &[
                ("origin", "https://auth.test.local"),
                ("sec-fetch-site", "same-origin"),
            ],
        )
        .await;
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
}

#[tokio::test]
async fn logout_rejects_get() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;

    let resp = browser.get(&app, "auth.test.local", "/logout").await;
    assert_eq!(resp.status(), reqwest::StatusCode::METHOD_NOT_ALLOWED);
}

// ---- Phase 9: bypass paths, rate limiting, mixed-case hosts --------------

#[tokio::test]
async fn bypass_path_skips_auth_entirely() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.bypass_paths = vec![bypass::BypassEntry::unrestricted("/public/logo.svg")];
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    // No session cookie at all — an unbypassed path is denied...
    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("x-forwarded-uri", "/private/secret")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);

    // ...but the bypassed path skips auth entirely — while still emitting
    // empty identity headers, so a client can't smuggle its own X-Auth-*
    // through to the backend on a bypassed path (see the
    // identity_headers_present_but_empty_when_disabled test).
    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("x-forwarded-uri", "/public/logo.svg")
        .header("x-auth-user", "root")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    for name in ["x-auth-user", "x-auth-email", "x-auth-groups"] {
        assert_eq!(
            resp.headers().get(name).map(|v| v.as_bytes()),
            Some(&b""[..]),
            "{name} must be present and empty on a bypassed path"
        );
    }
}

#[tokio::test]
async fn bypass_wildcard_path_skips_auth_for_everything_under_the_prefix() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.bypass_paths = vec![bypass::BypassEntry::unrestricted("/public/*")];
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    for uri in ["/public/anything", "/public/nested/thing"] {
        let resp = reqwest::Client::new()
            .get(format!("{app}/verify"))
            .header("host", "app.test.local")
            .header("x-forwarded-uri", uri)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::OK,
            "{uri} should bypass"
        );
        for name in ["x-auth-user", "x-auth-email", "x-auth-groups"] {
            assert_eq!(
                resp.headers().get(name).map(|v| v.as_bytes()),
                Some(&b""[..]),
                "{name} must be present and empty on a bypassed path"
            );
        }
    }

    for uri in ["/public", "/publicly", "/private/secret"] {
        let resp = reqwest::Client::new()
            .get(format!("{app}/verify"))
            .header("host", "app.test.local")
            .header("x-forwarded-uri", uri)
            .send()
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            reqwest::StatusCode::UNAUTHORIZED,
            "{uri} should not bypass"
        );
    }
}

#[tokio::test]
async fn bypass_wildcard_does_not_match_a_request_with_a_dot_segment() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.bypass_paths = vec![bypass::BypassEntry::unrestricted("/public/*")];
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("x-forwarded-uri", "/public/../admin")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn scoped_bypass_allows_configured_method_and_denies_others() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.bypass_paths = vec![bypass::BypassEntry {
        path: "/api/assets/*".to_string(),
        methods: Some(vec!["GET".to_string(), "HEAD".to_string()]),
    }];
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("x-forwarded-uri", "/api/assets/1")
        .header("x-forwarded-method", "GET")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "GET is in the configured methods list"
    );

    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("x-forwarded-uri", "/api/assets/1")
        .header("x-forwarded-method", "DELETE")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "DELETE is not in the configured methods list, so the same path must not bypass"
    );
}

#[tokio::test]
async fn scoped_bypass_fails_closed_when_x_forwarded_method_is_missing() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.bypass_paths = vec![bypass::BypassEntry {
        path: "/api/assets/*".to_string(),
        methods: Some(vec!["GET".to_string()]),
    }];
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("x-forwarded-uri", "/api/assets/1")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a method-scoped entry must not match when the method can't be determined"
    );
}

#[tokio::test]
async fn bypass_path_appended_as_query_string_does_not_bypass_a_protected_route() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.bypass_paths = vec![bypass::BypassEntry::unrestricted("/public/logo.svg")];
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("x-forwarded-uri", "/admin/dashboard?x=/public/logo.svg")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "an allowed path appended to an unrelated route's query string must not bypass auth"
    );
}

#[tokio::test]
async fn bypass_path_with_a_fragment_does_not_bypass() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.bypass_paths = vec![bypass::BypassEntry::unrestricted("/public/logo.svg")];
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("x-forwarded-uri", "/public/logo.svg#whatever")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn login_is_rate_limited_per_ip_but_not_other_ips() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut last_status = reqwest::StatusCode::OK;
    for _ in 0..25 {
        last_status = client
            .get(format!("{app}/login"))
            .header("host", "auth.test.local")
            .header("x-forwarded-for", "203.0.113.9")
            .send()
            .await
            .unwrap()
            .status();
    }
    assert_eq!(
        last_status,
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "should be rate limited after exhausting the burst capacity"
    );

    let resp = client
        .get(format!("{app}/login"))
        .header("host", "auth.test.local")
        .header("x-forwarded-for", "198.51.100.7")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SEE_OTHER,
        "a different source IP must have its own independent budget"
    );
}

#[tokio::test]
async fn mixed_case_and_multi_level_host_headers_resolve_correctly() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "deep.app.test.local".to_string(),
        resolved_host("deep.app.test.local", "test.local"),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://deep.app.test.local/",
    )
    .await;

    assert_eq!(
        browser
            .get(&app, "Deep.App.Test.Local", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        browser
            .get(&app, "DEEP.APP.TEST.LOCAL", "/verify")
            .await
            .status(),
        reqwest::StatusCode::OK
    );
}

// ---- Config rework: per-domain fallback, shared IdPs -------------------

/// A domain's `fallback` covers unlisted hosts under *that* domain only;
/// an unlisted host under another domain is still a hard failure.
#[tokio::test]
async fn a_domains_fallback_does_not_cover_hosts_under_another_domain() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();

    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    add_domain(&mut cfg, "other.local", "auth.other.local", &idp_base_url);
    cfg.base_domains.get_mut("test.local").unwrap().fallback = Some(config::ResolvedHost {
        host: None,
        ..resolved_host("*.test.local", "test.local")
    });
    let (app, _state) = spawn_app_with_config(cfg).await;

    let mut browser = Browser::new();
    let resp = browser
        .get(&app, "unlisted.deep.test.local", "/verify")
        .await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "an unlisted host under the domain with a fallback is protected, not unknown"
    );
    assert!(
        resp.headers()
            .get("x-login-url")
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.starts_with("https://auth.test.local/login?")),
        "the fallback host logs in at its own domain's auth subdomain"
    );

    let resp = browser.get(&app, "unlisted.other.local", "/verify").await;
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "the other domain has no fallback, so its unlisted hosts stay a hard failure"
    );
    assert!(
        resp.headers().get("x-login-url").is_none(),
        "unlike the fallback-covered host above, there's no auth subdomain to redirect to"
    );
}

/// Two domains referencing the same `[idp]` share one discovered client,
/// but each login carries that domain's own `/callback` as redirect URI
/// and completes on that domain's auth subdomain.
#[tokio::test]
async fn two_domains_sharing_one_idp_each_use_their_own_callback() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();

    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    add_domain(&mut cfg, "other.local", "auth.other.local", &idp_base_url);
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local"),
    );
    cfg.hosts.insert(
        "app.other.local".to_string(),
        resolved_host("app.other.local", "other.local"),
    );
    let (app, state) = spawn_app_with_config(cfg).await;
    assert_eq!(
        state.provider_runtimes().len(),
        1,
        "one [idp] block is discovered exactly once, however many domains use it"
    );

    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    for (auth_host, app_host) in [
        ("auth.test.local", "app.test.local"),
        ("auth.other.local", "app.other.local"),
    ] {
        let mut browser = Browser::new();
        let rd = format!("https://{app_host}/");
        let resp = browser
            .get(&app, auth_host, &format!("/login?rd={}", urlencode(&rd)))
            .await;
        assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
        let authorize_url = location(&resp);
        assert_eq!(
            query_param(&authorize_url, "redirect_uri"),
            format!("https://{auth_host}/callback"),
            "the authorization request names this domain's own callback"
        );

        let mut authorize_url = url::Url::parse(&authorize_url).unwrap();
        authorize_url
            .query_pairs_mut()
            .append_pair("login_hint", "alice");
        let idp_resp = follow_real_redirect(&idp_client, authorize_url.as_str()).await;
        assert_eq!(idp_resp.status(), reqwest::StatusCode::SEE_OTHER);
        let callback_location = location(&idp_resp);
        assert!(
            callback_location.starts_with(&format!("https://{auth_host}/callback")),
            "the IdP sends the browser back to this domain's callback: {callback_location}"
        );
        let code = query_param(&callback_location, "code");
        let csrf = query_param(&callback_location, "state");

        let resp = browser
            .get(
                &app,
                auth_host,
                &format!("/callback?code={code}&state={csrf}"),
            )
            .await;
        assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
        assert_eq!(location(&resp), rd);

        assert_eq!(
            browser.get(&app, app_host, "/verify").await.status(),
            reqwest::StatusCode::OK,
            "{app_host} accepts the session established on its own domain"
        );
    }
}

// ---- /verify HTTP caching ---------------------------------------------

fn header_str<'a>(resp: &'a reqwest::Response, name: &str) -> Option<&'a str> {
    resp.headers().get(name).and_then(|v| v.to_str().ok())
}

/// The `max-age` a `/verify` answer carries, or `None` if it isn't
/// cacheable.
fn verify_max_age(resp: &reqwest::Response) -> Option<u64> {
    header_str(resp, "cache-control")?
        .strip_prefix("max-age=")?
        .parse()
        .ok()
}

#[tokio::test]
async fn verify_stays_no_store_when_caching_is_disabled() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let (app, _state) = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;
    let resp = browser.get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(header_str(&resp, "cache-control"), Some("no-store"));
    assert_eq!(header_str(&resp, "vary"), None);
}

#[tokio::test]
async fn verify_success_is_cacheable_but_401_and_403_never_are() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.global.verify_cache_max_age = Duration::from_secs(60);
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local"),
    );
    let mut admin_host = resolved_host("admin.test.local", "test.local");
    admin_host.required_group = Some("admins".to_string());
    cfg.hosts.insert("admin.test.local".to_string(), admin_host);
    let (app, _state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut bob = Browser::new();
    login_as_with_groups(
        &app,
        &idp_client,
        &mut bob,
        "bob",
        "users",
        "https://app.test.local/",
    )
    .await;

    let resp = bob.get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(header_str(&resp, "cache-control"), Some("max-age=60"));
    // Host has no path rules, so the answer doesn't depend on the URI —
    // but always on the cookie and on which app is being accessed.
    assert_eq!(header_str(&resp, "vary"), Some("cookie, x-forwarded-host"));

    // Same session, a host that requires a group bob lacks: 403, uncached.
    let resp = bob.get(&app, "admin.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::FORBIDDEN);
    assert_eq!(header_str(&resp, "cache-control"), Some("no-store"));
    assert_eq!(verify_max_age(&resp), None);

    // No session: the 401 Caddy turns into the login redirect, uncached.
    let resp = Browser::new().get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert!(resp.headers().contains_key("x-login-url"));
    assert_eq!(header_str(&resp, "cache-control"), Some("no-store"));

    // Other routes are unaffected — including a redirect.
    let resp = Browser::new().get(&app, "auth.test.local", "/").await;
    assert!(resp.status().is_redirection());
    assert_eq!(header_str(&resp, "cache-control"), Some("no-store"));
}

#[tokio::test]
async fn verify_max_age_never_outlives_the_session_token() {
    // Access/ID token valid for 30s, cap far above that.
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(30)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.global.verify_cache_max_age = Duration::from_secs(600);
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local"),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;
    let resp = browser.get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let max_age = verify_max_age(&resp).expect("success should be cacheable");
    assert!(
        (1..=30).contains(&max_age),
        "max-age {max_age} must be clamped to the token's remaining validity"
    );
}

#[tokio::test]
async fn verify_max_age_never_outlives_the_session_max_age() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.global.verify_cache_max_age = Duration::from_secs(600);
    cfg.global.session_max_age = Duration::from_secs(20);
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local"),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;
    let idp_client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();

    let mut browser = Browser::new();
    login_as(
        &app,
        &idp_client,
        &mut browser,
        "alice",
        "https://app.test.local/",
    )
    .await;
    let resp = browser.get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let max_age = verify_max_age(&resp).expect("success should be cacheable");
    assert!(
        (1..=20).contains(&max_age),
        "max-age {max_age} must be clamped to the session's absolute max age"
    );
}

#[tokio::test]
async fn verify_bearer_success_is_cacheable_until_token_expiry_and_varies_on_its_header() {
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO, true).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.global.verify_cache_max_age = Duration::from_secs(600);
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", None),
    );
    let (app, _state) = spawn_app_with_config(cfg).await;

    let send = |token: String| {
        let app = app.clone();
        async move {
            reqwest::Client::new()
                .get(format!("{app}/verify"))
                .header("host", "api.test.local")
                .header("x-auth-token", token)
                .send()
                .await
                .unwrap()
        }
    };

    let token = build_access_token(
        &hmac_key.lock().unwrap(),
        &idp_base_url,
        "https://api.test.local/",
        None,
        120,
    );
    let resp = send(token).await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let max_age = verify_max_age(&resp).expect("success should be cacheable");
    assert!(
        (1..=120).contains(&max_age),
        "max-age {max_age} must be clamped to the token's exp"
    );
    assert_eq!(
        header_str(&resp, "vary"),
        Some("cookie, x-forwarded-host, x-auth-token")
    );

    let expired = build_access_token(
        &hmac_key.lock().unwrap(),
        &idp_base_url,
        "https://api.test.local/",
        None,
        -3600,
    );
    let resp = send(expired).await;
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    assert_eq!(header_str(&resp, "cache-control"), Some("no-store"));
}

#[tokio::test]
async fn verify_varies_on_uri_and_method_when_the_host_has_path_rules() {
    let (idp_base_url, _count, _tokens) = spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.global.verify_cache_max_age = Duration::from_secs(60);
    add_domain(&mut cfg, "test.local", "auth.test.local", &idp_base_url);
    let mut app_host = resolved_host("app.test.local", "test.local");
    app_host.bypass_paths = vec![bypass::BypassEntry::unrestricted("/public/logo.svg")];
    cfg.hosts.insert("app.test.local".to_string(), app_host);
    let (app, _state) = spawn_app_with_config(cfg).await;

    let resp = reqwest::Client::new()
        .get(format!("{app}/verify"))
        .header("host", "app.test.local")
        .header("x-forwarded-uri", "/public/logo.svg")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    assert_eq!(header_str(&resp, "cache-control"), Some("max-age=60"));
    assert_eq!(
        header_str(&resp, "vary"),
        Some("cookie, x-forwarded-host, x-forwarded-uri, x-forwarded-method")
    );
}
