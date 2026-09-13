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

use axum::extract::{Form, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
use forward_auth::config;
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

const CLIENT_ID: &str = "forward-auth-test-client";
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
}

#[derive(Deserialize)]
struct TokenParams {
    grant_type: String,
    code: Option<String>,
    refresh_token: Option<String>,
}

async fn discovery(State(idp): State<MockIdp>) -> Json<serde_json::Value> {
    Json(json!({
        "issuer": idp.base_url,
        "authorization_endpoint": format!("{}/authorize", idp.base_url),
        "token_endpoint": format!("{}/token", idp.base_url),
        "jwks_uri": format!("{}/jwks", idp.base_url),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["HS256"],
    }))
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
    let code = forward_auth::crypto::random_hex(16);
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
            let refresh_token = forward_auth::crypto::random_hex(16);
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
            let new_refresh_token = forward_auth::crypto::random_hex(16);
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
        spawn_mock_idp_full(access_token_ttl, refresh_delay).await;
    (base_url, refresh_grant_count, refresh_tokens)
}

/// Full form of `spawn_mock_idp`, also returning the mock's HMAC signing
/// key handle so a test can rotate it (Phase 5's key-rotation test) or
/// sign a hand-built bearer token directly without a real /token round
/// trip (`build_access_token`).
async fn spawn_mock_idp_full(
    access_token_ttl: Duration,
    refresh_delay: Duration,
) -> (
    String,
    Arc<AtomicUsize>,
    Arc<Mutex<HashMap<String, PendingAuth>>>,
    Arc<Mutex<CoreHmacKey>>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
    };

    let refresh_tokens = idp.refresh_tokens.clone();
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
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
    use base64::Engine;
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
    let header_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
    let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(serde_json::to_vec(&payload).unwrap());
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

fn test_provider(idp_base_url: &str) -> config::Provider {
    config::Provider {
        discovery_url: url::Url::parse(&format!("{idp_base_url}/.well-known/openid-configuration"))
            .unwrap(),
        client_id: CLIENT_ID.to_string(),
        client_secret: CLIENT_SECRET.to_string(),
    }
}

fn base_domain_block(name: &str, auth_subdomain: &str, idp_base_url: &str) -> config::BaseDomain {
    config::BaseDomain {
        name: name.to_string(),
        auth_subdomain: auth_subdomain.to_string(),
        provider: test_provider(idp_base_url),
    }
}

fn resolved_host(host: &str, base_domain: &str, idp_base_url: &str) -> config::ResolvedHost {
    config::ResolvedHost {
        host: Some(host.to_string()),
        base_domain: base_domain.to_string(),
        provider: test_provider(idp_base_url),
        required_group: None,
        group_claim_name: "groups".to_string(),
        bypass_paths: Vec::new(),
        forward_identity_headers: false,
        resource: None,
        required_scope: None,
    }
}

async fn spawn_app_with_config(cfg: config::Config) -> (String, forward_auth::state::AppState) {
    let state = forward_auth::build_state(cfg)
        .await
        .expect("build_state against mock IdP");
    let app = forward_auth::server::build_router(state.clone());

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
            otel_endpoint: None,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
        },
        base_domains: HashMap::new(),
        hosts: HashMap::new(),
        fallback: None,
    }
}

async fn spawn_app(
    idp_base_url: &str,
    db_path: &std::path::Path,
) -> (String, forward_auth::state::AppState) {
    let mut cfg = base_config(db_path);
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", idp_base_url),
    );
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local", idp_base_url),
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
        browser.cookies.contains_key("fa_session"),
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
    assert!(alice.cookies.contains_key("fa_session"));
    assert!(bob.cookies.contains_key("fa_session"));
    assert_ne!(alice.cookies["fa_session"], bob.cookies["fa_session"]);

    assert_eq!(
        alice.get(&app, "app.test.local", "/verify").await.status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        bob.get(&app, "app.test.local", "/verify").await.status(),
        reqwest::StatusCode::OK
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
    let session_cookie_before = browser.cookies["fa_session"].clone();

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
    assert_eq!(browser.cookies["fa_session"], session_cookie_before);
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
    let cookie_header = format!("fa_session={}", browser.cookies["fa_session"]);

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

    forward_auth::db::create_session(
        &state.db,
        "reaper-test-session",
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

    forward_auth::session::reap_expired_sessions(&state).await;

    assert!(
        forward_auth::db::get_session(&state.db, "reaper-test-session")
            .await
            .unwrap()
            .is_none()
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
    let cookie_header = format!("fa_session={}", browser.cookies["fa_session"]);

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
    forward_auth::session::reap_expired_sessions(&state).await;

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
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", &idp_base_url),
    );
    cfg.hosts.insert(
        "app-one.test.local".to_string(),
        resolved_host("app-one.test.local", "test.local", &idp_base_url),
    );
    cfg.hosts.insert(
        "app-two.test.local".to_string(),
        resolved_host("app-two.test.local", "test.local", &idp_base_url),
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
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", &idp_base_url),
    );
    cfg.base_domains.insert(
        "other.local".to_string(),
        base_domain_block("other.local", "auth.other.local", &idp_base_url),
    );
    cfg.hosts.insert(
        "app.test.local".to_string(),
        resolved_host("app.test.local", "test.local", &idp_base_url),
    );
    cfg.hosts.insert(
        "app.other.local".to_string(),
        resolved_host("app.other.local", "other.local", &idp_base_url),
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
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_GATEWAY);
}

#[tokio::test]
async fn fallback_provider_covers_hosts_with_no_explicit_config() {
    let (idp_base_url, _refresh_grant_count, _refresh_tokens) =
        spawn_mock_idp(Duration::from_secs(3600)).await;
    let db_dir = tempfile::tempdir().unwrap();

    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", &idp_base_url),
    );
    // No entry in `hosts` at all — every host on this instance relies on
    // the fallback provider.
    cfg.fallback = Some(config::ResolvedHost {
        host: None,
        ..resolved_host("<fallback>", "test.local", &idp_base_url)
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
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", &idp_base_url),
    );
    let mut admin_host = resolved_host("admin.test.local", "test.local", &idp_base_url);
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
async fn revoking_group_membership_denies_access_on_next_refresh_without_relogin() {
    let ttl = Duration::from_secs(1);
    let (idp_base_url, _refresh_grant_count, refresh_tokens) = spawn_mock_idp(ttl).await;
    let db_dir = tempfile::tempdir().unwrap();

    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", &idp_base_url),
    );
    let mut admin_host = resolved_host("admin.test.local", "test.local", &idp_base_url);
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
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .status()
}

fn api_host(
    resource: &str,
    required_scope: Option<&str>,
    idp_base_url: &str,
) -> config::ResolvedHost {
    config::ResolvedHost {
        resource: Some(resource.to_string()),
        required_scope: required_scope.map(str::to_string),
        ..resolved_host("api.test.local", "test.local", idp_base_url)
    }
}

#[tokio::test]
async fn bearer_token_grants_access_for_matching_resource_and_scope() {
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", &idp_base_url),
    );
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", Some("read"), &idp_base_url),
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
async fn bearer_token_for_a_different_resource_is_rejected() {
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", &idp_base_url),
    );
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", None, &idp_base_url),
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
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", &idp_base_url),
    );
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", Some("admin"), &idp_base_url),
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
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", &idp_base_url),
    );
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", None, &idp_base_url),
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
async fn bearer_token_survives_idp_key_rotation() {
    let (idp_base_url, _count, _tokens, hmac_key) =
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", &idp_base_url),
    );
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", None, &idp_base_url),
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
        spawn_mock_idp_full(Duration::from_secs(3600), Duration::ZERO).await;
    let db_dir = tempfile::tempdir().unwrap();
    let mut cfg = base_config(&db_dir.path().join("sessions.db"));
    cfg.base_domains.insert(
        "test.local".to_string(),
        base_domain_block("test.local", "auth.test.local", &idp_base_url),
    );
    cfg.hosts.insert(
        "api.test.local".to_string(),
        api_host("https://api.test.local/", None, &idp_base_url),
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
        !browser.cookies.contains_key("fa_session"),
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
        "page should name the resource the token is for"
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
