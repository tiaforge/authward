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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Form, Query, State};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration as ChronoDuration, Utc};
use forward_auth::config;
use openidconnect::core::{
    CoreGenderClaim, CoreHmacKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    CoreTokenResponse, CoreTokenType,
};
use openidconnect::{
    AccessToken, Audience, EmptyAdditionalClaims, EmptyExtraTokenFields, EndUserEmail, IdToken,
    IdTokenClaims, IdTokenFields, IssuerUrl, JsonWebKeySet, Nonce, PrivateSigningKey,
    StandardClaims, SubjectIdentifier,
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
}

#[derive(Clone)]
struct MockIdp {
    base_url: String,
    hmac_key: Arc<CoreHmacKey>,
    pending: Arc<Mutex<HashMap<String, PendingAuth>>>,
}

#[derive(Deserialize)]
struct AuthorizeParams {
    redirect_uri: String,
    state: String,
    nonce: String,
    /// Doubles as "which test identity is logging in" — a real IdP would
    /// show a login form; we skip straight to picking an identity.
    login_hint: Option<String>,
}

#[derive(Deserialize)]
struct TokenParams {
    code: String,
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
    Json(JsonWebKeySet::new(vec![idp.hmac_key.as_verification_key()]))
}

async fn authorize(
    State(idp): State<MockIdp>,
    Query(params): Query<AuthorizeParams>,
) -> impl IntoResponse {
    let code = forward_auth::crypto::random_hex(16);
    let subject = params
        .login_hint
        .unwrap_or_else(|| "default-user".to_string());
    idp.pending.lock().unwrap().insert(
        code.clone(),
        PendingAuth {
            nonce: params.nonce,
            email: format!("{subject}@example.test"),
            subject,
        },
    );

    let mut redirect_url = url::Url::parse(&params.redirect_uri).expect("valid redirect_uri");
    redirect_url
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &params.state);
    Redirect::to(redirect_url.as_str())
}

async fn token(
    State(idp): State<MockIdp>,
    Form(params): Form<TokenParams>,
) -> Json<CoreTokenResponse> {
    let pending = idp
        .pending
        .lock()
        .unwrap()
        .remove(&params.code)
        .expect("mock IdP received a code it never issued");

    let now = Utc::now();
    let claims = IdTokenClaims::new(
        IssuerUrl::new(idp.base_url.clone()).unwrap(),
        vec![Audience::new(CLIENT_ID.to_string())],
        now + ChronoDuration::seconds(3600),
        now,
        StandardClaims::new(SubjectIdentifier::new(pending.subject))
            .set_email(Some(EndUserEmail::new(pending.email))),
        EmptyAdditionalClaims {},
    )
    .set_nonce(Some(Nonce::new(pending.nonce)));

    let id_token = IdToken::<
        EmptyAdditionalClaims,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >::new(
        claims,
        idp.hmac_key.as_ref(),
        CoreJwsSigningAlgorithm::HmacSha256,
        None,
        None,
    )
    .expect("signing the mock ID token should not fail");

    let mut response = CoreTokenResponse::new(
        AccessToken::new("mock-access-token".to_string()),
        CoreTokenType::Bearer,
        IdTokenFields::new(Some(id_token), EmptyExtraTokenFields {}),
    );
    response.set_expires_in(Some(&Duration::from_secs(3600)));
    Json(response)
}

async fn spawn_mock_idp() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());

    let idp = MockIdp {
        base_url: base_url.clone(),
        hmac_key: Arc::new(CoreHmacKey::new(CLIENT_SECRET.as_bytes().to_vec())),
        pending: Arc::new(Mutex::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .with_state(idp);

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    base_url
}

// ---- App under test ---------------------------------------------------

async fn spawn_app(idp_base_url: &str, db_path: &std::path::Path) -> String {
    let base_domain_name = "test.local".to_string();
    let mut base_domains = HashMap::new();
    base_domains.insert(
        base_domain_name.clone(),
        config::BaseDomain {
            name: base_domain_name.clone(),
            auth_subdomain: "auth.test.local".to_string(),
            provider: config::Provider {
                discovery_url: url::Url::parse(&format!(
                    "{idp_base_url}/.well-known/openid-configuration"
                ))
                .unwrap(),
                client_id: CLIENT_ID.to_string(),
                client_secret: CLIENT_SECRET.to_string(),
            },
        },
    );

    let cfg = config::Config {
        global: config::Global {
            cookie_signing_key: "test-only-cookie-signing-key-32-bytes-min".to_string(),
            refresh_token_encryption_key: "test-only-refresh-key-32-bytes-minimum!!".to_string(),
            sqlite_path: db_path.to_path_buf(),
            session_ttl_fallback: Duration::from_secs(3600),
            otel_endpoint: None,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
        },
        base_domains,
        hosts: HashMap::new(),
        fallback: None,
    };

    let state = forward_auth::build_state(cfg)
        .await
        .expect("build_state against mock IdP");
    let app = forward_auth::server::build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{addr}")
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

async fn login_as(
    app: &str,
    idp_client: &reqwest::Client,
    browser: &mut Browser,
    login_hint: &str,
    rd: &str,
) {
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
        "expected /callback to redirect to rd"
    );
    assert_eq!(location(&resp), rd);
    assert!(
        browser.cookies.contains_key("fa_session"),
        "expected a session cookie after login"
    );
}

fn urlencode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[tokio::test]
async fn login_then_verify_succeeds() {
    let idp_base_url = spawn_mock_idp().await;
    let db_dir = tempfile::tempdir().unwrap();
    let app = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
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
        "https://app.test.local/dashboard",
    )
    .await;

    let resp = browser.get(&app, "app.test.local", "/verify").await;
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn verify_without_session_is_unauthorized() {
    let idp_base_url = spawn_mock_idp().await;
    let db_dir = tempfile::tempdir().unwrap();
    let app = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;

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
    let idp_base_url = spawn_mock_idp().await;
    let db_dir = tempfile::tempdir().unwrap();
    let app = spawn_app(&idp_base_url, &db_dir.path().join("sessions.db")).await;
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
