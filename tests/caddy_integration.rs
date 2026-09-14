//! End-to-end test of the actual Caddy integration (Phase 10): a real
//! `caddy` binary, configured the way the reference Caddyfile documents,
//! sitting in front of a real forward-auth instance and a trivial
//! backend app. Confirms the parts that can't be verified by testing
//! forward-auth alone: that `forward_auth` + `handle_response` really
//! does redirect an unauthenticated request to `/login`, that
//! `copy_headers` really does carry identity headers onto the backend
//! request, and that the full round trip (denied -> login -> callback ->
//! back to the originally-requested backend path) works through Caddy.
//!
//! Skips (prints a message, does not fail) if no `caddy` binary is
//! available — set `CADDY_BIN` to point at one, or have `caddy` on PATH.
//! This is the one test in the suite that depends on external tooling;
//! everything else in `login_flow.rs` deliberately simulates Caddy's
//! contract instead so it always runs.

use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::Query;
use axum::response::Redirect;
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::Utc;
use openidconnect::PrivateSigningKey;
use openidconnect::core::{CoreHmacKey, CoreJsonWebKey, CoreJwsSigningAlgorithm};
use serde::Deserialize;
use serde_json::json;

const CLIENT_ID: &str = "forward-auth-test-client";
const CLIENT_SECRET: &str = "caddy-integration-test-secret";

fn caddy_bin() -> String {
    std::env::var("CADDY_BIN").unwrap_or_else(|_| "caddy".to_string())
}

fn caddy_available() -> bool {
    Command::new(caddy_bin())
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

// ---- Minimal mock IdP (subject/email only; no groups/resource needed here) --

#[derive(Clone, Default)]
struct MockIdpState {
    base_url: Arc<std::sync::OnceLock<String>>,
    pending: Arc<std::sync::Mutex<std::collections::HashMap<String, (String, String)>>>, // code -> (subject, nonce)
}

#[derive(Deserialize)]
struct AuthorizeParams {
    redirect_uri: String,
    state: String,
    nonce: String,
}

async fn spawn_mock_idp() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let idp = MockIdpState::default();
    idp.base_url.set(base_url.clone()).unwrap();

    let hmac_key = Arc::new(CoreHmacKey::new(CLIENT_SECRET.as_bytes().to_vec()));

    let discovery = {
        let idp = idp.clone();
        move || {
            let base = idp.base_url.get().unwrap().clone();
            async move {
                Json(json!({
                    "issuer": base,
                    "authorization_endpoint": format!("{base}/authorize"),
                    "token_endpoint": format!("{base}/token"),
                    "jwks_uri": format!("{base}/jwks"),
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["HS256"],
                }))
            }
        }
    };

    let jwks = {
        let hmac_key = hmac_key.clone();
        move || {
            let hmac_key = hmac_key.clone();
            async move {
                Json(openidconnect::JsonWebKeySet::<CoreJsonWebKey>::new(vec![
                    hmac_key.as_verification_key(),
                ]))
            }
        }
    };

    let authorize = {
        let idp = idp.clone();
        move |Query(params): Query<AuthorizeParams>| {
            let idp = idp.clone();
            async move {
                let code = authgate::crypto::random_hex(16);
                idp.pending
                    .lock()
                    .unwrap()
                    .insert(code.clone(), ("alice".to_string(), params.nonce));
                let mut url = url::Url::parse(&params.redirect_uri).unwrap();
                url.query_pairs_mut()
                    .append_pair("code", &code)
                    .append_pair("state", &params.state);
                Redirect::to(url.as_str())
            }
        }
    };

    let token = {
        let idp = idp.clone();
        let hmac_key = hmac_key.clone();
        move |body: axum::body::Bytes| {
            let idp = idp.clone();
            let hmac_key = hmac_key.clone();
            async move {
                let code = url::form_urlencoded::parse(&body)
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.into_owned())
                    .unwrap();
                let (subject, nonce) = idp.pending.lock().unwrap().remove(&code).unwrap();
                let base = idp.base_url.get().unwrap().clone();
                let now = Utc::now();
                let payload = json!({
                    "iss": base,
                    "aud": [CLIENT_ID],
                    "sub": subject,
                    "email": format!("{subject}@example.test"),
                    "iat": now.timestamp(),
                    "exp": now.timestamp() + 3600,
                    "nonce": nonce,
                });
                use base64::Engine;
                let header_b64 =
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
                let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(serde_json::to_vec(&payload).unwrap());
                let signing_input = format!("{header_b64}.{payload_b64}");
                let sig = hmac_key
                    .sign(
                        &CoreJwsSigningAlgorithm::HmacSha256,
                        signing_input.as_bytes(),
                    )
                    .unwrap();
                let id_token = format!(
                    "{signing_input}.{}",
                    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(sig)
                );
                Json(json!({
                    "access_token": "mock-access-token",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "id_token": id_token,
                }))
            }
        }
    };

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token));

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    base_url
}

// ---- Trivial backend app, echoing headers so we can see what Caddy forwarded --

async fn spawn_backend_app() -> (u16, Arc<AtomicUsize>) {
    let hit_count = Arc::new(AtomicUsize::new(0));
    let hits = hit_count.clone();
    let handler = move |headers: axum::http::HeaderMap, uri: axum::http::Uri| {
        let hits = hits.clone();
        async move {
            hits.fetch_add(1, Ordering::SeqCst);
            let user = headers
                .get("x-auth-user")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();
            format!("backend ok path={uri} x-auth-user={user}")
        }
    };
    let app = Router::new().fallback(get(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (port, hit_count)
}

#[tokio::test]
async fn full_flow_through_real_caddy() {
    if !caddy_available() {
        eprintln!(
            "skipping full_flow_through_real_caddy: no `caddy` binary found (set CADDY_BIN or add caddy to PATH)"
        );
        return;
    }

    let idp_base_url = spawn_mock_idp().await;
    let (backend_port, backend_hits) = spawn_backend_app().await;

    // --- forward-auth itself, via the same in-process construction the
    // rest of the suite uses, so this test only adds the Caddy layer on
    // top rather than re-testing forward-auth's own logic.
    let mut base_domains = std::collections::HashMap::new();
    base_domains.insert(
        "test.local".to_string(),
        authgate::config::BaseDomain {
            name: "test.local".to_string(),
            auth_subdomain: "auth.test.local".to_string(),
            provider: authgate::config::Provider {
                discovery_url: url::Url::parse(&format!(
                    "{idp_base_url}/.well-known/openid-configuration"
                ))
                .unwrap(),
                client_id: CLIENT_ID.to_string(),
                client_secret: CLIENT_SECRET.to_string(),
            },
        },
    );
    let mut hosts = std::collections::HashMap::new();
    hosts.insert(
        "app.test.local".to_string(),
        authgate::config::ResolvedHost {
            host: Some("app.test.local".to_string()),
            base_domain: "test.local".to_string(),
            provider: authgate::config::Provider {
                discovery_url: url::Url::parse(&format!(
                    "{idp_base_url}/.well-known/openid-configuration"
                ))
                .unwrap(),
                client_id: CLIENT_ID.to_string(),
                client_secret: CLIENT_SECRET.to_string(),
            },
            required_group: None,
            group_claim_name: "groups".to_string(),
            bypass_paths: Vec::new(),
            forward_identity_headers: true,
            resource: None,
            required_scope: None,
        },
    );
    let db_dir = tempfile::tempdir().unwrap();
    let cfg = authgate::config::Config {
        global: authgate::config::Global {
            cookie_signing_key: "caddy-test-cookie-signing-key-32-bytes!!".to_string(),
            refresh_token_encryption_key: "caddy-test-refresh-key-32-bytes-minimum!".to_string(),
            sqlite_path: db_dir.path().join("sessions.db"),
            session_ttl_fallback: Duration::from_secs(3600),
            session_max_age: Duration::from_secs(24 * 3600),
            otel_endpoint: None,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
        },
        base_domains,
        hosts,
        fallback: None,
    };
    let state = authgate::build_state(cfg)
        .await
        .expect("build_state against mock IdP");
    let auth_app = authgate::server::build_router(state);
    let auth_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let auth_port = auth_listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(auth_listener, auth_app).await.unwrap();
    });

    // --- Real Caddy, configured per the reference Caddyfile's shape.
    let caddy_port = free_port().await;
    let caddyfile = format!(
        r#"
{{
	auto_https off
	admin off
}}

:{caddy_port} {{
	@auth host auth.test.local
	handle @auth {{
		reverse_proxy 127.0.0.1:{auth_port}
	}}

	@app host app.test.local
	handle @app {{
		forward_auth 127.0.0.1:{auth_port} {{
			uri /verify
			copy_headers X-Auth-User X-Auth-Email

			@denied status 401
			handle_response @denied {{
				redir * {{http.reverse_proxy.header.X-Login-Url}} 302
			}}
		}}
		reverse_proxy 127.0.0.1:{backend_port}
	}}
}}
"#
    );
    let mut caddyfile_path = std::env::temp_dir();
    caddyfile_path.push(format!("forward-auth-test-caddyfile-{caddy_port}"));
    std::fs::write(&caddyfile_path, &caddyfile).unwrap();

    let mut caddy = Command::new(caddy_bin())
        .args(["run", "--config"])
        .arg(&caddyfile_path)
        .args(["--adapter", "caddyfile"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start caddy");

    // Give Caddy a moment to bind its listener.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // A real cookie jar would (correctly, per RFC 6265) refuse the session
    // cookie's `Domain=.test.local` attribute for a response that, as far
    // as any real HTTP stack is concerned, came from `127.0.0.1` — this
    // test harness's IP-literal addressing again (see login_flow.rs's
    // module docs). Cookies are relayed by hand instead.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let mut cookies: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let cookie_header = |cookies: &std::collections::HashMap<String, String>| {
        cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    };
    let absorb = |cookies: &mut std::collections::HashMap<String, String>,
                  resp: &reqwest::Response| {
        for value in resp.headers().get_all("set-cookie") {
            let value = value.to_str().unwrap();
            let pair = value.split(';').next().unwrap();
            if let Some((name, val)) = pair.split_once('=') {
                cookies.insert(name.trim().to_string(), val.trim().to_string());
            }
        }
    };
    let caddy_base = format!("http://127.0.0.1:{caddy_port}");

    // 1. Unauthenticated request to the app, through Caddy, is denied and
    //    redirected to /login with rd pointing back at the original URL —
    //    query string included, `&` and all, since forward-auth builds the
    //    login URL itself (X-Login-Url) rather than Caddy splicing {uri}
    //    raw into a query parameter.
    let resp = client
        .get(format!("{caddy_base}/dashboard?a=1&b=2"))
        .header("host", "app.test.local")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FOUND,
        "forward_auth + handle_response should redirect a denied request"
    );
    let login_location = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        login_location.starts_with("https://auth.test.local/login?rd="),
        "unexpected redirect target: {login_location}"
    );
    let rd = url::Url::parse(&login_location)
        .unwrap()
        .query_pairs()
        .find(|(k, _)| k == "rd")
        .map(|(_, v)| v.to_string())
        .unwrap();
    assert_eq!(
        rd, "http://app.test.local/dashboard?a=1&b=2",
        "rd should be the full original URL, query string intact"
    );

    // 2. Follow through /login -> mock IdP -> /callback, all reached
    //    through Caddy's auth.test.local vhost (proving that route works
    //    too, not just /verify).
    let login_path = url::Url::parse(&login_location).unwrap();
    let resp = client
        .get(format!(
            "{caddy_base}{}?{}",
            login_path.path(),
            login_path.query().unwrap()
        ))
        .header("host", "auth.test.local")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SEE_OTHER,
        "/login (via Caddy) should redirect to the IdP"
    );
    absorb(&mut cookies, &resp);
    let authorize_url = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let idp_resp = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .get(&authorize_url)
        .send()
        .await
        .unwrap();
    assert_eq!(idp_resp.status(), reqwest::StatusCode::SEE_OTHER);
    let callback_location = idp_resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let callback_url = url::Url::parse(&callback_location).unwrap();

    let resp = client
        .get(format!(
            "{caddy_base}{}?{}",
            callback_url.path(),
            callback_url.query().unwrap()
        ))
        .header("host", "auth.test.local")
        .header("cookie", cookie_header(&cookies))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::SEE_OTHER,
        "/callback (via Caddy) should redirect to rd"
    );
    absorb(&mut cookies, &resp);
    let final_location = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(
        final_location, rd,
        "callback should redirect to the exact rd captured at the first denial"
    );

    // 3. Now authenticated (cookie relayed by hand above): the original
    //    path succeeds through Caddy, reaching the real backend, with the
    //    verified identity forwarded via copy_headers.
    let final_path = url::Url::parse(&final_location).unwrap();
    let resp = client
        .get(format!(
            "{caddy_base}{}?{}",
            final_path.path(),
            final_path.query().unwrap()
        ))
        .header("host", "app.test.local")
        .header("cookie", cookie_header(&cookies))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("x-auth-user=alice"),
        "expected the backend to see the forwarded identity header, got: {body}"
    );
    assert!(body.contains("path=/dashboard"));
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        1,
        "the backend should have been reached exactly once, only after authentication succeeded"
    );

    let _ = caddy.kill();
    let _ = caddy.wait();
    let _ = std::fs::remove_file(&caddyfile_path);
}
