//! End-to-end test of `/verify` HTTP caching (`verify_cache_max_age`)
//! behind a real caching proxy: nginx `auth_request` + `proxy_cache`,
//! configured the way docs/deployment.md documents. Confirms what the
//! header-level tests in `login_flow.rs` can't: that a cached `/verify`
//! answer is never served for a different user, a different protected
//! app, a different API token, or a different path — while the cache is
//! demonstrably serving hits, so the test can't pass by caching nothing.
//!
//! Runs nginx natively if `NGINX_BIN` is set, otherwise in a rootless
//! container via `podman` (image overridable with `NGINX_IMAGE`). Skips
//! (prints a message, does not fail) if neither is available.

use std::collections::HashMap;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
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

const CLIENT_ID: &str = "authward-test-client";
const CLIENT_SECRET: &str = "nginx-cache-integration-test-secret";
const API_RESOURCE: &str = "https://api.test.local/";
const DEFAULT_IMAGE: &str = "docker.io/library/nginx:stable-alpine";

/// The cache key docs/deployment.md tells nginx users to set. This test
/// exists to prove it's sufficient; keep the two in sync.
const DOCUMENTED_CACHE_KEY: &str =
    "$host|$request_method|$request_uri|$http_cookie|$http_x_auth_token|$http_authorization";
/// nginx's own default `proxy_cache_key`, for someone who never set one.
/// It names authward's address rather than the app's host, so isolation
/// between apps then rests entirely on authward's `Vary` (incl. `Host`).
const NGINX_DEFAULT_CACHE_KEY: &str = "$scheme$proxy_host$request_uri";

async fn free_port() -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap().port()
}

// ---- nginx launcher: native binary or rootless podman -----------------

enum Nginx {
    Native(String),
    Podman(String),
}

impl Nginx {
    fn detect() -> Option<Self> {
        if let Ok(bin) = std::env::var("NGINX_BIN") {
            return Some(Nginx::Native(bin));
        }
        let podman_ok = Command::new("podman")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|s| s.success());
        podman_ok.then(|| {
            Nginx::Podman(std::env::var("NGINX_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.into()))
        })
    }

    /// Starts nginx with `dir/nginx.conf`. Everything nginx writes goes
    /// under `dir`, which the container sees at the same path.
    fn start(&self, dir: &Path, port: u16) -> Running {
        let container = format!("authward-nginx-test-{port}");
        let conf = dir.join("nginx.conf");
        let mut cmd = match self {
            Nginx::Native(bin) => {
                let mut cmd = Command::new(bin);
                cmd.arg("-p").arg(dir).arg("-c").arg(&conf);
                cmd
            }
            Nginx::Podman(image) => {
                let mut cmd = Command::new("podman");
                let mount = format!("{0}:{0}", dir.display());
                cmd.args(["run", "--rm", "--name", &container, "--network", "host"])
                    .args(["-v", &mount, image])
                    .args(["nginx", "-c"])
                    .arg(&conf);
                cmd
            }
        };
        let child = cmd
            .args(["-g", "daemon off;"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to start nginx");
        Running {
            child,
            container: matches!(self, Nginx::Podman(_)).then_some(container),
        }
    }
}

/// Stops nginx when dropped — including when an assertion fails, so a
/// failed run doesn't leave a container behind. Killing the `podman run`
/// client alone doesn't stop the container.
struct Running {
    child: Child,
    container: Option<String>,
}

impl Drop for Running {
    fn drop(&mut self) {
        if let Some(container) = &self.container {
            let _ = Command::new("podman")
                .args(["rm", "-f", "-t", "0", container])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// nginx in front of authward (`/_auth` → `/verify`) and the backend,
/// caching `/verify` answers under `cache_key`. The cache status of each
/// request's auth subrequest is exposed to the test as `X-Auth-Cache`.
fn nginx_conf(dir: &Path, port: u16, auth_port: u16, backend_port: u16, cache_key: &str) -> String {
    let dir = dir.display();
    format!(
        r#"
user root;
worker_processes 1;
pid {dir}/nginx.pid;
error_log {dir}/error.log info;
events {{ worker_connections 64; }}
http {{
    access_log off;
    client_body_temp_path {dir}/client_body;
    proxy_temp_path {dir}/proxy_temp;
    fastcgi_temp_path {dir}/fastcgi_temp;
    uwsgi_temp_path {dir}/uwsgi_temp;
    scgi_temp_path {dir}/scgi_temp;
    proxy_cache_path {dir}/cache keys_zone=authward:1m;

    server {{
        listen 127.0.0.1:{port};

        location / {{
            auth_request /_auth;
            auth_request_set $auth_user $upstream_http_x_auth_user;
            auth_request_set $auth_cache $upstream_cache_status;
            add_header X-Auth-Cache $auth_cache always;
            proxy_set_header X-Auth-User $auth_user;
            proxy_pass http://127.0.0.1:{backend_port};
        }}

        location = /_auth {{
            internal;
            proxy_pass http://127.0.0.1:{auth_port}/verify;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Uri $request_uri;
            proxy_set_header X-Forwarded-Method $request_method;
            proxy_cache authward;
            proxy_cache_key "{cache_key}";
        }}
    }}
}}
"#
    )
}

// ---- Mock IdP: login_hint picks the subject, `groups` the group claim --

/// code -> (subject, groups, nonce)
type PendingCodes = HashMap<String, (String, String, String)>;

#[derive(Clone, Default)]
struct MockIdpState {
    base_url: Arc<std::sync::OnceLock<String>>,
    pending: Arc<std::sync::Mutex<PendingCodes>>,
}

#[derive(Deserialize)]
struct AuthorizeParams {
    redirect_uri: String,
    state: String,
    nonce: String,
    login_hint: String,
    #[serde(default)]
    groups: String,
}

fn sign_jwt(hmac_key: &CoreHmacKey, payload: &serde_json::Value) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let signing_input = format!(
        "{}.{}",
        b64.encode(br#"{"alg":"HS256"}"#),
        b64.encode(serde_json::to_vec(payload).unwrap())
    );
    let sig = hmac_key
        .sign(
            &CoreJwsSigningAlgorithm::HmacSha256,
            signing_input.as_bytes(),
        )
        .unwrap();
    format!("{signing_input}.{}", b64.encode(sig))
}

async fn spawn_mock_idp(hmac_key: Arc<CoreHmacKey>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let idp = MockIdpState::default();
    idp.base_url.set(base_url.clone()).unwrap();

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
                let code = authward::crypto::random_hex(16);
                idp.pending.lock().unwrap().insert(
                    code.clone(),
                    (params.login_hint, params.groups, params.nonce),
                );
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
        move |body: axum::body::Bytes| {
            let idp = idp.clone();
            let hmac_key = hmac_key.clone();
            async move {
                let code = url::form_urlencoded::parse(&body)
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.into_owned())
                    .unwrap();
                let (subject, groups, nonce) = idp.pending.lock().unwrap().remove(&code).unwrap();
                let groups: Vec<&str> = groups.split(',').filter(|g| !g.is_empty()).collect();
                let now = Utc::now();
                let id_token = sign_jwt(
                    &hmac_key,
                    &json!({
                        "iss": idp.base_url.get().unwrap(),
                        "aud": [CLIENT_ID],
                        "sub": subject,
                        "groups": groups,
                        "iat": now.timestamp(),
                        "exp": now.timestamp() + 3600,
                        "nonce": nonce,
                    }),
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

/// A resource-scoped access token for `API_RESOURCE`, as the IdP would
/// issue it to a non-browser client.
fn api_token(hmac_key: &CoreHmacKey, issuer: &str, subject: &str) -> String {
    let now = Utc::now();
    sign_jwt(
        hmac_key,
        &json!({
            "iss": issuer,
            "aud": API_RESOURCE,
            "sub": subject,
            "iat": now.timestamp(),
            "exp": now.timestamp() + 3600,
        }),
    )
}

// ---- Backend app: echoes the identity nginx forwarded -----------------

async fn spawn_backend_app() -> u16 {
    let handler = |headers: axum::http::HeaderMap| async move {
        let user = headers
            .get("x-auth-user")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        format!("user={user}")
    };
    let app = Router::new().fallback(get(handler));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    port
}

// ---- authward ----------------------------------------------------------

fn host(name: &str) -> authward::config::ResolvedHost {
    authward::config::ResolvedHost {
        host: Some(name.to_string()),
        base_domain: "test.local".to_string(),
        provider_key: "default".to_string(),
        required_group: None,
        group_claim_name: "groups".to_string(),
        bypass_paths: Vec::new(),
        path_required_groups: Vec::new(),
        forward_identity_headers: true,
        resource: None,
        required_scope: None,
        token_header: "x-auth-token".to_string(),
    }
}

async fn spawn_authward(idp_base_url: &str, db_dir: &Path) -> u16 {
    let mut idps = HashMap::new();
    idps.insert(
        "default".to_string(),
        authward::config::Idp {
            discovery_url: url::Url::parse(&format!(
                "{idp_base_url}/.well-known/openid-configuration"
            ))
            .unwrap(),
            client_id: CLIENT_ID.to_string(),
            client_secret: CLIENT_SECRET.to_string(),
        },
    );
    let mut base_domains = HashMap::new();
    base_domains.insert(
        "test.local".to_string(),
        authward::config::BaseDomain {
            name: "test.local".to_string(),
            auth_subdomain: "auth.test.local".to_string(),
            callback_url: url::Url::parse("https://auth.test.local/callback").unwrap(),
            idp: "default".to_string(),
            fallback: None,
        },
    );

    let mut hosts = HashMap::new();
    // Any login passes; one bypassed path.
    let mut app = host("app.test.local");
    app.bypass_paths = vec![authward::bypass::BypassEntry::unrestricted("/public")];
    hosts.insert("app.test.local".to_string(), app);
    // Same base domain (so the same cookie), but requires `admins`.
    let mut admin = host("admin.test.local");
    admin.required_group = Some("admins".to_string());
    hosts.insert("admin.test.local".to_string(), admin);
    // API tokens in the default header, and in `Authorization`.
    let mut api = host("api.test.local");
    api.resource = Some(API_RESOURCE.to_string());
    hosts.insert("api.test.local".to_string(), api);
    let mut api_authz = host("api2.test.local");
    api_authz.resource = Some(API_RESOURCE.to_string());
    api_authz.token_header = "authorization".to_string();
    hosts.insert("api2.test.local".to_string(), api_authz);

    let cfg = authward::config::Config {
        global: authward::config::Global {
            cookie_signing_key: "nginx-test-cookie-signing-key-32-bytes!!".to_string(),
            refresh_token_encryption_key: "nginx-test-refresh-key-32-bytes-minimum!".to_string(),
            sqlite_path: db_dir.join("sessions.db"),
            session_ttl_fallback: Duration::from_secs(3600),
            session_max_age: Duration::from_secs(24 * 3600),
            verify_cache_max_age: Duration::from_secs(60),
            bind_session_to_client_ip: true,
            otel_endpoint: None,
            listen_addr: "127.0.0.1:0".parse().unwrap(),
        },
        idps,
        base_domains,
        hosts,
    };
    let state = authward::build_state(cfg)
        .await
        .expect("build_state against mock IdP");
    let router = authward::server::build_router(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    port
}

/// Logs `user` in directly against authward (not through nginx — only
/// `/verify` is under test) and returns the `Cookie` header value a
/// browser would then send to every app under the domain.
async fn login(auth_port: u16, user: &str, groups: &str) -> String {
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let auth = format!("http://127.0.0.1:{auth_port}");
    let set_cookies = |resp: &reqwest::Response| -> Vec<String> {
        resp.headers()
            .get_all("set-cookie")
            .iter()
            .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_string())
            .collect()
    };

    let resp = client
        .get(format!("{auth}/login?rd=https://app.test.local/"))
        .header("host", "auth.test.local")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    let flow_cookie = set_cookies(&resp).join("; ");
    let mut authorize = url::Url::parse(resp.headers()["location"].to_str().unwrap()).unwrap();
    authorize
        .query_pairs_mut()
        .append_pair("login_hint", user)
        .append_pair("groups", groups);

    let resp = client.get(authorize).send().await.unwrap();
    let callback = url::Url::parse(resp.headers()["location"].to_str().unwrap()).unwrap();

    let resp = client
        .get(format!("{auth}/callback?{}", callback.query().unwrap()))
        .header("host", "auth.test.local")
        .header("cookie", flow_cookie)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::SEE_OTHER);
    let session = set_cookies(&resp)
        .into_iter()
        .find(|c| c.starts_with("authward_session="))
        .expect("callback should set the session cookie");
    // Another app's cookie alongside, as a real browser would send.
    format!("{session}; theme=dark")
}

// ---- The test -----------------------------------------------------------

struct Answer {
    status: u16,
    body: String,
    cache: String,
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {:?} (auth cache: {})",
            self.status, self.body, self.cache
        )
    }
}

struct Proxy {
    base: String,
    client: reqwest::Client,
}

impl Proxy {
    async fn get(&self, host: &str, path: &str, headers: &[(&str, &str)]) -> Answer {
        let mut req = self
            .client
            .get(format!("{}{path}", self.base))
            .header("host", host);
        for (name, value) in headers {
            req = req.header(*name, *value);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        let cache = resp
            .headers()
            .get("x-auth-cache")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body = resp.text().await.unwrap();
        Answer {
            status,
            body: if status == 200 { body } else { String::new() },
            cache,
        }
    }
}

#[tokio::test]
async fn cached_verify_answers_never_cross_users_apps_tokens_or_paths() {
    let Some(nginx) = Nginx::detect() else {
        eprintln!(
            "skipping cached_verify_answers_never_cross_users_apps_tokens_or_paths: \
             no nginx (set NGINX_BIN) and no podman"
        );
        return;
    };

    let hmac_key = Arc::new(CoreHmacKey::new(CLIENT_SECRET.as_bytes().to_vec()));
    let idp_base_url = spawn_mock_idp(hmac_key.clone()).await;
    let backend_port = spawn_backend_app().await;
    let db_dir = tempfile::tempdir().unwrap();
    let auth_port = spawn_authward(&idp_base_url, db_dir.path()).await;

    for cache_key in [DOCUMENTED_CACHE_KEY, NGINX_DEFAULT_CACHE_KEY] {
        eprintln!("checking with proxy_cache_key {cache_key}");
        check_isolation(
            &nginx,
            cache_key,
            auth_port,
            backend_port,
            &hmac_key,
            &idp_base_url,
        )
        .await;
    }
}

/// The whole scenario against a fresh nginx (and so a fresh cache) that
/// caches `/verify` under `cache_key`.
async fn check_isolation(
    nginx: &Nginx,
    cache_key: &str,
    auth_port: u16,
    backend_port: u16,
    hmac_key: &CoreHmacKey,
    idp_base_url: &str,
) {
    let nginx_dir = tempfile::tempdir().unwrap();
    let nginx_port = free_port().await;
    std::fs::write(
        nginx_dir.path().join("nginx.conf"),
        nginx_conf(
            nginx_dir.path(),
            nginx_port,
            auth_port,
            backend_port,
            cache_key,
        ),
    )
    .unwrap();
    let mut nginx = nginx.start(nginx_dir.path(), nginx_port);

    let proxy = Proxy {
        base: format!("http://127.0.0.1:{nginx_port}"),
        client: reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    };
    // Wait for nginx (a container may take a few seconds to come up).
    let mut ready = false;
    for _ in 0..100 {
        if proxy.client.get(&proxy.base).send().await.is_ok() {
            ready = true;
            break;
        }
        if let Ok(Some(status)) = nginx.child.try_wait() {
            let mut stderr = String::new();
            use std::io::Read;
            nginx
                .child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .ok();
            panic!("nginx exited early ({status}): {stderr}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ready, "nginx did not start listening");

    let alice = login(auth_port, "alice", "admins").await;
    let bob = login(auth_port, "bob", "users").await;
    let alice_h = [("cookie", alice.as_str())];
    let bob_h = [("cookie", bob.as_str())];

    // 1. The cache really caches: alice's second identical request is a
    //    hit, and still alice.
    let a = proxy.get("app.test.local", "/page", &alice_h).await;
    assert_eq!((a.status, a.body.as_str()), (200, "user=alice"), "{a:?}");
    assert_eq!(a.cache, "MISS", "{a:?}");
    let a = proxy.get("app.test.local", "/page", &alice_h).await;
    assert_eq!((a.status, a.body.as_str()), (200, "user=alice"), "{a:?}");
    assert_eq!(a.cache, "HIT", "the cache must actually serve hits: {a:?}");

    // 2. Another user, same app and path: never alice's answer.
    let b = proxy.get("app.test.local", "/page", &bob_h).await;
    assert_eq!((b.status, b.body.as_str()), (200, "user=bob"), "{b:?}");
    assert_eq!(b.cache, "MISS", "{b:?}");

    // 3. No session: not alice's answer, and a 401 is never cached.
    for _ in 0..2 {
        let anon = proxy.get("app.test.local", "/page", &[]).await;
        assert_eq!(anon.status, 401, "unauthenticated must be denied: {anon:?}");
        assert_ne!(anon.cache, "HIT", "a 401 must never be cached: {anon:?}");
    }

    // 4. Another app, same cookie and path: alice (admin) is let in and
    //    that answer gets cached; bob — whose cookie is equally valid on
    //    this base domain, and who has a cached 200 for the same path on
    //    app.test.local — is not, and his 403 is never cached.
    let a = proxy.get("admin.test.local", "/page", &alice_h).await;
    assert_eq!((a.status, a.body.as_str()), (200, "user=alice"), "{a:?}");
    let a = proxy.get("admin.test.local", "/page", &alice_h).await;
    assert_eq!(a.cache, "HIT", "{a:?}");
    for _ in 0..2 {
        let b = proxy.get("admin.test.local", "/page", &bob_h).await;
        assert_eq!(b.status, 403, "{b:?}");
        assert_ne!(b.cache, "HIT", "a 403 must never be cached: {b:?}");
    }
    // A spoofed X-Forwarded-Host from the client changes nothing.
    let b = proxy
        .get(
            "admin.test.local",
            "/page",
            &[
                ("cookie", bob.as_str()),
                ("x-forwarded-host", "app.test.local"),
            ],
        )
        .await;
    assert_eq!(b.status, 403, "{b:?}");

    // 5. Bypassed path vs protected path on the same host: a cached
    //    anonymous 200 for /public must not open /page.
    let p = proxy.get("app.test.local", "/public", &[]).await;
    assert_eq!((p.status, p.body.as_str()), (200, "user="), "{p:?}");
    let p = proxy.get("app.test.local", "/public", &[]).await;
    assert_eq!(p.cache, "HIT", "{p:?}");
    let anon = proxy.get("app.test.local", "/page", &[]).await;
    assert_eq!(anon.status, 401, "{anon:?}");

    // 6. API tokens, in both a custom header and `Authorization`: each
    //    token gets its own answer, and a cached one never covers a bad
    //    or missing token.
    let t1 = api_token(hmac_key, idp_base_url, "svc-one");
    let t2 = api_token(hmac_key, idp_base_url, "svc-two");
    for (api_host, header, prefix) in [
        ("api.test.local", "x-auth-token", ""),
        ("api2.test.local", "authorization", "Bearer "),
    ] {
        let v1 = format!("{prefix}{t1}");
        let v2 = format!("{prefix}{t2}");
        let bad = format!("{prefix}not-a-token");
        let r = proxy.get(api_host, "/data", &[(header, &v1)]).await;
        assert_eq!(
            (r.status, r.body.as_str()),
            (200, "user=svc-one"),
            "{api_host}: {r:?}"
        );
        let r = proxy.get(api_host, "/data", &[(header, &v1)]).await;
        assert_eq!(
            (r.cache.as_str(), r.body.as_str()),
            ("HIT", "user=svc-one"),
            "{api_host}: {r:?}"
        );
        let r = proxy.get(api_host, "/data", &[(header, &v2)]).await;
        assert_eq!(
            (r.status, r.body.as_str()),
            (200, "user=svc-two"),
            "{api_host}: {r:?}"
        );
        let r = proxy.get(api_host, "/data", &[(header, &bad)]).await;
        assert_eq!(r.status, 401, "{api_host}: bad token must be denied: {r:?}");
        let r = proxy.get(api_host, "/data", &[]).await;
        assert_eq!(
            r.status, 401,
            "{api_host}: missing token must be denied: {r:?}"
        );
    }
}
