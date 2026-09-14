use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use crate::routes;
use crate::state::AppState;
use crate::templates::ErrorPage;

/// The base router. `/healthz` is unauthenticated by design — it's meant to
/// live on the auth subdomain, which Caddy never routes through
/// `forward_auth`, so it needs no bypass-path config entry (see the plan's
/// locked-in decisions).
pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/", get(routes::overview))
        .route("/login", get(routes::login))
        .route("/token", get(routes::token))
        .route("/callback", get(routes::callback))
        .route("/verify", get(routes::verify))
        .route("/sessions/revoke", post(routes::revoke_session))
        .route("/logout", post(routes::logout))
        .route("/logged-out", get(routes::logged_out))
        .fallback(not_found)
        .layer(axum::middleware::from_fn(security_headers))
        .with_state(state)
}

/// Blanket response hardening. Nothing here is ever meant to be framed
/// (the token page shows a live credential; the dashboard names sessions),
/// and nothing is cacheable — `/verify` answers go to Caddy, everything
/// else is per-user HTML. A route that sets its own `Cache-Control` wins.
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("frame-ancestors 'none'"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    // `same-origin`, not `no-referrer`: the Fetch standard makes a browser
    // send `Origin: null` on a non-GET form navigation from a page whose
    // referrer policy is `no-referrer`, so the dashboard's own Log out /
    // revoke buttons would trip `same_origin_denial`'s CSRF check. With
    // `same-origin` the Origin is real for same-origin POSTs and `null`
    // only for cross-origin ones (which the guard refuses), while the
    // Referer still never leaves this origin.
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("same-origin"),
    );
    headers
        .entry(header::CACHE_CONTROL)
        .or_insert(HeaderValue::from_static("no-store"));
    response
}

async fn healthz() -> &'static str {
    "ok"
}

async fn not_found() -> impl IntoResponse {
    (
        StatusCode::NOT_FOUND,
        ErrorPage {
            title: "Not found",
            message: "The requested page does not exist.",
        },
    )
}
