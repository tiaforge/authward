use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
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
        .fallback(not_found)
        .with_state(state)
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
