use axum::Router;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;

use crate::templates::ErrorPage;

/// The base router. `/healthz` is unauthenticated by design — it's meant to
/// live on the auth subdomain, which Caddy never routes through
/// `forward_auth`, so it needs no bypass-path config entry (see the plan's
/// locked-in decisions).
pub fn build_router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .fallback(not_found)
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
