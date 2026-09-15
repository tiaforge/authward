//! Logo and favicon assets. Embedded at compile time (`include_str!`, same
//! idiom `db.rs` uses for migrations) so the binary doesn't depend on
//! `assets/` existing next to it wherever it's deployed.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

fn svg(body: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HeaderValue::from_static("image/svg+xml")),
            (
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ),
        ],
        body,
    )
        .into_response()
}

/// Same shape and colors as `authward-mark-light.svg`, but with a viewBox
/// cropped tightly to the shield instead of that file's full 160x175
/// canvas — a browser scales the whole viewBox down to a ~16px tab icon,
/// so the wide margin there left the shield looking tiny. The `-light`
/// mark (darker shield) reads better as the default favicon since most
/// browser chrome/tab backgrounds are light.
const FAVICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="44 38 72 97">
  <path d="M80 46 L108 56 L108 86 Q108 112 80 127 Q52 112 52 86 L52 56 Z" fill="#64748b"/>
  <path d="M64 86 L92 86 M82 76 L96 86 L82 96" fill="none" stroke="#ffffff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
</svg>"##;

pub async fn favicon() -> impl IntoResponse {
    svg(FAVICON_SVG)
}

pub async fn mark_dark() -> impl IntoResponse {
    svg(include_str!("../../assets/brand/authward-mark-dark.svg"))
}

pub async fn mark_light() -> impl IntoResponse {
    svg(include_str!("../../assets/brand/authward-mark-light.svg"))
}

pub async fn wordmark_dark() -> impl IntoResponse {
    svg(include_str!("../../assets/brand/authward-wordmark-dark.svg"))
}

pub async fn wordmark_light() -> impl IntoResponse {
    svg(include_str!("../../assets/brand/authward-wordmark-light.svg"))
}
