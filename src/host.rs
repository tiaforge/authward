//! Host resolution: `X-Forwarded-Host` (fallback `Host`), lowercased once at
//! ingress and used consistently for every downstream lookup (config,
//! cookie `Domain`, resource/`aud` matching) — per the plan's locked-in
//! multi-provider decision.

use axum::http::HeaderMap;

pub fn resolve_incoming_host(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get("host"))?
        .to_str()
        .ok()?;
    // Strip a port, if present, before lowercasing.
    let host = raw.split(':').next().unwrap_or(raw);
    Some(host.to_ascii_lowercase())
}

/// Whether cookies set for this request should carry the `Secure` flag.
/// Derived from `X-Forwarded-Proto` (set by Caddy) rather than hardcoded,
/// so a plain-http local/dev deployment behind a proxy that says so
/// doesn't end up with cookies the browser silently refuses to send back.
/// Defaults to secure when the header is absent or anything other than
/// exactly "http" — fail safe, not fail open.
pub fn cookies_should_be_secure(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .map(|v| !v.eq_ignore_ascii_case("http"))
        .unwrap_or(true)
}
