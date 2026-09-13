//! HTML templates. Every HTML-rendering route in this service goes through
//! Askama (auto-escaping by construction) — no hand-built HTML strings, so
//! attacker- or user-influenced content (hostnames, claim values, UA
//! strings shown on the dashboard in later phases) can't get interpreted as
//! markup. See the plan's security-review pass re: Authelia CVE-2026-33525.

use askama::Template;
use askama_web::WebTemplate;

/// Generic plain error/info page, reused for every "here's what happened"
/// response (IdP unreachable, not authorized, session expired, logged out,
/// 404, ...) rather than growing a template per case.
#[derive(Template, WebTemplate)]
#[template(path = "error.html")]
pub struct ErrorPage<'a> {
    pub title: &'a str,
    pub message: &'a str,
}

/// `/token` helper's one-time confirmation page (Phase 5). Shown once,
/// never persisted server-side — the access token only ever exists in
/// this HTTP response and the operator's clipboard.
#[derive(Template, WebTemplate)]
#[template(path = "token.html")]
pub struct TokenPage<'a> {
    pub resource: &'a str,
    pub access_token: &'a str,
}

/// One row in the dashboard's session list (Phase 6).
pub struct SessionRow {
    pub id: String,
    pub created_at: String,
    pub user_agent: String,
    pub is_current: bool,
}

/// The `/` overview page (Phase 6): who's logged in, their other active
/// sessions on this base domain, and links to request an API token for
/// any host that has one configured.
#[derive(Template, WebTemplate)]
#[template(path = "dashboard.html")]
pub struct DashboardPage<'a> {
    pub subject: &'a str,
    pub email: Option<&'a str>,
    pub sessions: Vec<SessionRow>,
    pub token_hosts: Vec<&'a str>,
}
