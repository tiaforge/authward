# Forward-Auth Service — Implementation Plan

Rust + Axum forward-auth service providing OIDC login for apps behind Caddy that don't support OIDC natively.

**Explicit design goal: config ergonomics for the common case.** The concrete reason to build this instead of reaching for Authelia is not just architecture — it's that a narrower-scope tool can and should be genuinely easy to configure for "one OIDC provider, a few subdomains," where Authelia's all-things-to-everyone YAML schema makes it easy to not know which fields actually matter for your setup. This shapes Phase 0 directly: fail-fast validation with specific field-level errors, a minimal worked example shipped in the repo, and config inheritance so a host only states what differs from its base domain's defaults.

## Locked-in decisions

- **Session model:** Hybrid. Opaque session ID in an encrypted, signed cookie. Refresh tokens live server-side in SQLite, keyed by session ID, encrypted at rest with a dedicated key (separate from the cookie-signing key, for defense-in-depth).
- **Session lifetime:** Mirrors OIDC token lifetime; silent refresh via the stored refresh token.
- **Refresh concurrency:** Row-level lock around refresh per session to avoid thundering-herd / refresh-token-rotation races with strict IdPs.
- **On refresh failure:** Silently clear session, redirect to login. No error surfaced.
- **Auth subdomain:** One dedicated `auth.<base-domain>` per base domain hosts `/login`, `/callback`, `/logout`, `/healthz` directly — no reserved path on protected apps, no collision risk with real app routes. One logical auth subdomain per base domain (config-routed, can still be one binary/one config file). Session cookie is set from the auth subdomain with `Domain=.<base-domain>` so any app on that base domain can read it.
- **Redirect flow:** On auth failure, app's `forward_auth` redirects the browser to `https://auth.<base-domain>/login?rd=<original-url>`. `/callback` redirects back to that captured URL after a successful login.
- **Open redirect protection:** `rd` (and any post-callback redirect target) must be validated — only allow targets whose host is within the same base domain (or an explicit allowlist).
- **Cookie domain:** Per base domain (`Domain=.example.com`), giving SSO across apps on the same domain. Apps on different base domains get separate logins/sessions — accepted.
- **Multi-provider:** Per-host config keyed by `X-Forwarded-Host` (fallback to `Host`), lowercased once at ingress and used consistently for every downstream lookup (config, cookie `Domain`, resource/`aud` matching).
- **Persistence:** SQLite (`rusqlite` or `sqlx`) for the refresh-token store. Single instance, no HA requirement.
- **Group authorization:** Group membership only (no arbitrary claim matching). Claim name configurable per-host, default `groups`. No config on a host = no check, any valid login passes.
- **Bypass paths:** Declared per-host in config (public assets, webhooks). Exact-match only against the normalized path (percent-decoded, query string stripped, no prefix/wildcard/regex matching) — closes the class of bug where an unanchored match let an attacker append an allowed path to bypass auth on an unrelated route. `/healthz` lives on the auth subdomain, which isn't behind `forward_auth`, so it needs no bypass entry.
- **Failure modes:** IdP unreachable at login → plain error page. Malformed or missing per-host config with no fallback match → log error, fail hard (502).
- **Proxy:** Caddy `forward_auth` first; design headers/response codes so nginx/Traefik support is addable later without a rewrite.

### Added in refinement pass (post-comparison review)

- **API token bypass (non-browser clients):** No custom token store. `/verify` checks the session cookie first; if absent, falls back to validating an `Authorization: Bearer <token>` as a resource-scoped OAuth access token issued directly by the IdP (RFC 8707 "Resource Indicators" — the `resource` parameter on the authorization/token request, supported by pocket-id's "APIs" feature and equivalent mechanisms in Keycloak/Auth0/Okta). Validation is local and stateless: check JWT signature against the IdP's published JWKS (cached, refreshed periodically), confirm `iss` matches the configured provider, confirm `aud` contains the resource identifier configured for that host, check expiry, check the required permission/scope claim if configured. Per-host config gains: `resource` identifier, optional `required_scope`. If a host's configured IdP doesn't support resource-scoped tokens, this bypass is simply unavailable for that host (fails to session-cookie-only, not a hard error). Token issuance and revocation are entirely the IdP's responsibility — nothing to build or store on our side. Revocation is coarse (disable the client or its API permission in the IdP), not per-token, which is an accepted tradeoff for the simplicity gained.
- **Token acquisition helper:** Since pocket-id (and equivalent IdPs) issue resource-scoped tokens only through an OIDC client performing the flow — there's no built-in end-user "generate key" button — our own service acts as that client. A thin `/token` endpoint on the auth subdomain: user authenticates normally (passkey via the IdP), our service performs the authorization-code+PKCE exchange with `resource=<host's resource>` on their behalf, and displays the resulting access token once on a plain confirmation page for the user to copy. No server-side storage of the issued token — it's shown and forgotten, same trust boundary as pocket-id's own consent flow. Gives non-browser-client users a way to get a token without needing their own OIDC-capable CLI tooling.
- **Overview page (`/`):** The auth subdomain's root path becomes a simple dashboard — not a public landing page. Requires login (redirects to `/login` like any protected route). Shows: who's logged in, a list of active sessions (from the SQLite session table) with per-session "log out this device," and a link into `/token` to get a token for a given host's resource. No token-revocation link to the IdP: there's no standard OIDC discovery field for a client-management URL, each IdP's admin console differs, and revoking a client's API permission is typically an admin-only action that affects every user of that client at once — not something to surface as a self-service link for an individual user. If a user needs a token revoked, that's an out-of-band admin conversation, not a UI element. This keeps the "invisible" design intact — a user only ever sees this page if they deliberately navigate to `auth.<base-domain>/`.
- **Identity header passthrough:** Per-host config flag (default off) to forward verified identity as `X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups` to the backend app. When enabled, the proxy strips any client-supplied `X-Auth-*` headers on the incoming request before setting its own. Relies on the network-isolation trust boundary below — the same requirement now also covers `X-Forwarded-Host`.
- **Optional-auth / public routes:** Deferred. Not needed for launch; see Deferred section.
- **Non-GET request body loss on session expiry:** Accepted behavior. Show a plain error page ("session expired, please resubmit") rather than buffering/replaying the request body.
- **Login rate limiting:** Per-IP rate limit (token-bucket) on `/login` and `/callback`. No per-account lockout, so it can't be weaponized into a targeted denial-of-service against a specific user. Exact threshold tuned during Phase 8.
- **Secrets handling:** Cookie-signing key and SQLite encryption key can come from either the config file (default, 0600 perms enforced/checked at startup) or environment variables (override). Env var takes precedence if both are set. Service refuses to boot if config-file key material is world/group-readable.
- **Clock skew leeway:** ±60 seconds applied to `exp`/`iat`/`nbf` validation on ID tokens.
- **Observability:** Structured audit log (login success/failure, token refresh, rate-limit triggers) as JSON to stdout, plus OpenTelemetry log export. Metrics endpoint (Prometheus-style) deferred.

### Added in security review pass (tinyauth CVE comparison)

- **Trust boundary for proxy-supplied headers:** Consolidates the identity-header requirement and extends it to host resolution. The service must be unreachable except through Caddy (internal network/socket only, never exposed directly) — this is the actual defense for both `X-Forwarded-Host` (drives config/cookie/resource lookup) and `X-Auth-*` header forwarding. No in-app shared-secret header check; network isolation is the boundary, documented as a hard deployment requirement in Phase 10.
- **PKCE state isolation (no shared mutable state):** Confirmed by design, not just assumed — tinyauth's CVE-2026-33544 was a race condition from storing PKCE verifiers/tokens as mutable fields on a singleton shared across concurrent requests, letting one user's login flow receive another user's identity. Our design already stores PKCE state in a per-browser flow cookie, never in shared server-side memory, so this bug class doesn't apply structurally. Added as an explicit Phase 1 test anyway: fire two concurrent login flows from different browsers against the same provider, confirm no cross-contamination.
- **Constant-time comparisons:** Any raw secret comparison we perform ourselves (session cookie signature/MAC check) uses a constant-time comparison, not `==`. Standard JWT/cookie-signing libraries already do this internally — call it out explicitly in Phase 11 code review rather than assume.
- **CSRF protection:** `SameSite=Lax` on the session cookie (needed anyway for the cross-site GET redirect-back-after-login flow) plus enforcing POST-only for every state-changing route — `/logout`, session-revoke on the dashboard, and the token-issuance step of `/token`. `SameSite=Lax` blocks cross-site POST from a third-party page; combined with POST-only routing, a GET link can't trigger any of these actions. No separate CSRF token needed. `/verify` and other read-only routes are unaffected since they don't mutate state.
- **Expired session cleanup:** Background reaper task, run on a timer (e.g. every few minutes), deletes SQLite session rows past their expiry. Keeps the table from growing unbounded over the life of the deployment; independent of the per-request refresh/expiry check in `/verify`, which only ever touches the session being used.

### Added in cross-check against Authelia / oauth2-proxy CVEs

- **Group claim re-validation on refresh:** Group membership is checked not just at initial login but on every silent refresh, against the freshly returned token/claims from the IdP — not the originally cached claim set. Closes the class of bug where a user removed from a required group at the IdP retains access for the life of their session (a real issue in Authelia's YAML backend and implicated in oauth2-proxy's id_token-vs-access_token refresh validation CVE). Applies to Phase 2 and Phase 4 together: refresh must feed back into the authorization check, not bypass it.
- **HTML output escaping:** All HTML rendered by the service (dashboard, error pages, `/token` confirmation page, "not authorized" page) goes through an auto-escaping template engine (Askama or Tera), never hand-built strings with interpolated values. Closes the class of bug behind Authelia's CVE-2026-33525 (unescaped input reflected into generated pages) — anything that could contain attacker- or user-influenced content (User-Agent shown in session list, hostnames, claim values) is escaped by default rather than requiring every call site to remember to do it.
- **Conservative path normalization for bypass-path matching:** Rather than trying to mirror Caddy's own path-parsing behavior exactly (which risks a "confusion" bug if the two ever diverge, as in oauth2-proxy's fragment-confusion CVE), normalization is maximally conservative: any path containing a fragment marker, ambiguous/double percent-encoding, or other non-canonical form is rejected outright (falls through to normal auth, never matched as a bypass) rather than an attempt made to interpret it the way Caddy might. A bypass path only matches on a clean, single-decoded, unambiguous literal path.
- **Auth principle, stated explicitly:** No bypass condition may ever depend on a client-controlled signal (User-Agent, custom header, IP-based heuristic beyond the network-isolation boundary). Bypass matching is static per-host config only — closes the class of bug behind oauth2-proxy's health-check/ping-flag bypass CVE.
- **Logout redirect validation:** The same open-redirect validation applied to the login `rd` parameter (Phase 3) also applies to any redirect target involved in the logout flow — no separate, less-validated code path for post-logout redirects.

---

## Phase 0 — Project setup

- Cargo workspace, Axum + Tokio base app
- Config file format decision (TOML recommended) and schema:
  - Global: cookie signing key, refresh-token encryption key (both overridable via env var), SQLite path, session TTL fallback default
  - Per-base-domain: auth subdomain, OIDC provider (discovery URL, client ID/secret)
  - Per-host: which base domain it belongs to, required group claim name + value (optional), bypass paths, identity-header-forwarding flag, fallback flag
  - Global fallback provider block
- Config loading + validation at startup (fail hard on malformed config); refuse to boot if key file permissions are too open
- Validation errors are field-specific and actionable — name the exact host/block and what's missing or inconsistent (e.g. "host `app.example.com`: `base_domain` references `example.com`, but no `[base_domain.example.com]` block exists"), not a generic "invalid config" message
- Per-host config inherits from its base-domain block by default; a host only needs to state fields that differ (provider override, group requirement, bypass paths, etc.) — not repeat the full provider config
- A minimal, complete worked example config ships in the repo (one pocket-id instance, two apps on one base domain) as the copy-and-edit starting point, alongside the full reference in Phase 12's docs
- Interactive CLI wizard (`forward-auth init`): prompts for base domain, IdP discovery URL, and the first app host, writes the resulting TOML file. Runs locally, once, using filesystem access the operator already has — no network exposure, no bootstrapping problem (unlike a web-based setup GUI, which would need to be either unauthenticated network-exposed surface or need its own separate auth story before OIDC itself is configured). Generates the same shape of config as the worked example, just filled in interactively instead of copy-edited by hand.
- Structured logging (`tracing`), JSON output, OpenTelemetry log export
- HTML templating setup: auto-escaping engine (Askama or Tera) wired in from the start — every HTML-rendering route uses it, no hand-built HTML strings anywhere in the codebase
- Basic health endpoint (`/healthz` on the auth subdomain — not behind `forward_auth`, so no bypass config needed)

## Phase 1 — OIDC core (single provider, single base domain)

- OIDC discovery via `openidconnect` crate
- `/login` on the auth subdomain: build authorization URL with PKCE (S256), `state`, `nonce`; stash `rd` alongside state; set short-lived flow cookie; redirect to IdP
- `/callback` on the auth subdomain: validate `state`, exchange code for tokens, validate ID token (issuer, audience, `nonce`, expiry, ±60s clock skew leeway), extract claims
- Session creation: generate opaque session ID, insert row into SQLite (encrypted refresh token, expiry, host, provider), set signed session cookie scoped to `Domain=.<base-domain>`, redirect to the stashed `rd` URL
- `/verify` internal endpoint (called by each app's `forward_auth`): check session cookie → SQLite row → validity → `200` or `401`
- Test: two concurrent login flows from different browsers against the same provider never cross-contaminate identity (confirms PKCE state isolation via per-browser flow cookie, not shared server state)
- Manual end-to-end test against one real IdP (Keycloak/Authentik/Auth0 — whichever you're using for dev)

## Phase 2 — Silent refresh

- On `/verify`, if access/ID token portion is expired but refresh token isn't: acquire row lock, call token endpoint with refresh token, update SQLite row, continue request
- Row-level locking strategy: per-session mutex (in-process, since single instance) guarding the refresh SQL + IdP call together
- On refresh failure (IdP rejects/revokes): delete session row, clear cookie, respond `401` → Caddy sends to login
- Re-run the group-claim check (Phase 4 logic) against the freshly refreshed token on every successful refresh; a user who lost required group membership is denied even mid-session, not just at next login
- Concurrency test: fire concurrent requests against one expiring session, confirm exactly one refresh call hits the IdP
- Background reaper task: periodic sweep (timer-based) deleting expired session rows from SQLite; test it doesn't race with or lock out an in-flight refresh on the same row

## Phase 3 — Multi-host, multi-base-domain config + fallback provider

- Host resolution from `X-Forwarded-Host` (fallback `Host`)
- Look up per-host config; if none found, use fallback provider config (if defined)
- If neither found: log error, `502`
- Confirm cookie domain is derived correctly per base domain across multiple test hosts
- Test: two hosts on the same base domain share SSO; a host on a different base domain gets its own auth subdomain and session
- Test `rd` open-redirect validation: reject any `rd` target whose host isn't within the same base domain

## Phase 4 — Authorization (group claims)

- Per-host optional `required_group` + `group_claim_name` (default `groups`) config
- After successful auth (fresh login or refresh), check claim membership; if present and required group missing → deny (`403` / "not authorized" page, distinct from "not authenticated")
- No config = no check, any valid login passes (default)
- Test against an IdP where you control group membership per test user
- Test: revoking a user's required group membership at the IdP mid-session results in denial on the next refresh, without waiting for full re-login

## Phase 5 — Resource-scoped API token validation (non-browser clients)

- Per-host config: optional `resource` identifier (must match what's configured on the IdP side) + optional `required_scope`
- JWKS fetch + cache per provider (reuse OIDC discovery from Phase 1), background refresh on a timer plus on signature-verification failure (key rotation handling)
- `/verify` fallback: if no valid session cookie, look for `Authorization: Bearer <token>`; if the host has a `resource` configured, validate JWT signature, `iss`, `aud` contains `resource`, expiry, and `required_scope` if set
- If the host has no `resource` configured, or the provider doesn't support resource-scoped tokens: fallback is simply unavailable, falls through to normal `401` → login redirect
- `/token` helper on the auth subdomain: authenticate the user normally (reuses `/login` flow), perform the authorization-code+PKCE exchange with `resource=<host's resource>` added, display the returned access token once on a plain confirmation page (copy-to-clipboard, no persistence) — this is our service acting as the OIDC client so users don't need their own CLI tooling
- Test: token issued for host A's resource is rejected on host B; token missing the required scope is rejected; expired token is rejected; token survives IdP key rotation (JWKS re-fetch path); `/token` helper correctly scopes the request to the selected host's resource

## Phase 6 — Overview page

- `/` on the auth subdomain, behind normal auth (redirects to `/login` if no session)
- Show: logged-in-as (from ID token claims), list of active sessions from the SQLite session table (created_at, host/provider, rough device/UA info if easily available)
- Per-session "log out this device" action → deletes that SQLite row (not necessarily the current session)
- Link to `/token` (Phase 5) to request a token for a given host
- No token-revocation UI or IdP link — revocation is an out-of-band admin action, not something the dashboard surfaces
- Test: logging out a *different* session than the current one correctly invalidates only that one; overview page itself requires auth like any other route
- Test: session-revoke action only accepts POST; a GET request is rejected (CSRF hardening)

## Phase 7 — Identity header passthrough

- Per-host `forward_identity_headers` flag (default off)
- When enabled: strip any client-supplied `X-Auth-*` headers on the inbound request, then set `X-Auth-User`, `X-Auth-Email`, `X-Auth-Groups` from verified claims before forwarding
- Document the hard requirement: backend apps must not be reachable except through the proxy
- Test: spoofed `X-Auth-User` header from the client is stripped and overwritten, not passed through

## Phase 8 — Logout

- `/logout` on the auth subdomain: delete SQLite session row, clear cookie
- Discovery-based check for `end_session_endpoint`; if present, redirect there with `post_logout_redirect_uri`
- Reuse the same `rd`/redirect-target validation logic from Phase 3 for any redirect target involved in logout — no separate, less-strict code path
- Local "logged out" confirmation page as the redirect target
- Test both paths: IdP with RP-initiated logout support, and one without (fallback to local-only)
- Test: `/logout` only accepts POST; a GET request is rejected (CSRF hardening)

## Phase 9 — Bypass paths + edge cases + rate limiting

- Per-host bypass path list, exact-match only against the normalized path (query string and fragment stripped, single-pass percent-decoded, non-canonical/double-encoded forms rejected outright rather than interpreted) — no prefix/wildcard/regex
- Test: a request with an allowed path appended to the query string of a protected route is correctly denied (regression test for the bypass-matching class of bug)
- Test: a path containing a fragment marker, double-encoding, or other ambiguous form never matches a bypass rule — falls through to normal auth instead
- Test: mixed-case `Host`/`X-Forwarded-Host` values resolve to the same lowercased config, cookie domain, and resource match as their lowercase form, including multi-level subdomains
- Bypassed paths skip `/verify` logic entirely, return `200` immediately
- Non-GET request behavior during session expiry: confirm it fails predictably with a plain error page (accepted behavior, just needs testing)
- IdP-unreachable-at-login plain error page
- Malformed/missing config fail-hard path, verified with intentionally broken config
- Per-IP rate limiting on `/login` and `/callback`; test it triggers and recovers correctly, and doesn't lock out legitimate shared-IP users (e.g. NAT) too aggressively

## Phase 10 — Caddy integration

- Reference `Caddyfile` snippet using `forward_auth` pointing at `/verify`, passing through `X-Forwarded-Host`, `X-Forwarded-Uri`, etc.
- Confirm redirect-back-to-original-URL flow works end to end through Caddy (login → callback → original requested page)
- Document required Caddy version/directives
- Document the internal-network-only requirement for backend apps when identity headers are enabled

## Phase 11 — Hardening pass

- Cookie flags audit (`HttpOnly`, `Secure`, `SameSite`) on all cookies (session, flow/PKCE)
- Confirm the service binds only to an internal address/socket reachable by Caddy — never exposed directly — as the trust boundary for `X-Forwarded-Host` and `X-Auth-*` headers
- Code review: all raw secret/signature comparisons use constant-time comparison, not standard equality
- SQLite file permissions (0600, service-owned)
- Key-rotation runbook (doc, not code): edit config, restart, expected mass-logout behavior
- Load test: N concurrent hosts/sessions against SQLite, confirm no lock contention issues at expected scale
- Review logging for accidental token/secret leakage (including bearer tokens and audit logs)
- `/token` helper page: confirm `Cache-Control: no-store` and equivalent headers so the displayed access token isn't cached by browser/proxy/history
- JWKS cache behavior under IdP unavailability (serve stale keys briefly vs. fail closed — decide and document)
- Decide whether group-claim checks apply to resource-scoped token requests, or scope claims alone are sufficient

## Phase 12 — Docs

- Deployment guide (binary + config file + Caddy snippet)
- Quickstart: `forward-auth init` walked through end-to-end (one pocket-id instance, two apps), positioned as the first thing a new user runs — get something running before reading the full reference
- Per-host / per-base-domain config reference (all fields, examples for two providers)
- Operational runbook: key rotation, adding a new host, adding a second provider, reading logs and OTel traces for auth failures, revoking API access (disabling the client/permission on the IdP)
- Worked example: configuring a resource-scoped API on pocket-id (or another supporting IdP) and wiring the matching `resource`/`required_scope` into our per-host config

---

## Deferred / explicitly not building

- Cookie/key rotation without downtime
- Multi-instance / shared session state (Redis, etc.) — single instance only
- User-facing provider choice at login
- Central "logout everywhere" across domains
- Retry/backoff on IdP-unreachable-at-login (fails to plain error page instead)
- Optional-auth / public-but-identity-aware routes
- Buffering/replaying non-GET request bodies across a login redirect
- Prometheus-style metrics endpoint (audit log + OTel logs cover launch needs)
- Per-account login lockout (only per-IP rate limiting, to avoid a lockout-DoS vector)
