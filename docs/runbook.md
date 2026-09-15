# Operational runbook

## Rotating keys

`cookie_signing_key` and `refresh_token_encryption_key` have no
zero-downtime rotation — this is an explicit deferred item (see the
plan), not an oversight. Rotating either one:

- **`cookie_signing_key`**: every existing session and flow cookie was
  signed/encrypted with the old key, so it stops validating the moment
  you switch keys. Every logged-in user is logged out and has to log in
  again. There's no partial state to clean up — the old sessions simply
  stop verifying and behave exactly like "no session."
- **`refresh_token_encryption_key`**: every session row's stored refresh
  token was encrypted with the old key and becomes undecryptable. The
  next silent-refresh attempt for each such session fails closed (Phase
  2/11 behavior: decrypt failure → clear the session, `401`, Caddy sends
  to `/login`), so this also amounts to a full logout, just discovered
  session-by-session at each one's next refresh instead of all at once.

**Procedure**: generate two new random values (32+ bytes; `authward
init`'s own key generation — 32 random bytes, hex-encoded — is a fine
reference for the shape, though you don't need to re-run the wizard
itself), set them via `AUTHWARD_COOKIE_KEY` / `AUTHWARD_REFRESH_KEY`
(or in the config file, keeping it `chmod 600`), and restart the
service. Do this during a maintenance window if a mass forced re-login is
disruptive for your users. There's nothing to migrate in SQLite —
old session rows simply become permanently unreachable garbage; the
background reaper will clean them up once they pass `session_max_age`,
or delete the database file entirely if you'd rather not wait.

Rotate both keys at the same time if you rotate either — there's no
reason to leave the other one stale, and keeping them on the same
schedule is one less thing to track.

## Adding a new host

1. Add a `[host."new.example.com"]` block (see
   [config-reference.md](config-reference.md) for every field). Its
   domain is inferred from the hostname, and an empty block inherits
   everything. If the domain has a `fallback`, an unlisted host is
   already covered and the block is only needed for host-specific
   settings.
2. Add a Caddy `forward_auth` site block for it, modeled on
   [`deploy/Caddyfile`](../deploy/Caddyfile)'s `app.example.com` example.
3. Reload both Caddy and authward. Order doesn't matter — authward
   rejects a request for an unconfigured host with a `401` rather than
   crashing, so a brief window where Caddy knows about the host before
   authward's config is reloaded just produces `401`s, not confusion.

No IdP-side change needed unless the new host also needs its own OIDC
client (see "adding a second provider" below) or its own resource for
API tokens (see [api-tokens.md](api-tokens.md)).

## Adding a second domain or a second IdP

- **A whole new domain** (a different top-level property with its own
  users): add a `[domain."other.com"]` block with its own
  `auth_subdomain`, then hosts under it as usual. It can reuse an
  existing `[idp]` (register `https://auth.other.com/callback` as an
  additional redirect URI of that client) or name a new one. Domains are
  fully independent, including the overview page and `/token`:
  `https://auth.other.com/` lists and issues tokens for `other.com`
  hosts only, and won't show them on `auth.example.com`.
- **A second identity provider**: add an `[idp."<name>"]` block with its
  `discovery_url`, `client_id` and `client_secret`, then reference it.
  Once more than one `[idp]` exists every domain must say which one it
  uses (`idp = "..."`) — a domain that relied on the single-IdP default
  becomes a config error listing the choices, so nothing switches IdP
  silently.
- **One host on an existing domain, but a different IdP than that
  domain's default** (e.g. a partner's app that authenticates against
  the partner's own IdP while staying under your domain's
  single-sign-on umbrella for everything else): set `idp = "<name>"` on
  that one `[host."..."]` block — see
  [config-reference.md](config-reference.md)'s two-IdP example and its
  "Per-host IdPs" section for how sessions behave across the two.

Either way: register the domain's `https://<auth_subdomain>/callback` as
a redirect URI of the OIDC client at that provider first, then update
the config and reload.

## Reading logs and OTel traces for auth failures

Logs are JSON on stdout always (`RUST_LOG` controls level, default
`info`), and optionally also exported via OTLP/gRPC when
`otel_endpoint` is set. Every denial or error logs a reason as a
structured field, not just a status code — grep/query on these instead
of guessing from the HTTP response alone. The `session_id` field is a
12-hex-character hash of the real ID, not the ID itself (which is the
session's credential): stable enough to correlate one session's lines,
useless as a cookie.

| What you're chasing | Look for | Key fields |
|---|---|---|
| Denied at `/verify` for a browser session | `"session presented against the wrong base domain"`, `"session was established at a different provider than this host uses"`, `"session past its absolute max age; clearing"`, `"session's provider is not available; clearing session"`, `"denied: missing required group"` | `session_id`, `subject`, `host`, `required_group`, `session_provider` / `expected_provider` |
| Denied at `/verify` for a bearer token | `"bearer token rejected"` (validation failure — bad signature, wrong audience, expired, missing scope), `"bearer token denied: missing required group"` | `err`, `host`, `required_group` |
| Silent refresh failing | `"refresh failed; clearing session"`, `"failed to decrypt stored refresh token"`, `"refreshed id_token failed verification; clearing session"` | `session_id`, `err` |
| CSRF / stale flow cookie at `/callback` | `"callback state mismatch — possible CSRF or stale flow cookie"` | (no session_id yet at this point — it's pre-login) |
| IdP returned an error at `/callback` | `"identity provider returned an error"` | `error`, `description` |
| Config problem at startup | printed to stderr, not through the logger — `authward: N config error(s) found in <path>` followed by every error | — |
| IdP unreachable at startup (its hosts show "Provider unavailable" until this clears; `provider_key` is the `[idp]` name) | `"OIDC provider discovery failed; will retry in the background"`, then `"OIDC provider discovery still failing"` every 30s, and `"OIDC provider discovered after earlier failure; now serving"` once it recovers. If no provider at all was reachable the process exits instead, with `no OIDC provider could be discovered` on stderr. | `provider_key`, `discovery_url`, `err` |
| Login refused because its provider is still undiscovered | `"login refused: provider not yet discovered"` | `provider_key` |
| JWKS refresh failing (bearer validation may start failing if this persists) | `"periodic JWKS refresh failed"` | `provider_key`, `err` |
| Rate limited | `"rate limit exceeded on login/callback"` | `ip` |
| Reaper activity (informational, not a failure) | `"reaper: swept expired sessions"` | `reaped` (count) |

A `401` with no `x-login-url` header and no matching request-scoped log
line at all usually means the *host* wasn't recognized — check
`"config loaded"` at startup logged `hosts = N` matching what you
expect, and that Caddy's `X-Forwarded-Host` matches the config's host
key exactly (case doesn't matter — both sides lowercase — but the base
hostname must match; `X-Forwarded-Host` should not include a port).

This is also the one `401` that's completely blank in the browser — a
normal not-logged-in `401` is intercepted by Caddy and redirected to
`/login` before it ever renders, and a session that expired mid-POST
renders an explicit "Session expired" page. So if you're testing a new
host and the browser just shows a bare, empty `401` with no page
content and no redirect, that alone points at an unrecognized host
before you even check headers or logs.

## Revoking API access

There is no per-token revoke on authward's side by design (see
[api-tokens.md](api-tokens.md)) — validation is stateless, and nothing
about a specific issued token is tracked here. To cut off access:

- Disable the OIDC client, or its permission on the specific resource,
  at the IdP. This is immediate for IdPs that check client/permission
  status at token-validation time, or takes effect as soon as the
  currently-issued token expires otherwise (typically short-lived —
  check your IdP's default access-token TTL for that resource).
- To force an immediate cut, shorten the resource's access-token TTL at
  the IdP (if supported) rather than trying to intervene from
  authward's side.

Disabling a **user** at the IdP takes effect at that user's next silent
refresh — i.e. within one access-token lifetime (`expires_in`, typically
minutes to an hour) — when the IdP refuses the refresh and authward
clears the session. There is no back-channel logout, so if you need it
faster, shorten the access-token TTL at the IdP for authward's
client. `session_max_age_seconds` (default 24h) is the hard upper bound
on any session regardless of what the IdP does.

Revoking a **browser session** is different and does have per-session
control: the `/` overview page lists a user's own other active sessions
with a revoke button (`POST /sessions/revoke`), scoped so a session can
only ever revoke another session belonging to the same subject and
domain — never anyone else's, even by guessing a session ID. `/logout`
(also POST-only) ends the current session and, when the provider
supports RP-Initiated Logout, sends the browser to the IdP's own
`end_session_endpoint` too so the IdP-side session ends as well, not
just authward's.
