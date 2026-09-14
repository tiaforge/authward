# Config reference

The config file is TOML with four kinds of block: `[global]`, one or
more `[base_domain."..."]`, one or more `[host."..."]`, and an optional
`[fallback]`. On any problem, authward reports **every** error it
finds in one run, not just the first — fix them all at once rather than
one at a time.

Host and base-domain names are case-normalized (lowercased) at load
time, and matched against the (also-lowercased) incoming `Host` /
`X-Forwarded-Host`, so `App.Example.COM` in the config and
`app.example.com` on the wire resolve to the same host.

## `[global]`

| Field | Required | Default | Notes |
|---|---|---|---|
| `cookie_signing_key` | yes, unless `AUTHWARD_COOKIE_KEY` is set | — | Signs/encrypts the session and flow cookies. Any string; treat it as a secret. Must differ from `refresh_token_encryption_key`. |
| `refresh_token_encryption_key` | yes, unless `AUTHWARD_REFRESH_KEY` is set | — | Encrypts refresh tokens at rest in SQLite. Must differ from `cookie_signing_key`. |
| `sqlite_path` | no | `authward.db` | Path to the session database. Created if missing; chmod'd to `0600`. |
| `session_ttl_fallback_seconds` | no | `3600` | Used only when the IdP's token response doesn't include an explicit `expires_in`. |
| `session_max_age_seconds` | no | `86400` (24h) | Absolute lifetime of a browser session from login, regardless of how many silent refreshes succeed. Bounds how long a stolen session cookie stays usable. Must be > 0. |
| `otel_endpoint` | no | unset | OTLP/gRPC endpoint for log export, e.g. `http://localhost:4317`. Logs always also go to stdout as JSON regardless. |
| `listen_addr` | no | `127.0.0.1:8080` | Must stay unreachable except from Caddy — see [deployment.md](deployment.md). |

If either key is set in the config file itself (not via env var), the
file must not be group- or other-readable — authward checks this at
startup and refuses to start otherwise. Prefer the env vars
(`AUTHWARD_COOKIE_KEY` / `AUTHWARD_REFRESH_KEY`) when your
deployment already has a secrets-injection mechanism.

## `[base_domain."<name>"]`

One block per base domain — a DNS suffix that shares one auth subdomain,
one OIDC client, and (via the session cookie's `Domain=.<name>` scope)
single sign-on across every host on it.

| Field | Required | Notes |
|---|---|---|
| `auth_subdomain` | yes | The host that serves `/login`, `/callback`, `/logout`, `/`, `/healthz` for this base domain. Point Caddy's plain `reverse_proxy` block at this host. |
| `provider.discovery_url` | yes | The IdP's `.well-known/openid-configuration` URL. Must be `https` — plain `http` is only accepted for loopback addresses (`127.0.0.1`, `localhost`, `::1`), and the same rule is applied at startup to every endpoint the discovery document advertises, since the client secret and tokens go to those. |
| `provider.client_id` | yes | |
| `provider.client_secret` | yes | Treat as a secret. |

## `[host."<hostname>"]`

One block per protected app hostname. Every field except `base_domain`
is optional and inherits from the named base domain when omitted.

| Field | Required | Default | Notes |
|---|---|---|---|
| `base_domain` | yes | — | Must name a configured `[base_domain."..."]`; a dangling reference is a hard config error. |
| `provider` | no | inherited | A full override (`discovery_url`, `client_id`, `client_secret`, all three or none — partial overrides are rejected rather than merged field-by-field). Puts this one host on a different OIDC client or a different IdP than its base domain's default; see [Per-host providers](#per-host-providers) for how sessions behave. |
| `required_group` | no | none (any valid login passes) | Value the claim named by `group_claim_name` must contain. Checked after every login and every silent refresh — losing the group mid-session denies on the next refresh, not just at next login. |
| `group_claim_name` | no | `groups` | The claim can be a JSON array of strings or a single string; anything else, or a missing claim while `required_group` is set, fails closed (denied). |
| `bypass_paths` | no | `[]` | Exact paths (no query string, no fragment) that skip auth entirely — e.g. `/healthz` on an app that has its own. Must start with `/`; must not contain `?` or `#`. Matching is exact-path only after one round of percent-decoding; a query string or fragment appended to a protected path never matches a bypass entry. |
| `forward_identity_headers` | no | `false` | When true, a successful `/verify` fills in `X-Auth-User` / `X-Auth-Email` / `X-Auth-Groups`, which Caddy's `copy_headers` must be configured to relay (see the Caddyfile). All three headers are sent on every successful `/verify` even when this is false (as empty values) so `copy_headers` always overwrites a client-supplied one. `X-Auth-Email` is only populated when the IdP marks the email verified (`email_verified: true`); an unverified email is whatever the user typed into their profile. Backends should key on `X-Auth-User` (the OIDC `sub`), which is stable and IdP-assigned. `X-Auth-Groups` is comma-joined without escaping — don't use group names containing commas. |
| `resource` | no | none | The OAuth resource identifier (RFC 8707) this host's API accepts. Required for `/token` to issue an API token for this host, and for a bearer token to be accepted at all (see [api-tokens.md](api-tokens.md)). |
| `required_scope` | no | none | A scope that must be present in a bearer access token's `scope` claim for this host. Only meaningful alongside `resource`. |

## `[fallback]`

Same fields as a `[host."..."]` block, minus a hostname — applies to any
request whose `Host`/`X-Forwarded-Host` doesn't match a base domain or an
explicit host entry. Omit it entirely to make an unrecognized host a
hard failure (logged, `502`) instead of silently falling back to
something.

## Per-host providers

Every distinct provider — each base domain's default plus every host
(or fallback) `provider` override — is discovered at startup (retried
in the background if its IdP is down at that moment — see the
[deployment guide](deployment.md)) and gets its own OIDC client and
JWKS cache. All clients under one base domain
share that base domain's `https://<auth_subdomain>/callback` as their
redirect URI, so register that URI at each IdP.

A session records which provider logged it in, and a host only accepts
sessions from *its* provider:

- `/login?rd=https://partner.example.com/...` runs the login at the
  provider `partner.example.com` is configured with (the host named by
  `rd`; no `rd`, or an unknown host, means the base domain's default).
  `/token?host=...` likewise uses the target host's provider.
- `/verify` for a host rejects a session established at any other
  provider, even on the same base domain, and sends the browser to log
  in at the right one. Bearer tokens are validated against the host's
  own provider's JWKS and issuer.
- A base domain still has one session cookie. Logging in at an
  overridden host replaces a session from the default provider (and
  vice versa), so a user moving between hosts on different providers is
  bounced through `/login` each time they cross over — silently, when
  the IdP still has its own session. Put hosts that users move between
  constantly on the same provider.
- The dashboard lists and revokes only sessions from the same provider
  as the current one; the same `sub` string at two IdPs is two people.
- `/logout` ends the session at the IdP that created it.

## Two-provider example

A host can point at an entirely different IdP than its base domain's
default by fully overriding `provider`:

```toml
[global]
cookie_signing_key = "..."
refresh_token_encryption_key = "..."

[base_domain."example.com"]
auth_subdomain = "auth.example.com"

[base_domain."example.com".provider]
discovery_url = "https://idp-a.example.com/.well-known/openid-configuration"
client_id = "authward"
client_secret = "..."

# Inherits idp-a above.
[host."app.example.com"]
base_domain = "example.com"

# Overrides to a second IdP entirely, still under the same base domain
# (same auth subdomain, same single-sign-on cookie scope — but this one
# host's own login goes to idp-b instead).
[host."partner-app.example.com"]
base_domain = "example.com"

[host."partner-app.example.com".provider]
discovery_url = "https://idp-b.example.com/.well-known/openid-configuration"
client_id = "authward-partner"
client_secret = "..."
```

See [`examples/config.toml`](../examples/config.toml) for a minimal
complete single-provider example, and [runbook.md](runbook.md) for how
to add a host or a second provider to a running deployment.
