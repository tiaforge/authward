# Config reference

The config file is TOML with four kinds of block: `[global]`, one or
more `[idp."..."]`, one or more `[domain."..."]` (each with an optional
`.fallback` sub-table), and any number of `[host."..."]`. On any problem,
authward reports **every** error it finds in one run, not just the
first — fix them all at once rather than one at a time.

Host and domain names are case-normalized (lowercased) at load time, and
matched against the (also-lowercased) incoming `Host` /
`X-Forwarded-Host`, so `App.Example.COM` in the config and
`app.example.com` on the wire resolve to the same host.

A complete small example:

```toml
[global]
cookie_signing_key = "..."
refresh_token_encryption_key = "..."

[idp."pocketid"]
discovery_url = "https://idp.example.com/.well-known/openid-configuration"
client_id = "authward"
client_secret = "..."

[domain."example.com"]
auth_subdomain = "auth.example.com"
idp = "pocketid"                 # may be omitted while there is only one [idp]

[domain."example.com".fallback]  # optional: any *.example.com host with no [host] block
required_group = "users"

[host."app.example.com"]         # an empty block is fine: it inherits everything

[host."admin.example.com"]
required_group = "admins"
```

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

## `[idp."<name>"]`

One block per registered OIDC client. The name is yours to choose
(`pocketid`, `keycloak-staff`, ...); domains and hosts refer to the block
by it, and it is recorded on every session (as the `provider_key` field
in logs). One identity provider with two different client registrations
is two `[idp]` blocks.

| Field | Required | Notes |
|---|---|---|
| `discovery_url` | yes | The IdP's `.well-known/openid-configuration` URL. Must be `https` — plain `http` is only accepted for loopback addresses (`127.0.0.1`, `localhost`, `::1`), and the same rule is applied at startup to every endpoint the discovery document advertises, since the client secret and tokens go to those. |
| `client_id` | yes | |
| `client_secret` | yes | Treat as a secret. |

Every `[idp]` is discovered once at startup (retried in the background if
its IdP is down at that moment — see the [deployment guide](deployment.md))
and gets one OIDC client and one JWKS cache, shared by every domain that
uses it. Register `https://<auth_subdomain>/callback` for **each** domain
that uses the IdP as a redirect URI of that client.

## `[domain."<name>"]`

One block per domain — a DNS suffix that shares one auth subdomain, one
default IdP, and (via the session cookie's `Domain=.<name>` scope) single
sign-on across every host on it.

| Field | Required | Notes |
|---|---|---|
| `auth_subdomain` | yes | The host that serves `/login`, `/callback`, `/logout`, `/`, `/token`, `/healthz` for this domain. Point Caddy's plain `reverse_proxy` block at this host. The overview page and `/token` here only cover hosts under this domain — each domain has its own dashboard. |
| `idp` | yes, unless exactly one `[idp]` block exists | Name of the `[idp."..."]` this domain's hosts authenticate against unless a host overrides it. With a single `[idp]` defined it is chosen automatically; with several, omitting it is a config error that lists the choices. |
| `fallback` | no | A sub-table (`[domain."<name>".fallback]`) with the same fields as a `[host]` block minus `domain`. Applies to any host under this domain that has no `[host]` block of its own. Omit it to make an unlisted host under this domain a hard failure (logged, `502`). |

## `[host."<hostname>"]`

One block per protected app hostname. Every field is optional; a host
inherits everything it doesn't set from its domain, so an empty block is
a valid, fully protected host.

| Field | Required | Default | Notes |
|---|---|---|---|
| `domain` | no | inferred | The `[domain."..."]` this host belongs to. Inferred as the longest configured domain that the hostname equals or is a subdomain of (at any depth), which is the only domain whose session cookie the browser would send to this host. A host under no configured domain is a hard config error. Set it explicitly only when configured domains nest (e.g. both `example.com` and `corp.example.com`) and you want the shorter one; it must still be a suffix of the hostname. |
| `idp` | no | the domain's | Name of an `[idp."..."]` block. Puts this one host on a different OIDC client or a different identity provider than its domain's default; see [Per-host IdPs](#per-host-idps) for how sessions behave. |
| `required_group` | no | none (any valid login passes) | Value the claim named by `group_claim_name` must contain. Checked after every login and every silent refresh — losing the group mid-session denies on the next refresh, not just at next login. |
| `group_claim_name` | no | `groups` | The claim can be a JSON array of strings or a single string; anything else, or a missing claim while `required_group` is set, fails closed (denied). |
| `bypass_paths` | no | `[]` | Exact paths (no query string, no fragment) that skip auth entirely — e.g. `/healthz` on an app that has its own. Must start with `/`; must not contain `?` or `#`. Matching is exact-path only after one round of percent-decoding; a query string or fragment appended to a protected path never matches a bypass entry. |
| `forward_identity_headers` | no | `false` | When true, a successful `/verify` fills in `X-Auth-User` / `X-Auth-Email` / `X-Auth-Groups`, which Caddy's `copy_headers` must be configured to relay (see the Caddyfile). All three headers are sent on every successful `/verify` even when this is false (as empty values) so `copy_headers` always overwrites a client-supplied one. `X-Auth-Email` is only populated when the IdP marks the email verified (`email_verified: true`); an unverified email is whatever the user typed into their profile. Backends should key on `X-Auth-User` (the OIDC `sub`), which is stable and IdP-assigned. `X-Auth-Groups` is comma-joined without escaping — don't use group names containing commas. |
| `resource` | no | none | The OAuth resource identifier (RFC 8707) this host's API accepts. Required for `/token` to issue an API token for this host, and for a bearer token to be accepted at all (see [api-tokens.md](api-tokens.md)). |
| `required_scope` | no | none | A scope that must be present in an API token's `scope` claim for this host. Only meaningful alongside `resource`. |
| `token_header` | no | `X-Auth-Token` | The request header an API token is read from. With the default, the header's value is the bare token — no `Bearer` word — so non-technical users can paste it as-is, and it stays out of the `Authorization` header that apps like Immich use for their own login. Set to `Authorization` to read a conventional `Authorization: Bearer <token>` instead. Only the configured header is ever read. Any valid header name is accepted except `Cookie`, `Host`, `X-Forwarded-Host` and `X-Forwarded-Uri`. Only meaningful alongside `resource`. |

## Host resolution

For every `/verify`, the incoming `X-Forwarded-Host` (or `Host`) is
matched, in order:

1. A `[host."<hostname>"]` block with exactly that name.
2. Otherwise, the `fallback` of the longest configured domain the
   hostname falls under (equal to it, or a subdomain at any depth).
3. Otherwise it is a hard failure: logged, `502`. Neither an allow nor a
   silent deny — an unknown host is a configuration mistake.

A host's `[host]` block always wins over its domain's fallback, and a
fallback never reaches across domains: `[domain."example.com".fallback]`
has no effect on `x.other.com`, listed or not.

## Per-host IdPs

A session records which `[idp]` logged it in, and a host only accepts
sessions from *its* IdP:

- `/login?rd=https://partner.example.com/...` runs the login at the IdP
  `partner.example.com` is configured with (the host named by `rd`; no
  `rd`, or an unknown host, means the domain's default). `/token?host=...`
  likewise uses the target host's IdP.
- `/verify` for a host rejects a session established at any other IdP,
  even on the same domain, and sends the browser to log in at the right
  one. Bearer tokens are validated against the host's own IdP's JWKS and
  issuer.
- A domain still has one session cookie. Logging in at a host with an
  `idp` override replaces a session from the default IdP (and vice
  versa), so a user moving between hosts on different IdPs is bounced
  through `/login` each time they cross over — silently, when the IdP
  still has its own session. Put hosts that users move between constantly
  on the same IdP.
- The dashboard lists and revokes only sessions from the same IdP as the
  current one; the same `sub` string at two IdPs is two people.
- `/logout` ends the session at the IdP that created it.

Upgrading from a config that predates named IdPs: sessions created before
the upgrade record the old provider identifier and are rejected at their
next `/verify`, so every user logs in once more. Nothing needs cleaning
up; the reaper removes the old rows as they age out.

## Two-IdP example

A host can point at an entirely different identity provider than its
domain's default by naming another `[idp]`:

```toml
[global]
cookie_signing_key = "..."
refresh_token_encryption_key = "..."

[idp."pocketid"]
discovery_url = "https://idp-a.example.com/.well-known/openid-configuration"
client_id = "authward"
client_secret = "..."

[idp."partner"]
discovery_url = "https://idp-b.partner.net/.well-known/openid-configuration"
client_id = "authward-partner"
client_secret = "..."

[domain."example.com"]
auth_subdomain = "auth.example.com"
idp = "pocketid"

# Inherits pocketid.
[host."app.example.com"]

# Logs in at the partner's IdP instead, still under the same domain (same
# auth subdomain, same single-sign-on cookie scope).
[host."partner-app.example.com"]
idp = "partner"
```

Both IdPs need `https://auth.example.com/callback` registered as a
redirect URI, since that is where every login under `example.com` lands.

See [`examples/config.toml`](../examples/config.toml) for a minimal
complete single-IdP example, and [runbook.md](runbook.md) for how to add
a host or a second IdP to a running deployment.
