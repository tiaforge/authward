# Worked example: resource-scoped API tokens

forward-auth lets a non-browser client (a CLI, a script, a cron job) call
a protected app with `Authorization: Bearer <token>` instead of a
session cookie. There's no token store or issuance logic on our side —
the IdP issues and can revoke the token; forward-auth only validates it
locally against the IdP's published JWKS (RFC 8707 "Resource Indicators"
+ RFC 9068's JWT access token profile). This only works if your IdP
supports scoping an access token to a resource identifier — pocket-id's
"APIs" feature is one; Keycloak, Auth0, and Okta have equivalents.

## 1. Define the resource at the IdP

In pocket-id, create an API resource for the app (consult pocket-id's
current docs for the exact UI — the underlying mechanism is standard
OAuth resource indicators regardless of the UI's wording). You'll end up
with:

- a **resource identifier** — a URI-shaped string identifying the API,
  e.g. `https://app.example.com/api`
- optionally, one or more **scopes** the resource accepts, e.g. `read`,
  `admin`

Whatever OIDC client forward-auth uses for that host (its base domain's
default, or a per-host `provider` override) needs to be allowed to
request tokens for this resource.

## 2. Wire it into forward-auth's config

Add `resource` (and optionally `required_scope`) to the host:

```toml
[host."app.example.com"]
base_domain = "example.com"
resource = "https://app.example.com/api"
required_scope = "read"   # omit if any scope from the resource is acceptable
```

That's the whole config change. No restart-order dependency — reload
forward-auth after editing.

## 3. Get a token

There's no end-user "generate key" button at most IdPs for this flow —
forward-auth's own `/token` endpoint acts as the OIDC client on the
user's behalf:

```
https://auth.example.com/token?host=app.example.com
```

Visiting it always starts a fresh authorization request to the IdP (it
doesn't check for an existing forward-auth session cookie first) with
`resource=https://app.example.com/api` added, then shows the resulting
access token once on a plain confirmation page (sent with
`Cache-Control: no-store`). If you already have an active session at the
IdP itself, it may skip straight past the login prompt — that's the
IdP's own SSO behavior, not something forward-auth controls. Copy the
token — forward-auth doesn't store it and can't show it again; re-visit
`/token` to get a new one.

If the host has no `resource` configured, `/token?host=...` returns a
400 rather than silently falling back to a session — this is a
config-completeness check, not a runtime fallback.

## 4. Call the API

```sh
curl -H "Authorization: Bearer $TOKEN" https://app.example.com/api/...
```

forward-auth's `/verify` (which Caddy's `forward_auth` calls for every
request) checks for a session cookie first; only if that's absent does
it try the `Authorization` header as a bearer token. Validation is
entirely local and stateless:

1. JWT signature checked against the IdP's JWKS (cached, refreshed
   periodically; refreshed on demand once if a signature check fails,
   to pick up key rotation — see [`src/jwks_cache.rs`](../src/jwks_cache.rs)).
2. `iss` must match the configured provider.
3. `aud` must contain the host's `resource` value.
4. `exp` must not have passed (with the usual ±60s clock-skew leeway).
5. If `required_scope` is set, the space-delimited `scope` claim must
   contain it.
6. If the host also has `required_group` set, the token's claims are
   checked against it exactly like a browser session — an API token
   doesn't bypass group-based authorization.

Any failure is a `401` (or `403` for the group check specifically),
logged with the reason — see the [runbook](runbook.md).

## Revocation

There's no per-token revoke on forward-auth's side — the plan's accepted
tradeoff for not needing a token store at all. To cut off API access,
disable the client (or its permission on that resource) at the IdP. The
next validation attempt fails at signature/audience time as soon as the
IdP stops recognizing it, or immediately if the IdP itself checks token
status server-side; either way, forward-auth has nothing to clean up on
its end.
