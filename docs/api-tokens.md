# Worked example: resource-scoped API tokens

authward lets a non-browser client (a CLI, a script, a cron job) call
a protected app with `Authorization: Bearer <token>` instead of a
session cookie. There's no token store or issuance logic on our side —
the IdP issues and can revoke the token; authward only validates it
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

Whatever `[idp]` authward uses for that host (its domain's default, or
the host's own `idp = ...`) needs to be allowed to request tokens for
this resource.

## 2. Wire it into authward's config

Add `resource` (and optionally `required_scope`) to the host:

```toml
[host."app.example.com"]
resource = "https://app.example.com/api"
required_scope = "read"   # omit if any scope from the resource is acceptable
```

That's the whole config change. No restart-order dependency — reload
authward after editing.

## 3. Get a token

There's no end-user "generate key" button at most IdPs for this flow —
authward's own `/token` endpoint acts as the OIDC client on the
user's behalf:

```
https://auth.example.com/token?host=app.example.com
```

Visiting it always starts a fresh authorization request to the IdP (it
doesn't check for an existing authward session cookie first) with
`resource=https://app.example.com/api` added, then shows the resulting
access token once on a plain confirmation page (sent with
`Cache-Control: no-store`). If you already have an active session at the
IdP itself, it may skip straight past the login prompt — that's the
IdP's own SSO behavior, not something authward controls. Copy the
token — authward doesn't store it and can't show it again; re-visit
`/token` to get a new one.

If the host has no `resource` configured, `/token?host=...` returns a
400 rather than silently falling back to a session — this is a
config-completeness check, not a runtime fallback.

`/token` and the overview page are scoped to one domain: the auth
subdomain you visit only lists, and only issues tokens for, hosts under
the domain that auth subdomain belongs to. A host under a second domain
shows up on *that* domain's overview page, and its token URL is
`https://<that domain's auth_subdomain>/token?host=...`.
Asking `auth.example.com` for a token for a host on `other.com` returns
a 400 ("Wrong auth domain").

The confirmation page also names the exact header to send the token in
for that host — by default `X-Auth-Token` with the bare token as its
value, so a user never has to know what "Bearer" means.

## 4. Call the API

```sh
curl -H "X-Auth-Token: $TOKEN" https://app.example.com/api/...
```

authward's `/verify` (which Caddy's `forward_auth` calls for every
request) checks for a valid session cookie first; if there is none — no
cookie, or one whose session has since been logged out, revoked, or
expired — it reads the token from the host's `token_header`. Only that
header is looked at. With the default `X-Auth-Token`, the value is the
token itself (a pasted leading `Bearer ` is tolerated). Set
`token_header = "Authorization"` on a host to read a conventional
`Authorization: Bearer <token>` instead; there the `Bearer` scheme is
required (and case-insensitive, per RFC 9110). Validation is entirely
local and stateless:

1. JWT signature checked against the IdP's JWKS (cached, refreshed
   periodically; refreshed on demand once if a signature check fails,
   to pick up key rotation — see [`src/jwks_cache.rs`](../src/jwks_cache.rs)).
2. `iss` must match the host's `[idp]`.
3. `aud` must contain the host's `resource` value.
4. `exp` must not have passed (with the usual ±60s clock-skew leeway).
5. If `required_scope` is set, the space-delimited `scope` claim must
   contain it.
6. If the host also has `required_group` set, the token's claims are
   checked against it exactly like a browser session — an API token
   doesn't bypass group-based authorization.

Any failure is a `401` (or `403` for the group check specifically),
logged with the reason — see the [runbook](runbook.md).

## Apps that use `Authorization` themselves (e.g. Immich)

Some apps authenticate their own clients with `Authorization: Bearer`
— Immich's mobile app sends its Immich session token that way on every
API call. That token isn't an IdP-issued JWT, so if authward read the
same header it would reject every request, and an authward token in
that header would break the app's own login. This is why the default
`token_header` is `X-Auth-Token`: the app keeps `Authorization`, and
authward's token travels in its own header alongside it.

For Immich specifically:

1. Configure the Immich host with a `resource` as above (keep the
   default `token_header`).
2. Each user visits `https://auth.example.com/` and requests a token for
   the Immich host. The page shows `X-Auth-Token: <token>`.
3. In the Immich mobile app, open *Settings → Advanced → Custom proxy
   headers* and add a header named `X-Auth-Token` with the token as its
   value. The app then sends it with every request, and authward
   accepts those while Immich continues to handle its own login.

The token expires on the IdP's access-token TTL for that resource;
when the app starts failing, fetch a new one from the overview page and
update the header. If that's too frequent, raise the TTL for the
resource at the IdP.

## Revocation

There's no per-token revoke on authward's side — the plan's accepted
tradeoff for not needing a token store at all. To cut off API access,
disable the client (or its permission on that resource) at the IdP. The
next validation attempt fails at signature/audience time as soon as the
IdP stops recognizing it, or immediately if the IdP itself checks token
status server-side; either way, authward has nothing to clean up on
its end.
