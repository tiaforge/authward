# Quickstart

This walks through getting authward running end to end with one IdP
(pocket-id, but any OIDC provider works the same way) and two apps on one
base domain, using `authward init` rather than hand-editing TOML.
Read this before the [config reference](config-reference.md) — the goal
here is a working setup, not full coverage of every field.

## 0. Prerequisites

- A running OIDC provider you can register a client on (pocket-id,
  Keycloak, Authentik, Auth0, ...). You'll need its discovery URL
  (`https://idp.example.com/.well-known/openid-configuration`) and a
  client ID/secret for a confidential client with a redirect URI of
  `https://auth.example.com/callback`.
- Caddy in front of both this service and the apps it protects, on a
  network where nothing but Caddy can reach either — see
  [deployment.md](deployment.md) for why this matters.
- The `authward` binary built (`cargo build --release`) or otherwise
  available on the host that will run it.

## 1. Register the OIDC client at your IdP

Create a confidential client with:

- Redirect URI: `https://auth.example.com/callback`
- Scopes: at least `openid profile email` (add `groups` too if your IdP
  needs it enabled explicitly to include a groups claim)

Note the client ID and client secret — the wizard will ask for them next.

## 2. Run the wizard

```sh
authward init
```

It prompts for:

1. **Base domain** (e.g. `example.com`) — everything under it shares one
   auth subdomain, one provider, and single sign-on via the session
   cookie's `Domain=.example.com` scope.
2. **Auth subdomain** (defaults to `auth.<base domain>`).
3. **OIDC discovery URL**.
4. **OIDC client ID** and **client secret**.
5. **First app hostname to protect** (e.g. `app.example.com`).

It then writes `config.toml` (chmod 600 — it contains generated secret
key material for cookie signing and refresh-token-at-rest encryption)
and prints next steps. It refuses to overwrite an existing file, so
re-running it is safe.

## 3. Add the second app

The wizard only sets up one host. Open the generated `config.toml` and
add a second `[host."..."]` block for your other app, inheriting
everything from the same base domain:

```toml
[host."app2.example.com"]
base_domain = "example.com"
```

See [config-reference.md](config-reference.md) for every field a host
can set (`required_group`, `bypass_paths`, `forward_identity_headers`,
`resource`/`required_scope` for API tokens, ...). The checked-in
[`examples/config.toml`](../examples/config.toml) is a second
copy-and-edit starting point with both a bare host and one using several
optional fields.

## 4. Point Caddy at it

Add both site blocks from [`deploy/Caddyfile`](../deploy/Caddyfile) to
your Caddy config — one for the auth subdomain (plain reverse proxy) and
one per protected app (`forward_auth` + the `handle_response` block that
turns a 401 on a GET into a redirect to `/login`, plus the `header_up`
lines that keep the session cookie away from the backend). Adjust the
hostnames and backend addresses, then reload Caddy.

## 5. Start authward

```sh
authward --config config.toml
```

It listens on `127.0.0.1:8080` by default (see `listen_addr` in
[config-reference.md](config-reference.md)) — only Caddy should ever be
able to reach it.

## 6. Try it

Visit `https://app.example.com/` in a browser. You should be redirected
to your IdP, log in, and land back on the app with a session cookie set.
Visiting `https://auth.example.com/` shows the overview page (who's
logged in, other active sessions, links to request an API token for any
host with a `resource` configured).

If something doesn't work, see the [runbook](runbook.md)'s "reading logs"
section — every request that's denied or errors logs a structured reason.
