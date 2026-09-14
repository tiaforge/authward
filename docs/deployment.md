# Deployment guide

## What you're deploying

A single Rust binary (`authgate`) plus one TOML config file and one
SQLite database file. No external services required — not even the
database is separate. This is deliberate: see the plan's locked-in
"single instance, no HA requirement" decision. There's no clustering
story and no shared session state; if you need authgate on more than
one machine, run one instance per deployment, each with its own config
and SQLite file.

## The trust boundary — read this first

authgate trusts three things unconditionally, because they're only
supposed to be set by a proxy it trusts, not by end clients:

- `X-Forwarded-Host` (falls back to `Host`) — which host config to apply
- `X-Forwarded-Proto` — whether to set the `Secure` cookie flag
- `X-Forwarded-For` (last hop only) — the client IP used for rate limiting

And on the way out, when a host has `forward_identity_headers = true`,
authgate's `/verify` response carries `X-Auth-User` /
`X-Auth-Email` / `X-Auth-Groups`, which Caddy's `copy_headers` then
overwrites onto the request forwarded to the backend app.

None of this is safe unless **both** of the following hold:

1. **authgate itself is unreachable except through Caddy.** Bind it
   to `127.0.0.1` (the default) or a private network address, never
   `0.0.0.0` on a host with a public interface, and never put it behind
   a second proxy that doesn't strip/overwrite these headers.
2. **Every backend app is unreachable except through Caddy.** If a
   client can reach `app.example.com`'s backend directly — a
   misconfigured firewall, a second exposed port, a container network
   with no isolation — they can set their own `X-Auth-User` header and
   the backend will trust it, because `copy_headers`' overwrite never
   happens for a request that skipped Caddy entirely.

In practice: put Caddy and every backend app on an internal network with
no other route in (a dedicated Docker network, a private VPC, or
loopback-only binds on a single host), and don't rely on the backend app
itself to defend against a spoofed identity header — it has no way to
tell authgate's header apart from a client's.

## Files on disk

| File | Contents | Permissions |
|---|---|---|
| the config file | OIDC client secrets, and (unless you use the env-var overrides below) the cookie-signing and refresh-token-encryption keys | must be `0600` — authgate refuses to start if key material lives in a config file that's group/other-readable |
| the SQLite database (`sqlite_path`, default `authgate.db`) | session rows: subject, email, encrypted refresh token, expiry, raw ID token claims | chmod'd to `0600` automatically at startup |

As a second layer, authgate sets `umask 0o077` for its own process
at startup, so any file it creates defaults to owner-only permissions
even if a call site forgot to `chmod` explicitly.

Secrets can also come from the environment instead of the file:
`AUTHGATE_COOKIE_KEY` and `AUTHGATE_REFRESH_KEY` take precedence
over the config file's `cookie_signing_key` / `refresh_token_encryption_key`
when set — useful for a secrets manager or container orchestrator that
injects env vars rather than files.

## Running it

```sh
authgate --config /etc/authgate/config.toml
```

There's no daemonization built in — run it under systemd, a container
supervisor, or whatever your platform already uses for long-running
services. It handles `SIGINT`/ctrl-c with a graceful shutdown (finishes
in-flight requests, then exits); there's no separate `SIGTERM` handling
distinct from that.

A minimal systemd unit:

```ini
[Unit]
Description=authgate
After=network.target

[Service]
ExecStart=/usr/local/bin/authgate --config /etc/authgate/config.toml
Restart=on-failure
User=authgate
WorkingDirectory=/var/lib/authgate

[Install]
WantedBy=multi-user.target
```

Run it as a dedicated non-root user that owns its config and database
directory — nothing here needs root.

### Login rate limiting

`/login`, `/token` and `/callback` share a per-client-IP token bucket:
a burst of 20 requests, refilling at 20 per minute. One login costs two
(the `/login` redirect and the `/callback`), so a single address gets
about 10 logins a minute sustained, plus the initial burst. IPv6
clients are keyed per /64, since one subscriber typically holds a whole
/64. There is no per-account lockout — the limit throttles a source
address, never a user, so it can't be turned into a targeted lockout.

The thresholds aren't configurable. They're generous for a household or
a small team, but an office behind a single NAT address logging in en
masse at the same minute can hit them and see "Too many requests" for a
few seconds; `/verify` — every request to an already-signed-in app — is
never rate limited, so existing sessions are unaffected. The client
address comes from the last hop of `X-Forwarded-For`, i.e. what Caddy
itself observed; a second proxy layer or CDN in front of Caddy would
collapse everyone behind it into one bucket unless Caddy is configured
to trust that layer's forwarded address.

## Caddy

See [`deploy/Caddyfile`](../deploy/Caddyfile) for a fully-commented
reference (validated with `caddy adapt`). The shape is: one plain
`reverse_proxy` block for the auth subdomain, and one `forward_auth`
block per protected app with an explicit `handle_response` for the 401
case — `forward_auth` does not redirect on non-2xx by default, it relays
the response verbatim, so without that block a denied request would show
authgate's raw 401 instead of sending the user to `/login`. The 401
carries the login URL to redirect to in `X-Login-Url` (with the original
request URL query-encoded inside `rd`); use
`redir * {http.reverse_proxy.header.X-Login-Url} 302` rather than
splicing `{uri}` into a query string yourself, which breaks on any `&`
in the original request.

Match that `handle_response` on *both* the 401 status and the presence
of `X-Login-Url`, as the reference file does. Only a GET (or HEAD) can
be replayed by sending the browser through login and back; a POST, PUT
or DELETE whose session expired would come out of that redirect chain
as a bodiless GET of its action URL. For those authgate answers a 401
*without* `X-Login-Url` and a plain "session expired, please go back
and resubmit" page, which Caddy relays as-is. The submitted body is not
buffered or replayed — that's an accepted limitation.

One more trust-boundary note: the session cookie is scoped to
`Domain=.<base_domain>` — that's what makes single sign-on across the
apps work — so every subdomain under a base domain is *same-site* as far
as the browser is concerned. authgate's own state-changing routes
(`/logout`, `/sessions/revoke`) additionally check `Origin` /
`Sec-Fetch-Site` so a compromised sibling app can't drive them, but a
sibling app can still *set* a cookie for the whole base domain. Only put
apps under one base domain that you'd trust with each other's sessions.

The same domain scoping means the browser sends `authgate_session` to
every app under the base domain, and `forward_auth` passes the original
request — cookie included — on to the backend. A backend that logs,
leaks, or is compromised could therefore replay that cookie as a
single-sign-on session against every sibling app. No backend ever needs
the cookie (identity arrives in the `X-Auth-*` headers), so the
reference Caddyfile strips it with two `header_up Cookie` rewrites on
each app's `reverse_proxy`:

```caddyfile
reverse_proxy localhost:9000 {
	header_up Cookie ";\s*authgate_session=[^;]*" ""
	header_up Cookie "^authgate_session=[^;]*;?\s*" ""
}
```

The first pattern removes the cookie from the middle or end of the
`Cookie` header, the second from the start; other cookies pass through
untouched. Keep both lines on every app block.

**Requires Caddy v2.11.2 or newer.** Caddy 2.10.0 through 2.11.1 carry
[GHSA-7r4p-vjf4-gxv4](https://github.com/caddyserver/caddy/security/advisories/GHSA-7r4p-vjf4-gxv4):
`copy_headers` only overwrites a client-supplied header when the auth
response includes that header, so a request that arrived with its own
`X-Auth-User` would reach the backend with it intact whenever authgate
had nothing to forward. authgate defends in depth by sending all three
`X-Auth-*` headers on every successful `/verify` — empty when the host has
`forward_identity_headers = false`, on bypass paths, or when a claim is
absent — so the overwrite always happens. Run a patched Caddy anyway, and
keep `copy_headers X-Auth-User X-Auth-Email X-Auth-Groups` on every
protected host, not just the ones that forward identity. Verified against
v2.11.4.

## Observability

JSON logs go to stdout always; level is controlled by `RUST_LOG`
(defaults to `info`). Set `otel_endpoint` in `[global]` to also export
logs via OTLP/gRPC to a collector. See the [runbook](runbook.md) for what
to look for when diagnosing an auth failure.

## What's explicitly not supported

Per the plan's "Deferred" list: no multi-instance/shared session state,
no zero-downtime key rotation (rotating `cookie_signing_key` or
`refresh_token_encryption_key` invalidates all existing sessions — see
the [runbook](runbook.md)'s rotation section for the safe procedure), no
retry/backoff if the IdP is unreachable at login (you get a plain error
page), and no central "logout everywhere" across multiple base domains.
