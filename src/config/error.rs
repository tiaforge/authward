use std::path::PathBuf;

/// A single, field-specific config problem. Callers accumulate these into a
/// `Vec<ConfigError>` so a user fixing config sees every mistake at once,
/// instead of playing whack-a-mole one error per run.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file `{path}`: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse `{path}` as TOML: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: Box<toml::de::Error>,
    },

    #[error(
        "{scope}: `idp` references `{idp}`, but no `[idp.\"{idp}\"]` block exists \
         (defined: {})",
        fmt_list(available)
    )]
    UnknownIdp {
        scope: String,
        idp: String,
        available: Vec<String>,
    },

    #[error(
        "domain `{domain}`: `idp` is not set and more than one `[idp]` block \
         exists — set it to one of: {}",
        fmt_list(available)
    )]
    DomainMissingIdp {
        domain: String,
        available: Vec<String>,
    },

    #[error(
        "domain `{domain}`: no `[idp.\"...\"]` block is defined — add one with \
         the provider's discovery_url, client_id and client_secret"
    )]
    NoIdpDefined { domain: String },

    #[error(
        "host `{host}` is not under any configured domain (defined: {}) — add a \
         `[domain.\"...\"]` block whose name is a DNS suffix of the host, or fix \
         the hostname",
        fmt_list(domains)
    )]
    HostNotUnderAnyDomain { host: String, domains: Vec<String> },

    #[error(
        "host `{host}`: `domain` references `{domain}`, but no \
         `[domain.\"{domain}\"]` block exists"
    )]
    UnknownDomain { host: String, domain: String },

    #[error(
        "host `{host}`: `domain` is `{domain}`, which is not a DNS suffix of the \
         hostname — the session cookie is scoped to `Domain=.{domain}`, so the \
         browser would never send it to this host"
    )]
    HostDomainMismatch { host: String, domain: String },

    #[error(
        "domain `{domain}`: `auth_subdomain` (`{auth_subdomain}`) is not a valid \
         hostname (`https://{auth_subdomain}/callback` doesn't parse as a URL)"
    )]
    InvalidAuthSubdomain {
        domain: String,
        auth_subdomain: String,
    },

    #[error("idp `{idp}`: `discovery_url` (`{url}`) is not a valid URL: {source}")]
    InvalidDiscoveryUrl {
        idp: String,
        url: String,
        #[source]
        source: url::ParseError,
    },

    #[error(
        "host `{host}`: bypass path `{path}` must start with `/` (matched as \
         an absolute path, optionally ending in `/*` to match that path and \
         everything under it)"
    )]
    BypassPathMustBeAbsolute { host: String, path: String },

    #[error(
        "host `{host}`: bypass path `{path}` must not contain a query string \
         (`?`) or fragment (`#`) — bypass matching is exact-path-only and \
         those characters are stripped from the real request before matching"
    )]
    BypassPathHasQueryOrFragment { host: String, path: String },

    #[error(
        "host `{host}`: bypass path `{path}` contains `*` somewhere other than \
         a trailing `/*` — the only supported wildcard form is a path ending \
         in `/*`, which matches that path and everything under it (e.g. \
         `/share/*`); `**`, a mid-path `*`, or more than one `*` are not \
         supported"
    )]
    BypassPathWildcardMustBeSuffix { host: String, path: String },

    #[error("host `{host}`: `token_header` `{header}` can't be used: {reason}")]
    InvalidTokenHeader {
        host: String,
        header: String,
        reason: &'static str,
    },

    #[error(
        "global: `cookie_signing_key` is not set — provide it in `[global]` \
         or via the `AUTHWARD_COOKIE_KEY` environment variable"
    )]
    MissingCookieSigningKey,

    #[error(
        "global: `refresh_token_encryption_key` is not set — provide it in \
         `[global]` or via the `AUTHWARD_REFRESH_KEY` environment variable"
    )]
    MissingRefreshKey,

    #[error(
        "global: `cookie_signing_key` and `refresh_token_encryption_key` must \
         not be the same value — they exist as separate keys for \
         defense-in-depth and sharing one defeats that"
    )]
    KeysMustDiffer,

    #[error(
        "global: `{name}` is {len} bytes long but must be at least {min} — use \
         random data (32 random bytes hex-encoded, as `authward init` \
         generates), never a passphrase"
    )]
    KeyTooShort {
        name: &'static str,
        len: usize,
        min: usize,
    },

    #[error(
        "config file `{path}` contains secret key material in `[global]` but \
         is readable by group or other (mode {mode:o}) — run `chmod 600 \
         {path}` or move the keys to environment variables instead"
    )]
    ConfigFilePermissionsTooOpen { path: PathBuf, mode: u32 },

    #[error(
        "{scope}: `{url}` uses plain http — the OIDC client secret, \
         authorization codes and refresh tokens travel to this provider, so \
         it must be https (plain http is only allowed for loopback addresses \
         in local development)"
    )]
    InsecureProviderUrl { scope: String, url: String },

    #[error("global: `session_max_age_seconds` must be greater than zero")]
    InvalidSessionMaxAge,

    #[error(
        "global: `listen_addr` (`{value}`) is not a valid `host:port` \
         socket address: {source}"
    )]
    InvalidListenAddr {
        value: String,
        #[source]
        source: std::net::AddrParseError,
    },
}

fn fmt_list(names: &[String]) -> String {
    if names.is_empty() {
        return "none".to_string();
    }
    let mut sorted: Vec<&str> = names.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted
        .iter()
        .map(|n| format!("`{n}`"))
        .collect::<Vec<_>>()
        .join(", ")
}
