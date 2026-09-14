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
        "host `{host}`: `base_domain` references `{base_domain}`, but no \
         `[base_domain.\"{base_domain}\"]` block exists"
    )]
    UnknownBaseDomain { host: String, base_domain: String },

    #[error(
        "fallback: `base_domain` references `{base_domain}`, but no \
         `[base_domain.\"{base_domain}\"]` block exists"
    )]
    FallbackUnknownBaseDomain { base_domain: String },

    #[error(
        "base_domain `{base_domain}`: `provider.discovery_url` (`{url}`) is not a valid URL: {source}"
    )]
    InvalidDiscoveryUrl {
        base_domain: String,
        url: String,
        #[source]
        source: url::ParseError,
    },

    #[error("host `{host}`: `provider.discovery_url` (`{url}`) is not a valid URL: {source}")]
    InvalidHostDiscoveryUrl {
        host: String,
        url: String,
        #[source]
        source: url::ParseError,
    },

    #[error(
        "host `{host}`: bypass path `{path}` must start with `/` (it is matched \
         as an absolute path, not a prefix or pattern)"
    )]
    BypassPathMustBeAbsolute { host: String, path: String },

    #[error(
        "host `{host}`: bypass path `{path}` must not contain a query string \
         (`?`) or fragment (`#`) — bypass matching is exact-path-only and \
         those characters are stripped from the real request before matching"
    )]
    BypassPathHasQueryOrFragment { host: String, path: String },

    #[error(
        "global: `cookie_signing_key` is not set — provide it in `[global]` \
         or via the `AUTHGATE_COOKIE_KEY` environment variable"
    )]
    MissingCookieSigningKey,

    #[error(
        "global: `refresh_token_encryption_key` is not set — provide it in \
         `[global]` or via the `AUTHGATE_REFRESH_KEY` environment variable"
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
         random data (32 random bytes hex-encoded, as `authgate init` \
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
        "host `{host}`: `provider` override is missing `{field}` — when a \
         host overrides `[host.\"{host}\".provider]` at all, it must specify the \
         full provider (discovery_url, client_id, client_secret); partial \
         overrides aren't supported since a mismatched client_id/secret pair \
         would fail silently at login time instead of at startup"
    )]
    IncompleteProviderOverride { host: String, field: &'static str },

    #[error(
        "fallback: `provider` override is missing `{field}` (see the \
         per-host provider-override error for why partial overrides aren't \
         allowed)"
    )]
    IncompleteFallbackProviderOverride { field: &'static str },

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
