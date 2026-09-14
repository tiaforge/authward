mod error;
mod raw;

pub use error::ConfigError;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use raw::{RawBaseDomain, RawConfig, RawFallback, RawHost, RawProvider};
use url::Url;

/// Fully resolved, ready-to-use configuration: every host's fields are
/// already merged with its base domain's defaults, env-var key overrides are
/// applied, and everything referenced is known to exist.
#[derive(Debug, Clone)]
pub struct Config {
    pub global: Global,
    pub base_domains: HashMap<String, BaseDomain>,
    pub hosts: HashMap<String, ResolvedHost>,
    pub fallback: Option<ResolvedHost>,
}

impl Config {
    /// Resolves a (lowercased — see `host::resolve_incoming_host`)
    /// `X-Forwarded-Host`/`Host` value to its per-host config, falling
    /// back to `[fallback]` when the host has no entry of its own. `None`
    /// means neither exists, which per the plan's locked-in decision is a
    /// hard failure (log + 502), not a silent allow or deny.
    pub fn resolve_host(&self, host: &str) -> Option<&ResolvedHost> {
        self.hosts.get(host).or(self.fallback.as_ref())
    }

    /// Every distinct provider to discover at startup, keyed the way
    /// `ResolvedHost::provider_key` names it, with the base domain whose
    /// auth subdomain serves its `/callback`: each base domain's default,
    /// plus every host-level (and fallback) override.
    pub fn providers(&self) -> Vec<(String, &Provider, &BaseDomain)> {
        let mut out: Vec<(String, &Provider, &BaseDomain)> = self
            .base_domains
            .iter()
            .map(|(name, bd)| (name.clone(), &bd.provider, bd))
            .collect();
        for host in self.hosts.values().chain(self.fallback.iter()) {
            if self.base_domains.contains_key(&host.provider_key) {
                continue;
            }
            if let Some(bd) = self.base_domains.get(&host.base_domain) {
                out.push((host.provider_key.clone(), &host.provider, bd));
            }
        }
        out
    }
}

#[derive(Debug, Clone)]
pub struct Global {
    pub cookie_signing_key: String,
    pub refresh_token_encryption_key: String,
    pub sqlite_path: PathBuf,
    pub session_ttl_fallback: Duration,
    pub session_max_age: Duration,
    pub otel_endpoint: Option<String>,
    pub listen_addr: SocketAddr,
}

/// Whether a provider-side URL may be talked to: https anywhere, or plain
/// http only to a loopback address (a local mock/dev IdP). Applied to the
/// configured discovery URL and to every endpoint the discovery document
/// hands back, since those are where secrets and tokens actually go.
pub fn is_secure_provider_url(url: &Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => match url.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            Some(url::Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
            None => false,
        },
        _ => false,
    }
}

#[derive(Debug, Clone)]
pub struct Provider {
    pub discovery_url: Url,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone)]
pub struct BaseDomain {
    pub name: String,
    pub auth_subdomain: String,
    pub provider: Provider,
}

/// A host's config after inheriting anything it didn't explicitly set from
/// its base domain. `host` is `None` for the synthetic entry built from the
/// `[fallback]` block, which applies to any request whose `Host` /
/// `X-Forwarded-Host` doesn't match a configured base domain or host.
#[derive(Debug, Clone)]
pub struct ResolvedHost {
    pub host: Option<String>,
    pub base_domain: String,
    pub provider: Provider,
    /// Which discovered provider this host authenticates against: the
    /// base domain's name when inheriting its provider, `host:<name>` for
    /// a host-level override, `fallback` for the fallback's. Keys the
    /// OIDC client / JWKS cache maps in `AppState`, and is recorded on
    /// every session so a login at one provider is never accepted by a
    /// host that uses another.
    pub provider_key: String,
    pub required_group: Option<String>,
    pub group_claim_name: String,
    pub bypass_paths: Vec<String>,
    pub forward_identity_headers: bool,
    pub resource: Option<String>,
    pub required_scope: Option<String>,
}

const DEFAULT_GROUP_CLAIM_NAME: &str = "groups";
const MIN_KEY_BYTES: usize = 32;

/// Load, resolve and validate the config file at `path`. Env vars
/// `AUTHWARD_COOKIE_KEY` / `AUTHWARD_REFRESH_KEY` take precedence
/// over the corresponding `[global]` values when set.
///
/// On any problem this returns every error found, not just the first, so a
/// user fixing config sees the whole list in one run.
pub fn load(path: &Path) -> Result<Config, Vec<ConfigError>> {
    let text = std::fs::read_to_string(path).map_err(|source| {
        vec![ConfigError::Io {
            path: path.to_path_buf(),
            source,
        }]
    })?;

    let raw: RawConfig = toml::from_str(&text).map_err(|source| {
        vec![ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        }]
    })?;

    resolve(raw, path)
}

fn resolve(raw: RawConfig, path: &Path) -> Result<Config, Vec<ConfigError>> {
    let mut errors = Vec::new();

    let global = resolve_global(&raw, path, &mut errors);

    // Host/base-domain names are lowercased once here so every downstream
    // lookup (by `X-Forwarded-Host`, itself lowercased at ingress — see
    // `host::resolve_incoming_host`) is a plain case-sensitive match,
    // rather than repeating case-insensitive comparisons at every call
    // site (the plan's locked-in decision, closing the class of bug where
    // mixed-case hosts silently miss their config).
    let mut base_domains = HashMap::new();
    for (name, raw_bd) in &raw.base_domains {
        match resolve_base_domain(name, raw_bd) {
            Ok(bd) => {
                base_domains.insert(name.to_ascii_lowercase(), bd);
            }
            Err(e) => errors.push(e),
        }
    }

    let mut hosts = HashMap::new();
    for (host_name, raw_host) in &raw.hosts {
        match resolve_host(host_name, raw_host, &base_domains) {
            Ok(resolved) => {
                hosts.insert(host_name.to_ascii_lowercase(), resolved);
            }
            Err(mut e) => errors.append(&mut e),
        }
    }

    let fallback = match &raw.fallback {
        None => None,
        Some(raw_fb) => match resolve_fallback(raw_fb, &base_domains) {
            Ok(resolved) => Some(resolved),
            Err(mut e) => {
                errors.append(&mut e);
                None
            }
        },
    };

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(Config {
        // global is only `None`-free once errors is empty; resolve_global
        // pushes onto `errors` and returns a placeholder on failure, so this
        // unwrap is safe here.
        global: global.expect("global resolved without error"),
        base_domains,
        hosts,
        fallback,
    })
}

fn resolve_global(raw: &RawConfig, path: &Path, errors: &mut Vec<ConfigError>) -> Option<Global> {
    let cookie_signing_key = std::env::var("AUTHWARD_COOKIE_KEY")
        .ok()
        .or_else(|| raw.global.cookie_signing_key.clone());
    let refresh_token_encryption_key = std::env::var("AUTHWARD_REFRESH_KEY")
        .ok()
        .or_else(|| raw.global.refresh_token_encryption_key.clone());

    // Any key material that came from the config file itself (not env)
    // means the file must not be group/other readable.
    let key_in_file = raw.global.cookie_signing_key.is_some()
        || raw.global.refresh_token_encryption_key.is_some();
    if key_in_file && let Ok(metadata) = std::fs::metadata(path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = metadata.permissions().mode();
            if mode & 0o077 != 0 {
                errors.push(ConfigError::ConfigFilePermissionsTooOpen {
                    path: path.to_path_buf(),
                    mode: mode & 0o777,
                });
            }
        }
    }

    let mut ok = true;
    if cookie_signing_key.is_none() {
        errors.push(ConfigError::MissingCookieSigningKey);
        ok = false;
    }
    if refresh_token_encryption_key.is_none() {
        errors.push(ConfigError::MissingRefreshKey);
        ok = false;
    }
    if let (Some(a), Some(b)) = (&cookie_signing_key, &refresh_token_encryption_key)
        && a == b
    {
        errors.push(ConfigError::KeysMustDiffer);
        ok = false;
    }
    // `cookie::Key::derive_from` panics below 32 bytes; catching it here
    // turns that into a config error alongside everything else. It's a
    // floor, not an entropy check — a 32-byte passphrase still passes.
    for (name, key) in [
        ("cookie_signing_key", &cookie_signing_key),
        (
            "refresh_token_encryption_key",
            &refresh_token_encryption_key,
        ),
    ] {
        if let Some(key) = key
            && key.len() < MIN_KEY_BYTES
        {
            errors.push(ConfigError::KeyTooShort {
                name,
                len: key.len(),
                min: MIN_KEY_BYTES,
            });
            ok = false;
        }
    }

    if raw.global.session_max_age_seconds == 0 {
        errors.push(ConfigError::InvalidSessionMaxAge);
        ok = false;
    }

    let listen_addr = match raw.global.listen_addr.parse::<SocketAddr>() {
        Ok(addr) => Some(addr),
        Err(source) => {
            errors.push(ConfigError::InvalidListenAddr {
                value: raw.global.listen_addr.clone(),
                source,
            });
            ok = false;
            None
        }
    };

    if !ok {
        return None;
    }

    Some(Global {
        cookie_signing_key: cookie_signing_key.unwrap(),
        refresh_token_encryption_key: refresh_token_encryption_key.unwrap(),
        sqlite_path: raw.global.sqlite_path.clone(),
        session_ttl_fallback: Duration::from_secs(raw.global.session_ttl_fallback_seconds),
        session_max_age: Duration::from_secs(raw.global.session_max_age_seconds),
        otel_endpoint: raw.global.otel_endpoint.clone(),
        listen_addr: listen_addr.unwrap(),
    })
}

fn resolve_base_domain(name: &str, raw: &RawBaseDomain) -> Result<BaseDomain, ConfigError> {
    let discovery_url = Url::parse(&raw.provider.discovery_url).map_err(|source| {
        ConfigError::InvalidDiscoveryUrl {
            base_domain: name.to_string(),
            url: raw.provider.discovery_url.clone(),
            source,
        }
    })?;
    if !is_secure_provider_url(&discovery_url) {
        return Err(ConfigError::InsecureProviderUrl {
            scope: format!("base_domain `{name}`"),
            url: raw.provider.discovery_url.clone(),
        });
    }

    Ok(BaseDomain {
        name: name.to_string(),
        auth_subdomain: raw.auth_subdomain.clone(),
        provider: Provider {
            discovery_url,
            client_id: raw.provider.client_id.clone(),
            client_secret: raw.provider.client_secret.clone(),
        },
    })
}

/// A host-level `provider` override table must set all three fields — see
/// `ConfigError::IncompleteProviderOverride` for why partial overrides are
/// rejected rather than merged field-by-field.
fn resolve_provider_override(raw: &RawProvider, host: &str) -> Result<Provider, ConfigError> {
    if raw.discovery_url.is_empty() {
        return Err(ConfigError::IncompleteProviderOverride {
            host: host.to_string(),
            field: "discovery_url",
        });
    }
    if raw.client_id.is_empty() {
        return Err(ConfigError::IncompleteProviderOverride {
            host: host.to_string(),
            field: "client_id",
        });
    }
    if raw.client_secret.is_empty() {
        return Err(ConfigError::IncompleteProviderOverride {
            host: host.to_string(),
            field: "client_secret",
        });
    }
    let discovery_url =
        Url::parse(&raw.discovery_url).map_err(|source| ConfigError::InvalidHostDiscoveryUrl {
            host: host.to_string(),
            url: raw.discovery_url.clone(),
            source,
        })?;
    if !is_secure_provider_url(&discovery_url) {
        return Err(ConfigError::InsecureProviderUrl {
            scope: format!("host `{host}`"),
            url: raw.discovery_url.clone(),
        });
    }
    Ok(Provider {
        discovery_url,
        client_id: raw.client_id.clone(),
        client_secret: raw.client_secret.clone(),
    })
}

fn validate_bypass_path(host: &str, path: &str, errors: &mut Vec<ConfigError>) {
    if !path.starts_with('/') {
        errors.push(ConfigError::BypassPathMustBeAbsolute {
            host: host.to_string(),
            path: path.to_string(),
        });
    }
    if path.contains('?') || path.contains('#') {
        errors.push(ConfigError::BypassPathHasQueryOrFragment {
            host: host.to_string(),
            path: path.to_string(),
        });
    }
}

fn resolve_host(
    host_name: &str,
    raw: &RawHost,
    base_domains: &HashMap<String, BaseDomain>,
) -> Result<ResolvedHost, Vec<ConfigError>> {
    let mut errors = Vec::new();

    let base_domain_key = raw.base_domain.to_ascii_lowercase();
    let base_domain = match base_domains.get(&base_domain_key) {
        Some(bd) => Some(bd),
        None => {
            errors.push(ConfigError::UnknownBaseDomain {
                host: host_name.to_string(),
                base_domain: raw.base_domain.clone(),
            });
            None
        }
    };

    let provider = match (&raw.provider, base_domain) {
        (Some(raw_provider), _) => resolve_provider_override(raw_provider, host_name)
            .map_err(|e| errors.push(e))
            .ok(),
        (None, Some(bd)) => Some(bd.provider.clone()),
        (None, None) => None,
    };

    for path in &raw.bypass_paths {
        validate_bypass_path(host_name, path, &mut errors);
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let provider_key = if raw.provider.is_some() {
        format!("host:{}", host_name.to_ascii_lowercase())
    } else {
        base_domain_key.clone()
    };
    Ok(ResolvedHost {
        host: Some(host_name.to_ascii_lowercase()),
        base_domain: base_domain_key,
        provider: provider.expect("provider resolved without error"),
        provider_key,
        required_group: raw.required_group.clone(),
        group_claim_name: raw
            .group_claim_name
            .clone()
            .unwrap_or_else(|| DEFAULT_GROUP_CLAIM_NAME.to_string()),
        bypass_paths: raw.bypass_paths.clone(),
        forward_identity_headers: raw.forward_identity_headers.unwrap_or(false),
        resource: raw.resource.clone(),
        required_scope: raw.required_scope.clone(),
    })
}

fn resolve_fallback(
    raw: &RawFallback,
    base_domains: &HashMap<String, BaseDomain>,
) -> Result<ResolvedHost, Vec<ConfigError>> {
    let mut errors = Vec::new();

    let base_domain_key = raw.base_domain.to_ascii_lowercase();
    let base_domain = match base_domains.get(&base_domain_key) {
        Some(bd) => Some(bd),
        None => {
            errors.push(ConfigError::FallbackUnknownBaseDomain {
                base_domain: raw.base_domain.clone(),
            });
            None
        }
    };

    let provider = match (&raw.provider, base_domain) {
        (Some(raw_provider), _) => resolve_fallback_provider_override(raw_provider)
            .map_err(|e| errors.push(e))
            .ok(),
        (None, Some(bd)) => Some(bd.provider.clone()),
        (None, None) => None,
    };

    for path in &raw.bypass_paths {
        validate_bypass_path("<fallback>", path, &mut errors);
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    let provider_key = if raw.provider.is_some() {
        "fallback".to_string()
    } else {
        base_domain_key.clone()
    };
    Ok(ResolvedHost {
        host: None,
        base_domain: base_domain_key,
        provider: provider.expect("provider resolved without error"),
        provider_key,
        required_group: raw.required_group.clone(),
        group_claim_name: raw
            .group_claim_name
            .clone()
            .unwrap_or_else(|| DEFAULT_GROUP_CLAIM_NAME.to_string()),
        bypass_paths: raw.bypass_paths.clone(),
        forward_identity_headers: raw.forward_identity_headers.unwrap_or(false),
        resource: raw.resource.clone(),
        required_scope: raw.required_scope.clone(),
    })
}

fn resolve_fallback_provider_override(raw: &RawProvider) -> Result<Provider, ConfigError> {
    if raw.discovery_url.is_empty() {
        return Err(ConfigError::IncompleteFallbackProviderOverride {
            field: "discovery_url",
        });
    }
    if raw.client_id.is_empty() {
        return Err(ConfigError::IncompleteFallbackProviderOverride { field: "client_id" });
    }
    if raw.client_secret.is_empty() {
        return Err(ConfigError::IncompleteFallbackProviderOverride {
            field: "client_secret",
        });
    }
    let discovery_url =
        Url::parse(&raw.discovery_url).map_err(|source| ConfigError::InvalidHostDiscoveryUrl {
            host: "<fallback>".to_string(),
            url: raw.discovery_url.clone(),
            source,
        })?;
    if !is_secure_provider_url(&discovery_url) {
        return Err(ConfigError::InsecureProviderUrl {
            scope: "fallback".to_string(),
            url: raw.discovery_url.clone(),
        });
    }
    Ok(Provider {
        discovery_url,
        client_id: raw.client_id.clone(),
        client_secret: raw.client_secret.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    fn write_config(contents: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        file
    }

    const VALID_TOML: &str = r#"
[global]
cookie_signing_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
refresh_token_encryption_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[base_domain."Example.COM"]
auth_subdomain = "auth.example.com"

[base_domain."Example.COM".provider]
discovery_url = "https://idp.example.com/.well-known/openid-configuration"
client_id = "client"
client_secret = "secret"

[host."App.Example.COM"]
base_domain = "Example.COM"
"#;

    #[test]
    fn mixed_case_host_and_base_domain_keys_normalize_to_lowercase() {
        let file = write_config(VALID_TOML);
        let cfg = load(file.path()).expect("valid config should load");

        assert!(
            cfg.base_domains.contains_key("example.com"),
            "base_domain key should be lowercased"
        );
        assert!(
            cfg.hosts.contains_key("app.example.com"),
            "host key should be lowercased"
        );
        assert_eq!(
            cfg.hosts["app.example.com"].base_domain, "example.com",
            "the base_domain reference should resolve case-insensitively too"
        );
    }

    #[test]
    fn malformed_toml_fails_hard_with_a_parse_error() {
        let file = write_config("this is not [ valid toml");
        let errors = load(file.path()).expect_err("malformed TOML must not load");
        assert!(matches!(errors.as_slice(), [ConfigError::Parse { .. }]));
    }

    #[test]
    fn host_referencing_an_unknown_base_domain_fails_hard() {
        let file = write_config(
            r#"
[global]
cookie_signing_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
refresh_token_encryption_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[host."app.example.com"]
base_domain = "nonexistent.example.com"
"#,
        );
        let errors = load(file.path()).expect_err("a dangling base_domain reference must not load");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::UnknownBaseDomain { .. }))
        );
    }

    #[test]
    fn short_keys_are_rejected_with_a_config_error_not_a_panic() {
        let file = write_config(
            r#"
[global]
cookie_signing_key = "changeme"
refresh_token_encryption_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#,
        );
        let errors = load(file.path()).expect_err("a short key must not load");
        assert!(errors.iter().any(|e| matches!(
            e,
            ConfigError::KeyTooShort {
                name: "cookie_signing_key",
                len: 8,
                ..
            }
        )));
    }

    #[test]
    fn host_provider_override_gets_its_own_provider_key() {
        let file = write_config(
            r#"
[global]
cookie_signing_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
refresh_token_encryption_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[base_domain."example.com"]
auth_subdomain = "auth.example.com"

[base_domain."example.com".provider]
discovery_url = "https://idp-a.example.com/.well-known/openid-configuration"
client_id = "a"
client_secret = "secret-a"

[host."app.example.com"]
base_domain = "example.com"

[host."Partner.example.com"]
base_domain = "example.com"

[host."Partner.example.com".provider]
discovery_url = "https://idp-b.example.com/.well-known/openid-configuration"
client_id = "b"
client_secret = "secret-b"
"#,
        );
        let cfg = load(file.path()).expect("valid config should load");
        assert_eq!(cfg.hosts["app.example.com"].provider_key, "example.com");
        assert_eq!(
            cfg.hosts["partner.example.com"].provider_key,
            "host:partner.example.com"
        );

        let mut keys: Vec<_> = cfg
            .providers()
            .into_iter()
            .map(|(k, p, bd)| (k, p.client_id.clone(), bd.auth_subdomain.clone()))
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                (
                    "example.com".to_string(),
                    "a".to_string(),
                    "auth.example.com".to_string()
                ),
                (
                    "host:partner.example.com".to_string(),
                    "b".to_string(),
                    "auth.example.com".to_string()
                ),
            ],
            "one provider per base domain plus one per override, each with its callback base domain"
        );
    }

    #[test]
    fn plain_http_provider_urls_are_rejected_except_loopback() {
        let file = write_config(
            r#"
[global]
cookie_signing_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
refresh_token_encryption_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

[base_domain."example.com"]
auth_subdomain = "auth.example.com"

[base_domain."example.com".provider]
discovery_url = "http://idp.example.com/.well-known/openid-configuration"
client_id = "client"
client_secret = "secret"
"#,
        );
        let errors = load(file.path()).expect_err("plain-http IdP must not load");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::InsecureProviderUrl { .. }))
        );

        for ok in [
            "https://idp.example.com/x",
            "http://127.0.0.1:9000/x",
            "http://localhost/x",
            "http://[::1]:9000/x",
        ] {
            assert!(is_secure_provider_url(&Url::parse(ok).unwrap()), "{ok}");
        }
        for bad in ["http://idp.example.com/x", "http://10.0.0.5/x", "ftp://x/y"] {
            assert!(!is_secure_provider_url(&Url::parse(bad).unwrap()), "{bad}");
        }
    }

    #[test]
    fn missing_keys_fail_hard_with_specific_errors() {
        let file = write_config("");
        let errors = load(file.path()).expect_err("a config with no keys at all must not load");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::MissingCookieSigningKey))
        );
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::MissingRefreshKey))
        );
    }
}
