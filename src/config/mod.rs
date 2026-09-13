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

#[derive(Debug, Clone)]
pub struct Global {
    pub cookie_signing_key: String,
    pub refresh_token_encryption_key: String,
    pub sqlite_path: PathBuf,
    pub session_ttl_fallback: Duration,
    pub otel_endpoint: Option<String>,
    pub listen_addr: SocketAddr,
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
    pub required_group: Option<String>,
    pub group_claim_name: String,
    pub bypass_paths: Vec<String>,
    pub forward_identity_headers: bool,
    pub resource: Option<String>,
    pub required_scope: Option<String>,
}

const DEFAULT_GROUP_CLAIM_NAME: &str = "groups";

/// Load, resolve and validate the config file at `path`. Env vars
/// `FORWARD_AUTH_COOKIE_KEY` / `FORWARD_AUTH_REFRESH_KEY` take precedence
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

    let mut base_domains = HashMap::new();
    for (name, raw_bd) in &raw.base_domains {
        match resolve_base_domain(name, raw_bd) {
            Ok(bd) => {
                base_domains.insert(name.clone(), bd);
            }
            Err(e) => errors.push(e),
        }
    }

    let mut hosts = HashMap::new();
    for (host_name, raw_host) in &raw.hosts {
        match resolve_host(host_name, raw_host, &base_domains) {
            Ok(resolved) => {
                hosts.insert(host_name.clone(), resolved);
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
    let cookie_signing_key = std::env::var("FORWARD_AUTH_COOKIE_KEY")
        .ok()
        .or_else(|| raw.global.cookie_signing_key.clone());
    let refresh_token_encryption_key = std::env::var("FORWARD_AUTH_REFRESH_KEY")
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

    let base_domain = match base_domains.get(&raw.base_domain) {
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

    Ok(ResolvedHost {
        host: Some(host_name.to_string()),
        base_domain: raw.base_domain.clone(),
        provider: provider.expect("provider resolved without error"),
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

    let base_domain = match base_domains.get(&raw.base_domain) {
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

    Ok(ResolvedHost {
        host: None,
        base_domain: raw.base_domain.clone(),
        provider: provider.expect("provider resolved without error"),
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
    Ok(Provider {
        discovery_url,
        client_id: raw.client_id.clone(),
        client_secret: raw.client_secret.clone(),
    })
}
