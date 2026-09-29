mod error;
mod raw;

pub use error::ConfigError;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use openidconnect::RedirectUrl;
use raw::{
    RawBypassEntry, RawConfig, RawDomain, RawHost, RawHostFields, RawIdp, RawPathRequiredGroup,
};
use url::Url;

/// Fully resolved, ready-to-use configuration: every host's fields are
/// already merged with its domain's defaults, env-var key overrides are
/// applied, and everything referenced is known to exist.
#[derive(Debug, Clone)]
pub struct Config {
    pub global: Global,
    /// Every `[idp."<name>"]` block, keyed by name. This name is what
    /// `ResolvedHost::provider_key` and session rows record.
    pub idps: HashMap<String, Idp>,
    /// Every `[domain."<name>"]` block, keyed by lowercased name.
    pub base_domains: HashMap<String, BaseDomain>,
    /// Every `[host."<name>"]` block, keyed by lowercased hostname.
    pub hosts: HashMap<String, ResolvedHost>,
}

impl Config {
    /// The configured domain a (lowercased) hostname belongs to: the
    /// longest domain name that equals the host or is a DNS suffix of it.
    /// Cookie `Domain=` matching is suffix-based at any depth, so this is
    /// the only domain whose session cookie the browser would send to
    /// that host.
    pub fn base_domain_for_host(&self, host: &str) -> Option<&BaseDomain> {
        self.base_domains
            .values()
            .filter(|bd| is_under_domain(host, &bd.name))
            .max_by_key(|bd| bd.name.len())
    }

    /// Resolves a (lowercased — see `host::resolve_incoming_host`)
    /// `X-Forwarded-Host`/`Host` value to its per-host config: its own
    /// `[host]` block, else the `fallback` of the domain it falls under.
    /// `None` means neither exists, which per the plan's locked-in decision
    /// is a hard failure (log + 502), not a silent allow or deny.
    pub fn resolve_host(&self, host: &str) -> Option<&ResolvedHost> {
        self.hosts
            .get(host)
            .or_else(|| self.base_domain_for_host(host)?.fallback.as_ref())
    }
}

/// Whether `host` is `domain` itself or somewhere beneath it.
pub fn is_under_domain(host: &str, domain: &str) -> bool {
    host == domain
        || (host.len() > domain.len()
            && host.ends_with(domain)
            && host.as_bytes()[host.len() - domain.len() - 1] == b'.')
}

#[derive(Debug, Clone)]
pub struct Global {
    pub cookie_signing_key: String,
    pub refresh_token_encryption_key: String,
    pub sqlite_path: PathBuf,
    pub session_ttl_fallback: Duration,
    pub session_max_age: Duration,
    /// Cap on how long a caller may cache a successful `/verify` answer;
    /// zero disables caching. See `routes::auth::cacheable`.
    pub verify_cache_max_age: Duration,
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

/// One registered OIDC client at one identity provider (an `[idp]`
/// block). Discovered once at startup; the redirect URI is applied per
/// request from the domain the login runs on, so one IdP can serve any
/// number of domains as long as each domain's `/callback` is registered
/// at the provider.
#[derive(Debug, Clone)]
pub struct Idp {
    pub discovery_url: Url,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Clone)]
pub struct BaseDomain {
    pub name: String,
    pub auth_subdomain: String,
    /// `https://<auth_subdomain>/callback`, validated at load so building
    /// the per-request redirect URI can't fail.
    pub callback_url: Url,
    /// Name of the `[idp]` this domain's hosts use unless they override it.
    pub idp: String,
    /// `[domain."<name>".fallback]`: the config for any host under this
    /// domain that has no `[host]` block. `host` is `None` on it.
    pub fallback: Option<ResolvedHost>,
}

impl BaseDomain {
    pub fn redirect_url(&self) -> RedirectUrl {
        RedirectUrl::from_url(self.callback_url.clone())
    }
}

/// A host's config after inheriting anything it didn't explicitly set from
/// its domain. `host` is `None` for the entry built from a domain's
/// `fallback` sub-table.
#[derive(Debug, Clone)]
pub struct ResolvedHost {
    pub host: Option<String>,
    pub base_domain: String,
    /// Name of the `[idp]` this host authenticates against: its own `idp`
    /// override, else its domain's. Keys the OIDC client / JWKS cache maps
    /// in `AppState`, and is recorded on every session so a login at one
    /// provider is never accepted by a host that uses another.
    pub provider_key: String,
    pub required_group: Option<String>,
    pub group_claim_name: String,
    pub bypass_paths: Vec<crate::bypass::BypassEntry>,
    /// Per-path overrides of `required_group`: a request whose path
    /// matches an entry here is checked ONLY against that entry's group
    /// (not ANDed with `required_group` above) — the first entry in list
    /// order that matches wins. A path matched by `bypass_paths` skips
    /// auth entirely and never reaches this check at all.
    pub path_required_groups: Vec<PathRequiredGroup>,
    pub forward_identity_headers: bool,
    pub resource: Option<String>,
    pub required_scope: Option<String>,
    /// The request header an API token is read from (lowercased; header
    /// names are case-insensitive). Defaults to `X-Auth-Token`, carrying
    /// the raw token. Apps like Immich use `Authorization` for their own
    /// session token, so the default keeps out of that header's way. When
    /// this *is* `authorization`, the value must use the `Bearer` scheme.
    pub token_header: String,
}

/// One `path_required_groups` entry, already validated at config-load
/// time.
#[derive(Debug, Clone)]
pub struct PathRequiredGroup {
    pub path: String,
    pub required_group: String,
}

const DEFAULT_GROUP_CLAIM_NAME: &str = "groups";
pub const DEFAULT_TOKEN_HEADER: &str = "x-auth-token";
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

    // References are checked against what the file *declares*, not what
    // resolved: a domain pointing at an `[idp]` whose own block has an
    // error shouldn't also be told that block doesn't exist, and a second
    // `[idp]` that failed must still count when deciding whether a domain
    // may omit `idp`. Anything depending on a failed block is skipped; its
    // own problems surface once the block is fixed.
    let declared_idps: Vec<String> = raw.idps.keys().cloned().collect();
    let mut idps = HashMap::new();
    for (name, raw_idp) in &raw.idps {
        match resolve_idp(name, raw_idp) {
            Ok(idp) => {
                idps.insert(name.clone(), idp);
            }
            Err(e) => errors.push(e),
        }
    }
    let idps_ctx = IdpsCtx {
        declared: &declared_idps,
        resolved: &idps,
    };

    // Domain/host names are lowercased once here so every downstream
    // lookup (by `X-Forwarded-Host`, itself lowercased at ingress — see
    // `host::resolve_incoming_host`) is a plain case-sensitive match,
    // rather than repeating case-insensitive comparisons at every call
    // site (the plan's locked-in decision, closing the class of bug where
    // mixed-case hosts silently miss their config).
    let declared_domains: Vec<String> =
        raw.domains.keys().map(|n| n.to_ascii_lowercase()).collect();
    let mut base_domains = HashMap::new();
    for (name, raw_domain) in &raw.domains {
        match resolve_domain(name, raw_domain, &idps_ctx) {
            Ok(Some(bd)) => {
                base_domains.insert(bd.name.clone(), bd);
            }
            Ok(None) => {}
            Err(mut e) => errors.append(&mut e),
        }
    }

    let mut hosts = HashMap::new();
    for (host_name, raw_host) in &raw.hosts {
        match resolve_host(
            host_name,
            raw_host,
            &declared_domains,
            &base_domains,
            &idps_ctx,
        ) {
            Ok(Some(resolved)) => {
                hosts.insert(host_name.to_ascii_lowercase(), resolved);
            }
            Ok(None) => {}
            Err(mut e) => errors.append(&mut e),
        }
    }

    if !errors.is_empty() {
        return Err(errors);
    }

    Ok(Config {
        // global is only `None`-free once errors is empty; resolve_global
        // pushes onto `errors` and returns a placeholder on failure, so this
        // unwrap is safe here.
        global: global.expect("global resolved without error"),
        idps,
        base_domains,
        hosts,
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
        verify_cache_max_age: Duration::from_secs(raw.global.verify_cache_max_age_seconds),
        otel_endpoint: raw.global.otel_endpoint.clone(),
        listen_addr: listen_addr.unwrap(),
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
    if path.contains('*') && !(path.ends_with("/*") && path.matches('*').count() == 1) {
        errors.push(ConfigError::BypassPathWildcardMustBeSuffix {
            host: host.to_string(),
            path: path.to_string(),
        });
    }
}

const KNOWN_HTTP_METHODS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT", "TRACE",
];

/// Validates and normalizes a scoped bypass entry's `methods` list,
/// pushing errors for an empty list or an unrecognized method token, and
/// returning the uppercase-normalized methods regardless (so a partially
/// invalid list still resolves to *something* well-formed — the caller
/// discards it anyway once `errors` is non-empty).
fn validate_bypass_methods(
    host: &str,
    path: &str,
    methods: &[String],
    errors: &mut Vec<ConfigError>,
) -> Vec<String> {
    if methods.is_empty() {
        errors.push(ConfigError::BypassPathEmptyMethods {
            host: host.to_string(),
            path: path.to_string(),
        });
    }
    methods
        .iter()
        .map(|m| {
            let upper = m.to_ascii_uppercase();
            if !KNOWN_HTTP_METHODS.contains(&upper.as_str()) {
                errors.push(ConfigError::BypassPathInvalidMethod {
                    host: host.to_string(),
                    path: path.to_string(),
                    method: m.clone(),
                });
            }
            upper
        })
        .collect()
}

/// Path-shape rules for a `path_required_groups` entry — identical to
/// `validate_bypass_path`'s, plus the group name must be non-empty.
fn validate_path_required_group(
    host: &str,
    entry: &RawPathRequiredGroup,
    errors: &mut Vec<ConfigError>,
) {
    let path = &entry.path;
    if !path.starts_with('/') {
        errors.push(ConfigError::PathRequiredGroupMustBeAbsolute {
            host: host.to_string(),
            path: path.clone(),
        });
    }
    if path.contains('?') || path.contains('#') {
        errors.push(ConfigError::PathRequiredGroupHasQueryOrFragment {
            host: host.to_string(),
            path: path.clone(),
        });
    }
    if path.contains('*') && !(path.ends_with("/*") && path.matches('*').count() == 1) {
        errors.push(ConfigError::PathRequiredGroupWildcardMustBeSuffix {
            host: host.to_string(),
            path: path.clone(),
        });
    }
    if entry.required_group.trim().is_empty() {
        errors.push(ConfigError::PathRequiredGroupEmptyGroup {
            host: host.to_string(),
            path: path.clone(),
        });
    }
}

/// A token header must be a syntactically valid header name, and not one
/// whose meaning is already taken: `Cookie` carries the session cookie
/// and `Host` drives config lookup, so neither can carry a token.
fn resolve_token_header(host: &str, raw: Option<&str>, errors: &mut Vec<ConfigError>) -> String {
    let Some(raw) = raw else {
        return DEFAULT_TOKEN_HEADER.to_string();
    };
    let name = raw.trim().to_ascii_lowercase();
    let reason = if name.is_empty() {
        Some("it is empty")
    } else if axum::http::HeaderName::from_bytes(name.as_bytes()).is_err() {
        Some("it is not a valid HTTP header name")
    } else if matches!(
        name.as_str(),
        "cookie" | "host" | "x-forwarded-host" | "x-forwarded-uri"
    ) {
        Some("that header already has a meaning for authward")
    } else {
        None
    };
    if let Some(reason) = reason {
        errors.push(ConfigError::InvalidTokenHeader {
            host: host.to_string(),
            header: raw.to_string(),
            reason,
        });
    }
    name
}

fn resolve_idp(name: &str, raw: &RawIdp) -> Result<Idp, ConfigError> {
    let discovery_url =
        Url::parse(&raw.discovery_url).map_err(|source| ConfigError::InvalidDiscoveryUrl {
            idp: name.to_string(),
            url: raw.discovery_url.clone(),
            source,
        })?;
    if !is_secure_provider_url(&discovery_url) {
        return Err(ConfigError::InsecureProviderUrl {
            scope: format!("idp `{name}`"),
            url: raw.discovery_url.clone(),
        });
    }
    Ok(Idp {
        discovery_url,
        client_id: raw.client_id.clone(),
        client_secret: raw.client_secret.clone(),
    })
}

/// The `[idp]` blocks as seen by the blocks that reference them: every
/// declared name (for reference checks and error messages) and the ones
/// that actually resolved.
struct IdpsCtx<'a> {
    declared: &'a [String],
    resolved: &'a HashMap<String, Idp>,
}

/// Outcome of checking an `idp = "..."` reference.
enum IdpRef {
    /// Names a resolved `[idp]`.
    Ok(String),
    /// Names a declared `[idp]` whose own block failed; the referrer is
    /// skipped without an error of its own.
    Broken,
    /// Names nothing; an error was recorded.
    Unknown,
}

/// Checks an `idp = "..."` reference (`scope` names the block it sits in,
/// for the error message).
fn resolve_idp_ref(
    scope: &str,
    idp: &str,
    idps: &IdpsCtx,
    errors: &mut Vec<ConfigError>,
) -> IdpRef {
    if idps.resolved.contains_key(idp) {
        IdpRef::Ok(idp.to_string())
    } else if idps.declared.iter().any(|d| d == idp) {
        IdpRef::Broken
    } else {
        errors.push(ConfigError::UnknownIdp {
            scope: scope.to_string(),
            idp: idp.to_string(),
            available: idps.declared.to_vec(),
        });
        IdpRef::Unknown
    }
}

/// `Ok(None)` means the domain depends on an `[idp]` block that has its
/// own error, so nothing further can be said about it yet.
fn resolve_domain(
    name: &str,
    raw: &RawDomain,
    idps: &IdpsCtx,
) -> Result<Option<BaseDomain>, Vec<ConfigError>> {
    let mut errors = Vec::new();
    let name = name.to_ascii_lowercase();
    let scope = format!("domain `{name}`");

    let idp = match &raw.idp {
        Some(idp) => resolve_idp_ref(&scope, idp, idps, &mut errors),
        None => match idps.declared {
            [only] => resolve_idp_ref(&scope, only, idps, &mut errors),
            [] => {
                errors.push(ConfigError::NoIdpDefined {
                    domain: name.clone(),
                });
                IdpRef::Unknown
            }
            _ => {
                errors.push(ConfigError::DomainMissingIdp {
                    domain: name.clone(),
                    available: idps.declared.to_vec(),
                });
                IdpRef::Unknown
            }
        },
    };

    let callback_url = match Url::parse(&format!("https://{}/callback", raw.auth_subdomain)) {
        Ok(url)
            if url
                .host_str()
                .is_some_and(|h| h.eq_ignore_ascii_case(&raw.auth_subdomain)) =>
        {
            Some(url)
        }
        _ => {
            errors.push(ConfigError::InvalidAuthSubdomain {
                domain: name.clone(),
                auth_subdomain: raw.auth_subdomain.clone(),
            });
            None
        }
    };

    if !errors.is_empty() {
        return Err(errors);
    }
    let (IdpRef::Ok(idp), Some(callback_url)) = (idp, callback_url) else {
        // A broken idp reference: nothing more to say about this domain.
        return Ok(None);
    };

    // The fallback needs the domain's default idp; resolve it against a
    // provisional domain and attach afterwards.
    let mut domain = BaseDomain {
        name: name.clone(),
        auth_subdomain: raw.auth_subdomain.clone(),
        callback_url,
        idp,
        fallback: None,
    };
    if let Some(raw_fallback) = &raw.fallback {
        match resolve_host_fields(&format!("*.{name}"), None, raw_fallback, &domain, idps) {
            Ok(fallback) => domain.fallback = fallback,
            Err(mut e) => errors.append(&mut e),
        }
    }

    if errors.is_empty() {
        Ok(Some(domain))
    } else {
        Err(errors)
    }
}

/// `Ok(None)` means the host's domain (or idp) block has its own error,
/// so nothing further can be said about the host yet.
fn resolve_host(
    host_name: &str,
    raw: &RawHost,
    declared_domains: &[String],
    base_domains: &HashMap<String, BaseDomain>,
    idps: &IdpsCtx,
) -> Result<Option<ResolvedHost>, Vec<ConfigError>> {
    let host_name = host_name.to_ascii_lowercase();
    let domain_name = match &raw.domain {
        Some(explicit) => {
            let key = explicit.to_ascii_lowercase();
            if !declared_domains.contains(&key) {
                return Err(vec![ConfigError::UnknownDomain {
                    host: host_name,
                    domain: explicit.clone(),
                }]);
            }
            if !is_under_domain(&host_name, &key) {
                return Err(vec![ConfigError::HostDomainMismatch {
                    host: host_name,
                    domain: key,
                }]);
            }
            key
        }
        None => match declared_domains
            .iter()
            .filter(|name| is_under_domain(&host_name, name))
            .max_by_key(|name| name.len())
        {
            Some(name) => name.clone(),
            None => {
                return Err(vec![ConfigError::HostNotUnderAnyDomain {
                    host: host_name,
                    domains: declared_domains.to_vec(),
                }]);
            }
        },
    };
    let Some(domain) = base_domains.get(&domain_name) else {
        return Ok(None);
    };
    resolve_host_fields(
        &host_name,
        Some(host_name.clone()),
        &raw.fields,
        domain,
        idps,
    )
}

/// Shared by `[host]` blocks and a domain's `fallback`: merges the
/// per-host fields with the domain's defaults. `label` names the block in
/// error messages (`app.example.com`, or `*.example.com` for a fallback).
/// `Ok(None)` means the host's `idp` override names a block with its own
/// error.
fn resolve_host_fields(
    label: &str,
    host: Option<String>,
    raw: &RawHostFields,
    domain: &BaseDomain,
    idps: &IdpsCtx,
) -> Result<Option<ResolvedHost>, Vec<ConfigError>> {
    let mut errors = Vec::new();

    let provider_key = match &raw.idp {
        Some(idp) => resolve_idp_ref(&format!("host `{label}`"), idp, idps, &mut errors),
        None => IdpRef::Ok(domain.idp.clone()),
    };

    let mut bypass_paths = Vec::with_capacity(raw.bypass_paths.len());
    for entry in &raw.bypass_paths {
        match entry {
            RawBypassEntry::Path(path) => {
                validate_bypass_path(label, path, &mut errors);
                bypass_paths.push(crate::bypass::BypassEntry::unrestricted(path.clone()));
            }
            RawBypassEntry::Scoped { path, methods } => {
                validate_bypass_path(label, path, &mut errors);
                let methods = validate_bypass_methods(label, path, methods, &mut errors);
                bypass_paths.push(crate::bypass::BypassEntry {
                    path: path.clone(),
                    methods: Some(methods),
                });
            }
        }
    }

    let mut path_required_groups = Vec::with_capacity(raw.path_required_groups.len());
    for entry in &raw.path_required_groups {
        validate_path_required_group(label, entry, &mut errors);
        path_required_groups.push(PathRequiredGroup {
            path: entry.path.clone(),
            required_group: entry.required_group.clone(),
        });
    }

    let token_header = resolve_token_header(label, raw.token_header.as_deref(), &mut errors);

    if !errors.is_empty() {
        return Err(errors);
    }
    let provider_key = match provider_key {
        IdpRef::Ok(key) => key,
        IdpRef::Broken => return Ok(None),
        IdpRef::Unknown => unreachable!("an unknown idp reference records an error"),
    };

    Ok(Some(ResolvedHost {
        host,
        base_domain: domain.name.clone(),
        provider_key,
        required_group: raw.required_group.clone(),
        group_claim_name: raw
            .group_claim_name
            .clone()
            .unwrap_or_else(|| DEFAULT_GROUP_CLAIM_NAME.to_string()),
        bypass_paths,
        path_required_groups,
        forward_identity_headers: raw.forward_identity_headers.unwrap_or(false),
        resource: raw.resource.clone(),
        required_scope: raw.required_scope.clone(),
        token_header,
    }))
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

    const KEYS: &str = r#"
[global]
cookie_signing_key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
refresh_token_encryption_key = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
"#;

    const ONE_IDP: &str = r#"
[idp."main"]
discovery_url = "https://idp.example.com/.well-known/openid-configuration"
client_id = "client"
client_secret = "secret"
"#;

    fn load_str(body: &str) -> Result<Config, Vec<ConfigError>> {
        let file = write_config(&format!("{KEYS}{body}"));
        load(file.path())
    }

    #[test]
    fn mixed_case_host_and_domain_keys_normalize_to_lowercase() {
        let cfg = load_str(&format!(
            r#"{ONE_IDP}
[domain."Example.COM"]
auth_subdomain = "auth.example.com"

[host."App.Example.COM"]
"#
        ))
        .expect("valid config should load");

        assert!(cfg.base_domains.contains_key("example.com"));
        assert!(cfg.hosts.contains_key("app.example.com"));
        assert_eq!(cfg.hosts["app.example.com"].base_domain, "example.com");
        assert_eq!(cfg.hosts["app.example.com"].provider_key, "main");
        assert_eq!(
            cfg.base_domains["example.com"].callback_url.as_str(),
            "https://auth.example.com/callback"
        );
    }

    #[test]
    fn malformed_toml_fails_hard_with_a_parse_error() {
        let file = write_config("this is not [ valid toml");
        let errors = load(file.path()).expect_err("malformed TOML must not load");
        assert!(matches!(errors.as_slice(), [ConfigError::Parse { .. }]));
    }

    #[test]
    fn sole_idp_is_the_default_but_several_require_naming_one() {
        let cfg = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"
"#
        ))
        .expect("a single idp needs no reference");
        assert_eq!(cfg.base_domains["example.com"].idp, "main");

        let two = format!(
            r#"{ONE_IDP}
[idp."other"]
discovery_url = "https://idp-b.example.com/.well-known/openid-configuration"
client_id = "b"
client_secret = "s"
"#
        );
        let errors = load_str(&format!(
            r#"{two}
[domain."example.com"]
auth_subdomain = "auth.example.com"
"#
        ))
        .expect_err("two idps and no reference must not load");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::DomainMissingIdp { .. })),
            "{errors:?}"
        );

        let cfg = load_str(&format!(
            r#"{two}
[domain."example.com"]
auth_subdomain = "auth.example.com"
idp = "other"

[host."app.example.com"]

[host."b.example.com"]
idp = "main"
"#
        ))
        .expect("explicit references should load");
        assert_eq!(cfg.base_domains["example.com"].idp, "other");
        assert_eq!(cfg.hosts["app.example.com"].provider_key, "other");
        assert_eq!(cfg.hosts["b.example.com"].provider_key, "main");
    }

    #[test]
    fn unknown_idp_references_and_no_idp_at_all_fail_hard() {
        let errors = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"
idp = "typo"

[host."app.example.com"]
idp = "also-typo"
"#
        ))
        .expect_err("dangling idp references must not load");
        let unknown: Vec<_> = errors
            .iter()
            .filter_map(|e| match e {
                ConfigError::UnknownIdp { scope, idp, .. } => Some((scope.as_str(), idp.as_str())),
                _ => None,
            })
            .collect();
        assert!(
            unknown.contains(&("domain `example.com`", "typo")),
            "{errors:?}"
        );
        // The host can't resolve because its domain failed, so only the
        // domain's error is reported; that's fine as long as it's there.

        let errors = load_str(
            r#"
[domain."example.com"]
auth_subdomain = "auth.example.com"
"#,
        )
        .expect_err("a domain with no idp defined anywhere must not load");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::NoIdpDefined { .. })),
            "{errors:?}"
        );
    }

    #[test]
    fn host_domain_is_inferred_from_the_longest_matching_suffix() {
        let cfg = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[domain."corp.example.com"]
auth_subdomain = "auth.corp.example.com"

[host."app.example.com"]
[host."deep.app.example.com"]
[host."app.corp.example.com"]
[host."example.com"]

[host."wide.corp.example.com"]
domain = "example.com"
"#
        ))
        .expect("valid config should load");
        assert_eq!(cfg.hosts["app.example.com"].base_domain, "example.com");
        assert_eq!(cfg.hosts["deep.app.example.com"].base_domain, "example.com");
        assert_eq!(
            cfg.hosts["app.corp.example.com"].base_domain,
            "corp.example.com"
        );
        assert_eq!(cfg.hosts["example.com"].base_domain, "example.com");
        assert_eq!(
            cfg.hosts["wide.corp.example.com"].base_domain, "example.com",
            "an explicit shorter domain wins over inference"
        );
    }

    #[test]
    fn host_outside_every_domain_or_with_a_non_suffix_domain_fails_hard() {
        let errors = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[host."app.other.net"]

[host."notexample.com"]

[host."app.example.com"]
domain = "other.net"

[host."b.example.com"]
domain = "example.com.evil"
"#
        ))
        .expect_err("hosts outside their domain must not load");
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ConfigError::HostNotUnderAnyDomain { host, .. } if host == "app.other.net"
            )),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ConfigError::HostNotUnderAnyDomain { host, .. } if host == "notexample.com"
            )),
            "a plain suffix match without the dot must not count: {errors:?}"
        );
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ConfigError::UnknownDomain { host, .. } if host == "app.example.com"
            )),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ConfigError::UnknownDomain { host, .. } if host == "b.example.com"
            )),
            "{errors:?}"
        );

        let errors = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[domain."other.net"]
auth_subdomain = "auth.other.net"

[host."app.example.com"]
domain = "other.net"
"#
        ))
        .expect_err("an explicit domain that isn't a suffix must not load");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::HostDomainMismatch { .. })),
            "{errors:?}"
        );
    }

    #[test]
    fn fallback_nests_under_its_domain_and_only_covers_that_domain() {
        let cfg = load_str(&format!(
            r#"{ONE_IDP}
[idp."partner"]
discovery_url = "https://idp-b.example.com/.well-known/openid-configuration"
client_id = "b"
client_secret = "s"

[domain."example.com"]
auth_subdomain = "auth.example.com"
idp = "main"

[domain."example.com".fallback]
idp = "partner"
required_group = "users"

[domain."other.net"]
auth_subdomain = "auth.other.net"
idp = "main"

[host."admin.example.com"]
required_group = "admins"
"#
        ))
        .expect("valid config should load");

        let fallback = cfg.base_domains["example.com"]
            .fallback
            .as_ref()
            .expect("fallback attached to its domain");
        assert_eq!(fallback.host, None);
        assert_eq!(fallback.base_domain, "example.com");
        assert_eq!(fallback.provider_key, "partner");
        assert_eq!(fallback.required_group.as_deref(), Some("users"));
        assert!(cfg.base_domains["other.net"].fallback.is_none());

        assert_eq!(
            cfg.resolve_host("admin.example.com")
                .unwrap()
                .required_group
                .as_deref(),
            Some("admins"),
            "an explicit host block wins over the fallback"
        );
        assert_eq!(
            cfg.resolve_host("anything.example.com")
                .unwrap()
                .required_group
                .as_deref(),
            Some("users")
        );
        assert_eq!(
            cfg.resolve_host("deep.er.example.com")
                .unwrap()
                .provider_key,
            "partner"
        );
        assert!(
            cfg.resolve_host("unlisted.other.net").is_none(),
            "one domain's fallback must not cover another domain's hosts"
        );
        assert!(cfg.resolve_host("example.net").is_none());
    }

    #[test]
    fn fallback_errors_are_labelled_with_a_wildcard_host() {
        let errors = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[domain."example.com".fallback]
bypass_paths = ["no-slash"]
"#
        ))
        .expect_err("bad fallback fields must not load");
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ConfigError::BypassPathMustBeAbsolute { host, .. } if host == "*.example.com"
            )),
            "{errors:?}"
        );
    }

    #[test]
    fn trailing_wildcard_bypass_path_loads_without_error() {
        let cfg = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[host."app.example.com"]
bypass_paths = ["/share/*", "/healthz", "/*"]
"#
        ))
        .expect("wildcard bypass paths should load");
        let paths: Vec<&str> = cfg.hosts["app.example.com"]
            .bypass_paths
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        assert_eq!(paths, vec!["/share/*", "/healthz", "/*"]);
        assert!(
            cfg.hosts["app.example.com"]
                .bypass_paths
                .iter()
                .all(|e| e.methods.is_none()),
            "plain-string bypass_paths entries must be unrestricted"
        );
    }

    #[test]
    fn scoped_bypass_path_loads_and_normalizes_methods() {
        let cfg = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[host."app.example.com"]
bypass_paths = [
  "/healthz",
  {{ path = "/api/assets/*", methods = ["get", "Head"] }},
]
"#
        ))
        .expect("scoped bypass path should load");
        let entries = &cfg.hosts["app.example.com"].bypass_paths;
        assert_eq!(entries[0].path, "/healthz");
        assert_eq!(entries[0].methods, None);
        assert_eq!(entries[1].path, "/api/assets/*");
        assert_eq!(
            entries[1].methods,
            Some(vec!["GET".to_string(), "HEAD".to_string()])
        );
    }

    #[test]
    fn scoped_bypass_path_empty_methods_is_an_error() {
        let errors = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[host."app.example.com"]
bypass_paths = [{{ path = "/api/assets/*", methods = [] }}]
"#
        ))
        .expect_err("empty methods list should be rejected");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::BypassPathEmptyMethods { .. })),
            "{errors:?}"
        );
    }

    #[test]
    fn scoped_bypass_path_unknown_method_is_an_error() {
        let errors = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[host."app.example.com"]
bypass_paths = [{{ path = "/api/assets/*", methods = ["FETCH"] }}]
"#
        ))
        .expect_err("unknown method should be rejected");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::BypassPathInvalidMethod { method, .. } if method == "FETCH")),
            "{errors:?}"
        );
    }

    #[test]
    fn trailing_wildcard_path_required_group_loads_without_error() {
        let cfg = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[host."app.example.com"]
path_required_groups = [{{ path = "/admin/*", required_group = "admins" }}]
"#
        ))
        .expect("path_required_groups should load");
        let overrides = &cfg.hosts["app.example.com"].path_required_groups;
        assert_eq!(overrides.len(), 1);
        assert_eq!(overrides[0].path, "/admin/*");
        assert_eq!(overrides[0].required_group, "admins");
    }

    #[test]
    fn path_required_group_wildcard_must_be_a_trailing_slash_star() {
        for bad in ["/admin*", "/a/**", "/*/*"] {
            let errors = load_str(&format!(
                r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[host."app.example.com"]
path_required_groups = [{{ path = "{bad}", required_group = "admins" }}]
"#
            ))
            .expect_err(&format!("`{bad}` should be rejected"));
            assert!(
                errors.iter().any(|e| matches!(
                    e,
                    ConfigError::PathRequiredGroupWildcardMustBeSuffix { .. }
                )),
                "`{bad}`: {errors:?}"
            );
        }
    }

    #[test]
    fn path_required_group_empty_group_is_an_error() {
        let errors = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[host."app.example.com"]
path_required_groups = [{{ path = "/admin/*", required_group = "" }}]
"#
        ))
        .expect_err("empty required_group should be rejected");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::PathRequiredGroupEmptyGroup { .. })),
            "{errors:?}"
        );
    }

    #[test]
    fn bypass_path_wildcard_must_be_a_trailing_slash_star() {
        for bad in ["/share*", "/a/**", "/*/*", "/share/*/extra", "/a*/*"] {
            let errors = load_str(&format!(
                r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[host."app.example.com"]
bypass_paths = ["{bad}"]
"#
            ))
            .expect_err(&format!("`{bad}` should be rejected"));
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, ConfigError::BypassPathWildcardMustBeSuffix { .. })),
                "`{bad}`: {errors:?}"
            );
        }
    }

    #[test]
    fn token_header_defaults_and_rejects_reserved_or_malformed_names() {
        let cfg = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[host."app.example.com"]

[host."api.example.com"]
resource = "https://api.example.com/"
token_header = "Authorization"
"#
        ))
        .expect("valid token_header config should load");
        assert_eq!(
            cfg.hosts["app.example.com"].token_header,
            DEFAULT_TOKEN_HEADER
        );
        assert_eq!(cfg.hosts["api.example.com"].token_header, "authorization");

        for bad in ["Cookie", "host", "not a header", ""] {
            let errors = load_str(&format!(
                r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com"

[host."api.example.com"]
token_header = "{bad}"
"#
            ))
            .expect_err("bad token_header must not load");
            assert!(
                errors
                    .iter()
                    .any(|e| matches!(e, ConfigError::InvalidTokenHeader { .. })),
                "token_header {bad:?} should be rejected, got {errors:?}"
            );
        }
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
    fn plain_http_provider_urls_are_rejected_except_loopback() {
        let errors = load_str(
            r#"
[idp."main"]
discovery_url = "http://idp.example.com/.well-known/openid-configuration"
client_id = "client"
client_secret = "secret"
"#,
        )
        .expect_err("plain-http IdP must not load");
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
    fn invalid_auth_subdomain_is_a_config_error() {
        let errors = load_str(&format!(
            r#"{ONE_IDP}
[domain."example.com"]
auth_subdomain = "auth.example.com/with/path"
"#
        ))
        .expect_err("an auth_subdomain that isn't a bare hostname must not load");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::InvalidAuthSubdomain { .. })),
            "{errors:?}"
        );
    }

    /// A broken `[idp]` block still counts as declared: a domain that
    /// references it isn't told it doesn't exist, and a domain relying on
    /// the single-idp default doesn't silently get the other one.
    #[test]
    fn a_broken_idp_block_neither_vanishes_nor_cascades() {
        let errors = load_str(&format!(
            r#"{ONE_IDP}
[idp."broken"]
discovery_url = "http://idp.partner.net/.well-known/openid-configuration"
client_id = "b"
client_secret = "s"

[domain."example.com"]
auth_subdomain = "auth.example.com"

[domain."other.net"]
auth_subdomain = "auth.other.net"
idp = "broken"

[host."app.other.net"]
[host."api.example.com"]
idp = "broken"
"#
        ))
        .expect_err("a plain-http idp must not load");
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, ConfigError::InsecureProviderUrl { .. })),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| matches!(
                e,
                ConfigError::DomainMissingIdp { domain, available }
                    if domain == "example.com" && available.len() == 2
            )),
            "two idps are declared, so the default must not apply: {errors:?}"
        );
        assert!(
            !errors
                .iter()
                .any(|e| matches!(e, ConfigError::UnknownIdp { .. })),
            "referencing a declared-but-broken idp is not an unknown reference: {errors:?}"
        );
        assert!(
            !errors.iter().any(|e| matches!(
                e,
                ConfigError::UnknownDomain { .. } | ConfigError::HostNotUnderAnyDomain { .. }
            )),
            "hosts under a domain that failed are skipped, not misreported: {errors:?}"
        );
    }

    /// The copy-and-edit example shipped in the repo must always load.
    #[test]
    fn shipped_example_config_loads() {
        let example = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/config.toml"),
        )
        .unwrap();
        let file = write_config(&example);
        let cfg = load(file.path()).unwrap_or_else(|e| panic!("examples/config.toml: {e:?}"));
        assert_eq!(cfg.idps.len(), 1);
        assert_eq!(cfg.base_domains["example.com"].idp, "pocketid");
        assert_eq!(
            cfg.hosts["admin.example.com"].required_group.as_deref(),
            Some("admins")
        );
        assert_eq!(cfg.hosts["app.example.com"].provider_key, "pocketid");
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
