//! Structures deserialized directly from the TOML config file, before
//! inheritance/env-var resolution. Every field a host, a domain's fallback
//! or a domain can omit (to inherit from its domain, or fall back to a
//! default) is `Option`.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RawConfig {
    #[serde(default)]
    pub global: RawGlobal,
    #[serde(default, rename = "idp")]
    pub idps: HashMap<String, RawIdp>,
    #[serde(default, rename = "domain")]
    pub domains: HashMap<String, RawDomain>,
    #[serde(default, rename = "host")]
    pub hosts: HashMap<String, RawHost>,
}

#[derive(Debug, Deserialize)]
pub struct RawGlobal {
    pub cookie_signing_key: Option<String>,
    pub refresh_token_encryption_key: Option<String>,
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: PathBuf,
    #[serde(default = "default_session_ttl_fallback_seconds")]
    pub session_ttl_fallback_seconds: u64,
    /// Hard cap on how long a session lives after login, regardless of
    /// how many silent refreshes succeed. Bounds the window a stolen
    /// session cookie stays usable.
    #[serde(default = "default_session_max_age_seconds")]
    pub session_max_age_seconds: u64,
    /// Upper bound on the `Cache-Control: max-age` a successful `/verify`
    /// answer carries, for callers that cache it. `0` (the default) keeps
    /// every `/verify` answer `no-store`.
    #[serde(default)]
    pub verify_cache_max_age_seconds: u64,
    /// Bind each session to the client address seen at login (from
    /// `X-Forwarded-For`) and refuse it from any other address.
    #[serde(default = "default_bind_session_to_client_ip")]
    pub bind_session_to_client_ip: bool,
    pub otel_endpoint: Option<String>,
    /// Internal address the service listens on. Must only be reachable by
    /// the proxy (see Phase 11) — never expose this publicly.
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
}

impl Default for RawGlobal {
    fn default() -> Self {
        RawGlobal {
            cookie_signing_key: None,
            refresh_token_encryption_key: None,
            sqlite_path: default_sqlite_path(),
            session_ttl_fallback_seconds: default_session_ttl_fallback_seconds(),
            session_max_age_seconds: default_session_max_age_seconds(),
            verify_cache_max_age_seconds: 0,
            bind_session_to_client_ip: default_bind_session_to_client_ip(),
            otel_endpoint: None,
            listen_addr: default_listen_addr(),
        }
    }
}

fn default_bind_session_to_client_ip() -> bool {
    true
}

fn default_sqlite_path() -> PathBuf {
    PathBuf::from("authward.db")
}

fn default_session_ttl_fallback_seconds() -> u64 {
    3600
}

fn default_session_max_age_seconds() -> u64 {
    24 * 3600
}

fn default_listen_addr() -> String {
    "127.0.0.1:8080".to_string()
}

/// One `[idp."<name>"]` block: a registered OIDC client at one identity
/// provider. Domains and hosts reference it by name.
#[derive(Debug, Deserialize)]
pub struct RawIdp {
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret: String,
}

/// One `[domain."<name>"]` block.
#[derive(Debug, Deserialize)]
pub struct RawDomain {
    pub auth_subdomain: String,
    /// Which `[idp]` this domain's hosts authenticate against by default.
    /// May be omitted when exactly one `[idp]` block exists.
    pub idp: Option<String>,
    /// `[domain."<name>".fallback]`: applies to any host under this domain
    /// that has no `[host]` block of its own.
    pub fallback: Option<RawHostFields>,
}

/// One `bypass_paths` entry: either a bare path (unrestricted — matches
/// any request method, same as before this variant existed), or a table
/// restricting the bypass to specific HTTP methods.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RawBypassEntry {
    Path(String),
    Scoped {
        path: String,
        #[serde(default)]
        methods: Vec<String>,
    },
}

/// One `path_required_groups` entry: a path pattern (same syntax as
/// `bypass_paths`) and the group that overrides the host's own
/// `required_group` for requests matching it.
#[derive(Debug, Deserialize)]
pub struct RawPathRequiredGroup {
    pub path: String,
    pub required_group: String,
}

/// The per-host fields, shared by `[host."..."]` blocks and a domain's
/// `fallback` sub-table.
#[derive(Debug, Default, Deserialize)]
pub struct RawHostFields {
    /// Overrides the domain's default `[idp]` for this host only.
    pub idp: Option<String>,
    pub required_group: Option<String>,
    pub group_claim_name: Option<String>,
    #[serde(default)]
    pub bypass_paths: Vec<RawBypassEntry>,
    #[serde(default)]
    pub path_required_groups: Vec<RawPathRequiredGroup>,
    pub forward_identity_headers: Option<bool>,
    pub resource: Option<String>,
    pub required_scope: Option<String>,
    pub token_header: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RawHost {
    /// Normally inferred (the longest configured domain that is a DNS
    /// suffix of the hostname); explicit only to pick a shorter one when
    /// configured domains nest. Must still be a suffix of the hostname.
    pub domain: Option<String>,
    #[serde(flatten)]
    pub fields: RawHostFields,
}
