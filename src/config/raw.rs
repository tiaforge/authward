//! Structures deserialized directly from the TOML config file, before
//! inheritance/env-var resolution. Every field a host or the fallback block
//! can omit (to inherit from its base domain, or fall back to a default) is
//! `Option`.

use std::collections::HashMap;
use std::path::PathBuf;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RawConfig {
    #[serde(default)]
    pub global: RawGlobal,
    #[serde(default, rename = "base_domain")]
    pub base_domains: HashMap<String, RawBaseDomain>,
    #[serde(default, rename = "host")]
    pub hosts: HashMap<String, RawHost>,
    pub fallback: Option<RawFallback>,
}

#[derive(Debug, Deserialize)]
pub struct RawGlobal {
    pub cookie_signing_key: Option<String>,
    pub refresh_token_encryption_key: Option<String>,
    #[serde(default = "default_sqlite_path")]
    pub sqlite_path: PathBuf,
    #[serde(default = "default_session_ttl_fallback_seconds")]
    pub session_ttl_fallback_seconds: u64,
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
            otel_endpoint: None,
            listen_addr: default_listen_addr(),
        }
    }
}

fn default_sqlite_path() -> PathBuf {
    PathBuf::from("forward-auth.db")
}

fn default_session_ttl_fallback_seconds() -> u64 {
    3600
}

fn default_listen_addr() -> String {
    "127.0.0.1:8080".to_string()
}

#[derive(Debug, Deserialize)]
pub struct RawProvider {
    pub discovery_url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Debug, Deserialize)]
pub struct RawBaseDomain {
    pub auth_subdomain: String,
    pub provider: RawProvider,
}

#[derive(Debug, Deserialize)]
pub struct RawHost {
    pub base_domain: String,
    /// Full override of the base domain's provider. If present, all three
    /// fields are required (see ConfigError::IncompleteProviderOverride) —
    /// we don't support merging individual provider fields.
    pub provider: Option<RawProvider>,
    pub required_group: Option<String>,
    pub group_claim_name: Option<String>,
    #[serde(default)]
    pub bypass_paths: Vec<String>,
    pub forward_identity_headers: Option<bool>,
    pub resource: Option<String>,
    pub required_scope: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RawFallback {
    pub base_domain: String,
    pub provider: Option<RawProvider>,
    pub required_group: Option<String>,
    pub group_claim_name: Option<String>,
    #[serde(default)]
    pub bypass_paths: Vec<String>,
    pub forward_identity_headers: Option<bool>,
    pub resource: Option<String>,
    pub required_scope: Option<String>,
}
