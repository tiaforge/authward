//! `authward init` — an interactive wizard that writes a starter config.
//!
//! Runs locally, once, using filesystem access the operator already has —
//! no network exposure, no bootstrapping problem (unlike a web-based setup
//! GUI, which would need either unauthenticated network-exposed surface or
//! its own separate auth story before OIDC itself is configured).

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use dialoguer::{Confirm, Input, Password};
use rand::RngExt;

pub fn run(output: &Path) -> Result<()> {
    println!("authward init — let's set up your first config.\n");

    if output.exists() {
        anyhow::bail!(
            "{} already exists — remove it or pass a different --output path if you want to \
             regenerate it, so this wizard never silently overwrites an existing config",
            output.display()
        );
    }

    let domain: String = Input::new()
        .with_prompt("Domain (e.g. example.com — every app under it shares one login)")
        .interact_text()?;

    let auth_subdomain: String = Input::new()
        .with_prompt("Auth subdomain")
        .default(format!("auth.{domain}"))
        .interact_text()?;

    let idp_name: String = Input::new()
        .with_prompt("Name for your identity provider (how the config refers to it)")
        .default("default".to_string())
        .interact_text()?;

    let discovery_url: String = Input::new()
        .with_prompt(
            "OIDC discovery URL (e.g. https://idp.example.com/.well-known/openid-configuration)",
        )
        .validate_with(|input: &String| -> Result<(), String> {
            url::Url::parse(input)
                .map(|_| ())
                .map_err(|e| e.to_string())
        })
        .interact_text()?;

    let client_id: String = Input::new().with_prompt("OIDC client ID").interact_text()?;
    let client_secret: String = Password::new()
        .with_prompt("OIDC client secret")
        .interact()?;

    let first_host: String = Input::new()
        .with_prompt("First app hostname to protect (e.g. app.example.com)")
        .validate_with(|input: &String| -> Result<(), String> {
            if authward_is_under_domain(input, &domain) {
                Ok(())
            } else {
                Err(format!(
                    "must be {domain} itself or a subdomain of it — the login cookie is scoped \
                     to that domain"
                ))
            }
        })
        .interact_text()?;

    let with_fallback = Confirm::new()
        .with_prompt(format!(
            "Protect every other host under {domain} with the same settings? (adds a fallback)"
        ))
        .default(false)
        .interact()?;

    let cookie_signing_key = random_key_hex();
    let refresh_token_encryption_key = random_key_hex();

    let toml = render_config(RenderInput {
        domain: &domain,
        auth_subdomain: &auth_subdomain,
        idp_name: &idp_name,
        discovery_url: &discovery_url,
        client_id: &client_id,
        client_secret: &client_secret,
        first_host: &first_host,
        with_fallback,
        cookie_signing_key: &cookie_signing_key,
        refresh_token_encryption_key: &refresh_token_encryption_key,
    });

    fs::write(output, toml).with_context(|| format!("failed to write {}", output.display()))?;

    // The file we just wrote embeds secret key material — enforce the same
    // permission requirement `config::load` checks for at startup.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(output, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to chmod 600 {}", output.display()))?;
    }

    println!(
        "\nWrote {} (chmod 600 — it contains secret key material).",
        output.display()
    );
    println!("\nNext steps:");
    println!("  1. Review the generated file and adjust as needed.");
    println!(
        "  2. Point `{auth_subdomain}` and `{first_host}` at this service through Caddy's \
         forward_auth (Phase 10)."
    );
    println!(
        "  3. Run `authward --config {}` to start the service.",
        output.display()
    );

    Ok(())
}

fn authward_is_under_domain(host: &str, domain: &str) -> bool {
    crate::config::is_under_domain(
        &host.trim().to_ascii_lowercase(),
        &domain.trim().to_ascii_lowercase(),
    )
}

fn random_key_hex() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill(&mut bytes);
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

struct RenderInput<'a> {
    domain: &'a str,
    auth_subdomain: &'a str,
    idp_name: &'a str,
    discovery_url: &'a str,
    client_id: &'a str,
    client_secret: &'a str,
    first_host: &'a str,
    with_fallback: bool,
    cookie_signing_key: &'a str,
    refresh_token_encryption_key: &'a str,
}

fn render_config(input: RenderInput) -> String {
    let RenderInput {
        domain,
        auth_subdomain,
        idp_name,
        discovery_url,
        client_id,
        client_secret,
        first_host,
        with_fallback,
        cookie_signing_key,
        refresh_token_encryption_key,
    } = input;

    let fallback = if with_fallback {
        format!(
            r#"
# Any other host under {domain} that reaches authward is protected with
# these settings; add fields here to change them for all such hosts.
[domain."{domain}".fallback]
"#
        )
    } else {
        String::new()
    };

    format!(
        r#"# Generated by `authward init`.
# This file contains secret key material — keep it chmod 600 and out of
# version control.

[global]
cookie_signing_key = "{cookie_signing_key}"
refresh_token_encryption_key = "{refresh_token_encryption_key}"
sqlite_path = "authward.db"

# Your identity provider: one registered OIDC client. Domains and hosts
# refer to it by this name.
[idp."{idp_name}"]
discovery_url = "{discovery_url}"
client_id = "{client_id}"
client_secret = "{client_secret}"

# Everything under this domain shares one auth subdomain and one login.
[domain."{domain}"]
auth_subdomain = "{auth_subdomain}"
idp = "{idp_name}"
{fallback}
# Inherits everything from its domain; add fields here (required_group,
# bypass_paths, ...) to override. Add one block per app to protect.
[host."{first_host}"]
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn render(with_fallback: bool) -> String {
        render_config(RenderInput {
            domain: "example.com",
            auth_subdomain: "auth.example.com",
            idp_name: "pocketid",
            discovery_url: "https://idp.example.com/.well-known/openid-configuration",
            client_id: "authward",
            client_secret: "s3cret",
            first_host: "app.example.com",
            with_fallback,
            cookie_signing_key: &"a".repeat(64),
            refresh_token_encryption_key: &"b".repeat(64),
        })
    }

    /// What the wizard writes must load through the real config loader.
    #[test]
    fn rendered_config_loads() {
        for with_fallback in [false, true] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            std::io::Write::write_all(&mut file, render(with_fallback).as_bytes()).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(file.path(), std::fs::Permissions::from_mode(0o600))
                    .unwrap();
            }
            let cfg = crate::config::load(file.path())
                .unwrap_or_else(|e| panic!("generated config must load: {e:?}"));
            assert_eq!(cfg.hosts["app.example.com"].provider_key, "pocketid");
            assert_eq!(cfg.base_domains["example.com"].idp, "pocketid");
            assert_eq!(
                cfg.base_domains["example.com"].fallback.is_some(),
                with_fallback
            );
        }
    }
}
