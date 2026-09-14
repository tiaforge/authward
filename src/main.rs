use std::path::{Path, PathBuf};
use std::time::Duration;

use authgate::{config, logging, server};
use clap::{Parser, Subcommand};

/// How often the expired-session reaper sweeps SQLite (Phase 2/9).
const REAPER_INTERVAL: Duration = Duration::from_secs(300);
/// How often the JWKS cache for resource-scoped bearer tokens refreshes
/// in the background, independent of the on-demand refresh triggered by
/// a signature-verification failure (Phase 5).
const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(900);
/// How often idle per-IP rate-limit buckets are pruned (Phase 9).
const RATE_LIMIT_PRUNE_INTERVAL: Duration = Duration::from_secs(600);

#[derive(Parser)]
#[command(name = "authgate", version, about = "Authgate OIDC login service")]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Path to the config file (used when no subcommand is given).
    #[arg(long, short, default_value = "config.toml")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Command {
    /// Interactively generate a starter config file.
    Init {
        /// Where to write the generated config.
        #[arg(long, default_value = "config.toml")]
        output: PathBuf,
    },
}

/// Restricts every file this process creates from here on (the SQLite
/// database and its transient rollback-journal sidecar, the config file
/// written by `init`) to owner-only permissions by default, rather than
/// relying on each call site to `chmod` after the fact — a backstop for
/// any file-creation path that doesn't (Phase 11 hardening pass).
#[cfg(unix)]
fn restrict_default_file_permissions() {
    // SAFETY: umask() has no preconditions; it only affects file modes
    // this process creates from now on and cannot itself invalidate any
    // Rust invariant.
    unsafe {
        libc::umask(0o077);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(unix)]
    restrict_default_file_permissions();

    let cli = Cli::parse();

    match cli.command {
        Some(Command::Init { output }) => authgate::cli::init::run(&output),
        None => run_server(&cli.config).await,
    }
}

async fn run_server(config_path: &Path) -> anyhow::Result<()> {
    let cfg = match config::load(config_path) {
        Ok(cfg) => cfg,
        Err(errors) => {
            eprintln!(
                "authgate: {} config error(s) found in {}:\n",
                errors.len(),
                config_path.display()
            );
            for e in &errors {
                eprintln!("  - {e}");
            }
            anyhow::bail!("refusing to start with invalid config");
        }
    };

    let otel_provider = logging::init(cfg.global.otel_endpoint.as_deref());

    tracing::info!(
        base_domains = cfg.base_domains.len(),
        hosts = cfg.hosts.len(),
        has_fallback = cfg.fallback.is_some(),
        "config loaded"
    );

    let listen_addr = cfg.global.listen_addr;
    let state = authgate::build_state(cfg).await?;

    authgate::session::spawn_reaper(state.clone(), REAPER_INTERVAL);
    authgate::jwks_cache::spawn_periodic_refresh(state.clone(), JWKS_REFRESH_INTERVAL);
    authgate::ratelimit::spawn_periodic_prune(state.clone(), RATE_LIMIT_PRUNE_INTERVAL);

    let app = server::build_router(state);
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!(addr = %listen_addr, "listening");

    let result = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await;

    logging::shutdown(otel_provider);
    result.map_err(Into::into)
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    tracing::info!("shutdown signal received");
}
