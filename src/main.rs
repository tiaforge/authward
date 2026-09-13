use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Parser, Subcommand};
use forward_auth::{config, logging, server};

/// How often the expired-session reaper sweeps SQLite (Phase 2/9).
const REAPER_INTERVAL: Duration = Duration::from_secs(300);
/// How often the JWKS cache for resource-scoped bearer tokens refreshes
/// in the background, independent of the on-demand refresh triggered by
/// a signature-verification failure (Phase 5).
const JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(900);

#[derive(Parser)]
#[command(
    name = "forward-auth",
    version,
    about = "Forward-auth OIDC login service"
)]
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Command::Init { output }) => forward_auth::cli::init::run(&output),
        None => run_server(&cli.config).await,
    }
}

async fn run_server(config_path: &Path) -> anyhow::Result<()> {
    let cfg = match config::load(config_path) {
        Ok(cfg) => cfg,
        Err(errors) => {
            eprintln!(
                "forward-auth: {} config error(s) found in {}:\n",
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
    let state = forward_auth::build_state(cfg).await?;

    forward_auth::session::spawn_reaper(state.clone(), REAPER_INTERVAL);
    forward_auth::jwks_cache::spawn_periodic_refresh(state.clone(), JWKS_REFRESH_INTERVAL);

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
