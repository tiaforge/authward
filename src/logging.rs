//! Structured logging setup: JSON to stdout always, plus OpenTelemetry log
//! export when a collector endpoint is configured. Metrics are explicitly
//! out of scope for now (see the plan's Deferred section).

use std::time::Duration;

use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, WithExportConfig};
use opentelemetry_sdk::{Resource, logs::SdkLoggerProvider};
use tracing_subscriber::{EnvFilter, prelude::*};

/// Initializes the global tracing subscriber. The returned provider (when
/// OTel export is configured) must be kept alive for the life of the
/// process — dropping it stops export — and passed to [`shutdown`] before
/// exit so buffered logs flush instead of being lost.
pub fn init(otel_endpoint: Option<&str>) -> Option<SdkLoggerProvider> {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let fmt_layer = tracing_subscriber::fmt::layer().json();

    let provider = otel_endpoint.map(|endpoint| {
        let exporter = LogExporter::builder()
            .with_tonic()
            .with_endpoint(endpoint)
            .with_timeout(Duration::from_secs(5))
            .build()
            .expect("failed to build OTLP log exporter");

        SdkLoggerProvider::builder()
            .with_resource(Resource::builder().with_service_name("authward").build())
            .with_batch_exporter(exporter)
            .build()
    });

    let otel_layer = provider.as_ref().map(OpenTelemetryTracingBridge::new);

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .with(otel_layer)
        .init();

    provider
}

/// Flushes and shuts down the OTel logger provider, if one was created.
pub fn shutdown(provider: Option<SdkLoggerProvider>) {
    if let Some(provider) = provider
        && let Err(err) = provider.shutdown()
    {
        eprintln!("error shutting down OpenTelemetry logger provider: {err}");
    }
}
