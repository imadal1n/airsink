//! AirPlay 2 audio sender for Linux.
//!
//! This binary wires together the application supervisor and terminal user interface,
//! providing a complete AirPlay 2 streaming solution from Linux to Apple devices.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use airsink::{App, Config};

/// AirPlay 2 audio sender for Linux.
#[derive(Parser, Debug)]
#[command(name = "airsink")]
#[command(about = "Stream audio from Linux to Apple AirPlay 2 devices", long_about = None)]
struct Args {
    /// Human-readable sender name exposed to remote receivers.
    #[arg(long, default_value = "airsink")]
    host_name: String,

    /// Optional specific local interface address to bind sockets to.
    #[arg(long)]
    bind_ip: Option<String>,

    /// Target end-to-end latency for stream buffering in milliseconds.
    #[arg(long, default_value = "2000")]
    latency: u32,

    /// Name of the virtual PipeWire sink to create.
    #[arg(long, default_value = "airsink")]
    sink_name: String,
}

/// Entry point for the airsink application.
///
/// Initializes logging, parses CLI arguments, builds the application configuration,
/// starts the supervisor, and runs the TUI event loop.
#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize tracing subscriber with environment filter.
    // Respects RUST_LOG environment variable, defaults to "info" level.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // Parse optional bind IP from CLI argument.
    let bind_ip = if let Some(ip_str) = args.bind_ip {
        Some(IpAddr::from_str(&ip_str)?)
    } else {
        None
    };

    // Build application configuration from CLI arguments.
    let config = Config {
        host_name: args.host_name,
        bind_ip,
        target_latency_ms: args.latency,
        virtual_sink_name: args.sink_name,
    };

    // Initialize the default file-based pairing store.
    let store = airsink::default_store()?;
    let store = Arc::new(store);

    // Start the application supervisor and get a handle for the UI.
    let handle = App::start(config, store).await?;

    // Run the TUI event loop. This blocks until the user quits.
    airsink::ui::run(handle).await?;

    Ok(())
}
