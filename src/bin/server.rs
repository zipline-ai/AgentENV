use std::sync::{Arc, OnceLock, RwLock};

use agentenv::api::shutdown::{cleanup_phase, serve_with_shutdown, HTTP_DRAIN_BUDGET};
use agentenv::api::{server, ApiImpl};
use agentenv::api_key::ApiKey;
use agentenv::identity::NodeIdentity;
use agentenv::image::ImageResolver;
use agentenv::observability::shutdown::{shutdown_with_reporter, REPORTER_SHUTDOWN_BUDGET};
use agentenv::observability::{ObservabilityReporter, ObservabilityService};
use agentenv::orchestrator::Orchestrator;
use agentenv::overlaybd::OverlaybdP2pRuntime;
use agentenv::sandbox::{FirecrackerPool, FirecrackerSandboxFactory, UblkDeviceManager};
use agentenv::snapshot::SnapshotManager;
use agentenv::template::TemplateBuilder;
use clap::Parser;
use tracing::{info, warn};

#[global_allocator]
static ALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

// jemalloc tuning: purge dirty/muzzy pages after 1s instead of the default
// 10s, and do the purging on a background thread (the `background_threads`
// cargo feature is already enabled). Burst allocations (RocksDB opens, image
// resolution, template builds) otherwise linger as retained RSS long after
// the burst is over.
#[used]
#[allow(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static malloc_conf: &[u8] = b"dirty_decay_ms:1000,muzzy_decay_ms:1000,background_thread:true\0";

#[derive(Debug, Parser)]
#[command(name = "agentenv server")]
struct ServerCli {
    /// Run setup/provisioning only, then exit.
    #[arg(long)]
    setup_only: bool,

    /// Provision machine-wide KVM, ublk, and networking prerequisites.
    #[arg(long, conflicts_with = "setup_only")]
    setup_host: bool,

    /// Account that will run AENV after host provisioning.
    #[arg(long, default_value = "aenv", requires = "setup_host")]
    runtime_user: String,

    /// Runtime service group; owns AENV state and receives ublk device access.
    #[arg(long, default_value = "aenv", requires = "setup_host")]
    runtime_group: String,

    /// Path to config file (same as AENV_CONFIG_PATH).
    #[arg(long)]
    config: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    agentenv::logging::init();
    agentenv_observability::init_prometheus_recorder()?;

    let cli = ServerCli::parse();
    let config_manager = if let Some(config_path) = cli.config.as_deref() {
        agentenv::cfg::ConfigManager::init_global_from_path(config_path)?
    } else {
        agentenv::cfg::ConfigManager::init_global()?
    };
    let config = config_manager.config();

    if cli.setup_only {
        agentenv::setup::ensure_provisioning(config).await?;
        info!(target: "agentenv", "dependency setup complete (setup-only mode)");
        return Ok(());
    }

    if cli.setup_host {
        agentenv::setup::ensure_host(config, &cli.runtime_user, &cli.runtime_group)?;
        info!(target: "agentenv", "host setup complete");
        return Ok(());
    }

    agentenv::privileges::require_runtime_capabilities()?;
    agentenv::privileges::clear_ambient_capabilities()?;

    let api_key = ApiKey::resolve(config)?;

    let addr = std::env::var("API_ADDR").unwrap_or_else(|_| "0.0.0.0:8000".to_string());
    let identity = NodeIdentity::from_config(&config.node_identity);
    let p2p_transport = agentenv::p2p::transport_from_config(config, &identity).await?;
    let p2p_local_endpoint = p2p_transport.local_endpoint();
    let overlaybd_p2p =
        OverlaybdP2pRuntime::start_from_app_config(config, Arc::clone(&p2p_transport)).await;

    agentenv::setup::ensure_environment(config, overlaybd_p2p.read_facade_address()).await?;

    // Initialize the global ublk device manager (spawns daemon if configured).
    UblkDeviceManager::init_global_from_config_with_p2p_publish_url(
        config,
        overlaybd_p2p.publish_address(),
    )
    .await?;

    if let Err(err) = FirecrackerPool::prime(std::time::Duration::from_secs(10)).await {
        warn!(target: "agentenv", error = %err, "firecracker pool prime failed; continuing startup");
    }

    let snapshot_p2p_transport = config
        .snapshot
        .p2p_enabled
        .then(|| Arc::clone(&p2p_transport));
    let snapshot_manager = Arc::new(SnapshotManager::new(snapshot_p2p_transport)?);
    let cluster_cpu_arc: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
    let template_builder = Arc::new(TemplateBuilder::with_cpu_config(Arc::clone(
        &cluster_cpu_arc,
    )));
    let image_resolver = Arc::new(ImageResolver::new(config));
    let factory = FirecrackerSandboxFactory::with_cpu_config(Arc::clone(&cluster_cpu_arc));
    let orchestrator = Orchestrator::with_file_backed_store_and_factory(factory).await?;
    let observability_config = &config.observability;
    let observability = if observability_config.enabled {
        Some(Arc::new(
            ObservabilityService::new(
                identity,
                Arc::clone(&orchestrator),
                config.resolved_cpu_template_helper(),
                cluster_cpu_arc,
            )
            .await,
        ))
    } else {
        None
    };
    let mut reporter = if let Some(service) = observability.as_ref() {
        let mut reporter = ObservabilityReporter::new(
            Arc::clone(service),
            &observability_config.scheduler_report,
            &config.cluster,
            p2p_local_endpoint,
        )?;
        if let Some(inner) = reporter.as_mut() {
            inner.start();
        }
        reporter
    } else {
        None
    };

    let api_impl = Arc::new(ApiImpl::new(
        Arc::clone(&orchestrator),
        snapshot_manager,
        template_builder,
        image_resolver,
        observability,
        config.sandbox_proxy.domains.clone(),
        api_key,
    ));
    let http_shutdown = api_impl.http_shutdown_state();
    let app = server::new(api_impl);
    let shutdown_orchestrator = Arc::clone(&orchestrator);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!(target: "agentenv", addr = %addr, "API server listening");

    let signal_at = Arc::new(OnceLock::new());
    let cleanup_signal_at = signal_at.clone();
    let guest_cleanup = async move {
        let mut failures = Vec::new();
        info!(target: "agentenv", "stopping sandboxes before process exit");
        if let Err(err) = cleanup_phase("orchestrator", shutdown_orchestrator.shutdown()).await {
            failures.push(format!("orchestrator: {err}"));
            warn!(target: "agentenv", error = %err, "error occurred while shutting down orchestrator");
        }
        if let Some(pool) = FirecrackerPool::global() {
            info!(target: "agentenv", "shutting down firecracker pool");
            if let Err(err) = cleanup_phase("firecracker_pool", pool.shutdown()).await {
                failures.push(format!("firecracker_pool: {err}"));
                warn!(target: "agentenv", error = %err, "error occurred while shutting down firecracker pool");
            }
        }
        info!(target: "agentenv", "shutting down ublk daemon");
        if let Err(err) =
            cleanup_phase("ublk_daemon", UblkDeviceManager::global().shutdown_daemon()).await
        {
            failures.push(format!("ublk_daemon: {err}"));
            warn!(target: "agentenv", error = %err, "error occurred while shutting down ublk daemon");
        }
        info!(target: "agentenv", "shutting down overlaybd p2p runtime");
        if let Err(err) = cleanup_phase("overlaybd_p2p", overlaybd_p2p.shutdown()).await {
            failures.push(format!("overlaybd_p2p: {err}"));
            warn!(target: "agentenv", error = %err, "error occurred while shutting down overlaybd p2p runtime");
        }
        info!(target: "agentenv", "shutting down p2p transport");
        if let Err(err) = cleanup_phase("p2p_transport", p2p_transport.shutdown()).await {
            failures.push(format!("p2p_transport: {err}"));
            warn!(target: "agentenv", error = %err, "error occurred while shutting down p2p transport");
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(failures.join("; ")))
        }
    };

    let shutdown_cleanup = async move {
        let started = *cleanup_signal_at.get_or_init(tokio::time::Instant::now);
        shutdown_with_reporter(
            reporter.take(),
            started + REPORTER_SHUTDOWN_BUDGET,
            guest_cleanup,
        )
        .await
    };

    serve_with_shutdown(
        listener,
        app,
        http_shutdown,
        async move {
            shutdown_signal().await;
            let _ = signal_at.set(tokio::time::Instant::now());
            orchestrator.close_admission();
        },
        shutdown_cleanup,
        HTTP_DRAIN_BUDGET,
    )
    .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {
            info!(target: "agentenv", "received Ctrl+C, starting graceful shutdown");
        }
        _ = terminate => {
            info!(target: "agentenv", "received SIGTERM, starting graceful shutdown");
        }
    }
}
