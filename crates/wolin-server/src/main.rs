use std::net::SocketAddr;

use tracing::info;
use tracing_subscriber::EnvFilter;
use wolin_core::{ResourceUri, WebId};
use wolin_identity::OidcValidationOptions;
use wolin_policy::{AccessMode, PolicyEngine, SubjectMatcher, WacRule};
use wolin_server::{
    AppState, CliParseOutcome, LdpConfig, ServerCliConfig, build_router, shutdown_signal,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli_cfg = match ServerCliConfig::parse_from(std::env::args()) {
        Ok(CliParseOutcome::Run(cfg)) => cfg,
        Ok(CliParseOutcome::Help(help_text)) => {
            println!("{help_text}");
            return Ok(());
        }
        Ok(CliParseOutcome::Version(ver_text)) => {
            println!("{ver_text}");
            return Ok(());
        }
        Err(err) => {
            eprintln!("error: {err}");
            std::process::exit(2);
        }
    };

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info,wolin_server=info,wolin_mcp=info,tower_http=info")
    });
    tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(true)
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "Starting Wolin (月印) Server : Universal Identity & Persistence Fabric"
    );

    let mut policy =
        PolicyEngine::with_explicit_delegation_required(cli_cfg.require_explicit_delegation);
    let prefix = cli_cfg.pod_uri_prefix.trim_end_matches('/');
    policy.add_wac_rule(WacRule {
        id: "default-public-container-read".to_string(),
        access_to: vec![ResourceUri(format!("{prefix}/public"))],
        default_for: vec![ResourceUri(format!("{prefix}/public/"))],
        subjects: vec![SubjectMatcher::Public],
        modes: vec![AccessMode::Read],
    });

    if let Some(ref owner) = cli_cfg.owner_webid {
        policy.add_wac_rule(WacRule {
            id: "bootstrap-pod-owner".to_string(),
            access_to: vec![ResourceUri(prefix.to_string())],
            default_for: vec![ResourceUri(format!("{prefix}/"))],
            subjects: vec![SubjectMatcher::WebId(WebId(owner.clone()))],
            modes: vec![
                AccessMode::Read,
                AccessMode::Write,
                AccessMode::Append,
                AccessMode::Control,
            ],
        });
    }

    let mut oidc_opts = OidcValidationOptions::new(&cli_cfg.oidc_issuer);
    if let Some(ref aud) = cli_cfg.oidc_audience {
        oidc_opts = oidc_opts.with_audience(aud);
    }

    let base_url = cli_cfg.effective_base_url();
    let ldp_config = LdpConfig::new(&base_url, &cli_cfg.pod_uri_prefix)
        .with_pod_cloud_domain(&cli_cfg.pod_cloud_domain)
        .with_oidc_options(oidc_opts)
        .with_max_body_bytes(cli_cfg.max_body_bytes);

    let state = match &cli_cfg.storage_dir {
        Some(dir) => {
            info!(storage_dir = %dir.display(), "Initializing persistent OpenDAL + Oxigraph Pod storage");
            AppState::new_persistent(dir, policy, ldp_config).await?
        }
        None => {
            info!("Initializing ephemeral in-memory OpenDAL + Oxigraph Pod storage");
            AppState::new_in_memory(policy, ldp_config).await?
        }
    };

    let bind_addr = SocketAddr::new(cli_cfg.host, cli_cfg.port);
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;

    info!(
        listen_addr = %local_addr,
        base_url = %base_url,
        "Wolin Server ready (Solid LDP + WAC/ACP + Native MCP)"
    );

    let app = build_router(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Wolin Server shut down cleanly");
    Ok(())
}
