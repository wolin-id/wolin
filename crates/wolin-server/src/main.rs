use tracing::info;
use tracing_subscriber::EnvFilter;
use wolin_core::{ResourceUri, WebId};
use wolin_identity::OidcValidationOptions;
use wolin_policy::{AccessMode, PolicyEngine, SubjectMatcher, WacRule};
use wolin_server::{
    AppState, CliParseOutcome, LdpConfig, ServerCliConfig, build_router, run_healthcheck_probe,
    shutdown_signal,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli_cfg = match ServerCliConfig::parse_from_os() {
        Ok(CliParseOutcome::Run(cfg)) => cfg,
        Ok(CliParseOutcome::Healthcheck(cfg)) => {
            if let Err(err) = run_healthcheck_probe(&cfg).await {
                eprintln!("healthcheck failed: {err}");
                std::process::exit(1);
            }
            return Ok(());
        }
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

    let log_directive = std::env::var("RUST_LOG")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            std::env::var("WOLIN_LOG")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .unwrap_or_else(|| "info,wolin_server=info,wolin_mcp=info,tower_http=info".to_string());

    let env_filter = EnvFilter::try_new(&log_directive).unwrap_or_else(|err| {
        eprintln!("error: invalid log filter directive '{log_directive}': {err}");
        std::process::exit(2);
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
    let mut ldp_config = LdpConfig::new(&base_url, &cli_cfg.pod_uri_prefix)
        .with_pod_cloud_domain(&cli_cfg.pod_cloud_domain)
        .with_oidc_options(oidc_opts)
        .with_max_body_bytes(cli_cfg.max_body_bytes)
        .with_max_open_pods(cli_cfg.max_open_pods)
        .with_pod_quota_bytes(cli_cfg.pod_quota_bytes)
        .with_reserved_pods(cli_cfg.reserved_pods.iter().cloned())
        .with_mcp_enabled(cli_cfg.mcp_enabled);
    if let Some(ref token) = cli_cfg.admin_token {
        ldp_config = ldp_config.with_admin_token(token);
    }

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

    let bind_addr = cli_cfg.listen_addr();
    let listener = tokio::net::TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;

    info!(
        listen_addr = %local_addr,
        base_url = %base_url,
        mcp_enabled = cli_cfg.mcp_enabled,
        "Wolin Server ready (Solid LDP + WAC/ACP + Native MCP)"
    );

    let app = build_router(state);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Wolin Server shut down cleanly");
    Ok(())
}
