use tracing::info;
use wolin_core::ResourceUri;
use wolin_policy::{AccessMode, PolicyEngine, SubjectMatcher, WacRule};
use wolin_server::{build_router, AppState, LdpConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting Wolin (月인) Server : Universal Identity & Persistence Fabric");

    let mut policy = PolicyEngine::new();
    policy.add_wac_rule(WacRule {
        id: "default-public-container-read".to_string(),
        access_to: vec![ResourceUri("wolin://pod/public".to_string())],
        default_for: vec![ResourceUri("wolin://pod/public/".to_string())],
        subjects: vec![SubjectMatcher::Public],
        modes: vec![AccessMode::Read],
    });

    let state = AppState::new_in_memory(policy, LdpConfig::default()).await?;
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4000").await?;
    info!("Wolin listening on http://127.0.0.1:4000");

    axum::serve(listener, app).await?;
    Ok(())
}
