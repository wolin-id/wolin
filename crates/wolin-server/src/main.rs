use axum::{
    Router,
    response::Json,
    routing::get,
};
use serde_json::json;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting Wolin (月인) Server : Universal Identity & Persistence Fabric");

    let app = Router::new()
        .route("/health", get(health_check))
        .route("/.well-known/wolin", get(well_known_wolin));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:4000").await?;
    info!("Wolin listening on http://127.0.0.1:4000");

    axum::serve(listener, app).await?;
    Ok(())
}

async fn health_check() -> Json<serde_json::Value> {
    Json(json!({
        "status": "healthy",
        "service": "wolin-server",
        "version": env!("CARGO_PKG_VERSION"),
        "motto": "One Identity. Infinite Reflections. (月印千江)"
    }))
}

async fn well_known_wolin() -> Json<serde_json::Value> {
    Json(json!({
        "wolin_version": "0.1.0",
        "protocols": ["solid-0.11", "wac-2.0", "mcp-2024-11-05", "oidc-1.0"],
        "storage_backend": "opendal+oxigraph",
        "identity_mesh": ["webid", "did:key", "did:nostr", "zitadel-oidc"]
    }))
}
