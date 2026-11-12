//! Wolin MCP: Model Context Protocol native interface and Semantic Projection Gateway
//! for Sovereign Solid Pods.
//!
//! Exposes JSON-RPC 2.0 MCP handlers (`initialize`, `tools/list`, `tools/call`,
//! `resources/list`, `resources/read`) with WAC/ACP Policy Decision Point (PDP)
//! delegation enforcement and agent-scoped Zero-PII selective disclosure.

pub mod projection;
pub mod protocol;
pub mod server;
pub mod uri;

pub use projection::{DisclosurePolicy, DisclosureProfile, PiiCategory, ProjectedTriples};
pub use server::{McpAgentServer, McpGateway, McpGatewayConfig};
