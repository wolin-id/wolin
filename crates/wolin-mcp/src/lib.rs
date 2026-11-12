//! Wolin MCP: Model Context Protocol native interface for AI Agents.
//! Exposes semantic SPARQL queries, consented data reads, and policy-gated resource mutations.

pub mod protocol;
pub mod server;

pub use server::McpAgentServer;
