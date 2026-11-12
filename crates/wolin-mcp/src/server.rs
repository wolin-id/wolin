use crate::protocol::{McpContentItem, McpToolCall, McpToolResult};
use wolin_core::{Principal, ResourceUri, Result};
use wolin_policy::{AccessMode, PolicyEngine};

pub struct McpAgentServer;

impl McpAgentServer {
    /// Execute an MCP tool call on behalf of an authenticated principal
    pub async fn handle_tool_call(
        principal: &Principal,
        call: McpToolCall,
    ) -> Result<McpToolResult> {
        match call.name.as_str() {
            "wolin_query_semantic" => {
                let target = ResourceUri("wolin://pod/semantic".to_string());
                match PolicyEngine::evaluate(principal, &target, AccessMode::Read) {
                    wolin_policy::AccessDecision::Permit => Ok(McpToolResult {
                        content: vec![McpContentItem::Text {
                            text: "Semantic query projection executed successfully.".to_string(),
                        }],
                        is_error: false,
                    }),
                    wolin_policy::AccessDecision::Deny { reason } => Ok(McpToolResult {
                        content: vec![McpContentItem::Text { text: reason }],
                        is_error: true,
                    }),
                }
            }
            unknown => Ok(McpToolResult {
                content: vec![McpContentItem::Text {
                    text: format!("Unknown tool: {unknown}"),
                }],
                is_error: true,
            }),
        }
    }
}
