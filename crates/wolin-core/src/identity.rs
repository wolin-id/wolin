use serde::{Deserialize, Serialize};

/// Sovereign WebID URI representing a persistent digital entity
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WebId(pub String);

impl std::fmt::Display for WebId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Actor principal requesting access (Human User, AI Agent, or Service)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Principal {
    User {
        webid: WebId,
        issuer: String,
    },
    Agent {
        agent_id: String,
        delegated_by: WebId,
        scope: Vec<String>,
    },
    Anonymous,
}
