use serde::{Deserialize, Serialize};
use wolin_core::{Principal, ResourceUri};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessMode {
    Read,
    Write,
    Append,
    Control,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessDecision {
    Permit,
    Deny { reason: String },
}

pub struct PolicyEngine;

impl PolicyEngine {
    /// Evaluate whether a principal has permission to perform `mode` on `target`
    pub fn evaluate(
        principal: &Principal,
        target: &ResourceUri,
        mode: AccessMode,
    ) -> AccessDecision {
        match principal {
            Principal::User { .. } => AccessDecision::Permit,
            Principal::Agent { scope, .. } => {
                let required_scope = match mode {
                    AccessMode::Read => "read",
                    AccessMode::Write | AccessMode::Append => "write",
                    AccessMode::Control => "admin",
                };
                if scope.iter().any(|s| s == required_scope || s == "*") {
                    AccessDecision::Permit
                } else {
                    AccessDecision::Deny {
                        reason: format!("Agent lacks scope: {required_scope}"),
                    }
                }
            }
            Principal::Anonymous => match mode {
                AccessMode::Read => {
                    if target.0.contains("/public/") {
                        AccessDecision::Permit
                    } else {
                        AccessDecision::Deny {
                            reason: "Resource is private".to_string(),
                        }
                    }
                }
                _ => AccessDecision::Deny {
                    reason: "Authentication required for write/control".to_string(),
                },
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wolin_core::WebId;

    #[test]
    fn test_user_access_permitted() {
        let user = Principal::User {
            webid: WebId("https://user.wolin.id/profile".to_string()),
            issuer: "wolin".to_string(),
        };
        let target = ResourceUri("wolin://pod/data/private".to_string());
        assert_eq!(
            PolicyEngine::evaluate(&user, &target, AccessMode::Read),
            AccessDecision::Permit
        );
        assert_eq!(
            PolicyEngine::evaluate(&user, &target, AccessMode::Write),
            AccessDecision::Permit
        );
    }

    #[test]
    fn test_agent_scope_enforcement() {
        let agent = Principal::Agent {
            agent_id: "claude-subagent-1".to_string(),
            delegated_by: WebId("https://user.wolin.id/profile".to_string()),
            scope: vec!["read".to_string()],
        };
        let target = ResourceUri("wolin://pod/data/doc".to_string());
        assert_eq!(
            PolicyEngine::evaluate(&agent, &target, AccessMode::Read),
            AccessDecision::Permit
        );
        assert!(matches!(
            PolicyEngine::evaluate(&agent, &target, AccessMode::Write),
            AccessDecision::Deny { .. }
        ));
    }

    #[test]
    fn test_anonymous_public_only() {
        let anon = Principal::Anonymous;
        let pub_target = ResourceUri("wolin://pod/public/about".to_string());
        let priv_target = ResourceUri("wolin://pod/private/keys".to_string());

        assert_eq!(
            PolicyEngine::evaluate(&anon, &pub_target, AccessMode::Read),
            AccessDecision::Permit
        );
        assert!(matches!(
            PolicyEngine::evaluate(&anon, &priv_target, AccessMode::Read),
            AccessDecision::Deny { .. }
        ));
    }
}
