//! Wolin Policy: Policy Decision Point (PDP) and Policy Enforcement Point (PEP).
//! Evaluates WAC / ACP access rules and generates agent-specific semantic projections.

pub mod pdp;

pub use pdp::{AccessDecision, AccessMode, PolicyEngine};
