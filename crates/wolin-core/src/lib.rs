//! Wolin Core: Foundational domain models and semantic identifiers.
//!
//! "One Identity. Infinite Reflections." (月印千江)

pub mod error;
pub mod identity;
pub mod resource;

pub use error::{Result, WolinError};
pub use identity::{Principal, WebId};
pub use resource::{ResourceKind, ResourceUri};
