//! Wolin Identity: WebID discovery, W3C DID resolution, and OIDC / DPoP token validation.

pub mod did;
pub mod oidc;

pub use did::DidResolver;
pub use oidc::OidcValidator;
