//! Wolin Identity: WebID discovery, W3C DID resolution, and OIDC / DPoP token validation.

pub mod did;
pub mod oidc;

pub use did::{DidDocument, DidMethod, DidResolver, ParsedDid, VerificationMethod};
pub use oidc::{
    ActorClaim, JwtSignatureVerifier, OidcClaims, OidcValidationOptions, OidcValidator,
};
