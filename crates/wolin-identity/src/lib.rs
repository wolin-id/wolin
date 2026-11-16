//! Wolin Identity: WebID discovery, W3C DID resolution, and OIDC / DPoP token validation.

pub mod did;
pub mod oidc;
pub mod solid_oidc;

pub use did::{DidDocument, DidMethod, DidResolver, ParsedDid, VerificationMethod};
pub use oidc::{
    ActorClaim, ConfirmationClaim, JwtSignatureVerifier, OidcClaims, OidcValidationOptions,
    OidcValidator,
};
pub use solid_oidc::{
    DpopProofClaims, DpopReplayCache, DpopValidationContext, HttpWebIdDereferencer,
    JwksSignatureVerifier, LDP_INBOX_IRI, PIM_STORAGE_IRI, SOLID_OIDC_ISSUER_IRI,
    WebIdDereferencer, WebIdProfile, compute_jwk_thumbprint_sha256, sha256_base64url,
    verify_dpop_proof,
};
