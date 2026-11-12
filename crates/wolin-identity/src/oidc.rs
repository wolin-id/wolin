use wolin_core::{Principal, Result, WebId};

pub struct OidcValidator;

impl OidcValidator {
    pub fn validate_claims(token: &str, issuer: &str) -> Result<Principal> {
        // Validation stub: will verify RSA/EC JWT signature against JWKS
        Ok(Principal::User {
            webid: WebId(format!("{issuer}#{token}")),
            issuer: issuer.to_string(),
        })
    }
}
