use wolin_core::{Principal, Result, WebId};

pub struct DidResolver;

impl DidResolver {
    pub fn resolve_principal(did: &str) -> Result<Principal> {
        Ok(Principal::User {
            webid: WebId(did.to_string()),
            issuer: "wolin:did".to_string(),
        })
    }
}
