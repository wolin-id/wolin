use thiserror::Error;

#[derive(Error, Debug)]
pub enum WolinError {
    #[error("Authentication failed: {0}")]
    Unauthenticated(String),

    #[error("Access denied: {0}")]
    Unauthorized(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Storage engine error: {0}")]
    Storage(String),

    #[error("Semantic/RDF error: {0}")]
    Semantic(String),

    #[error("Invalid resource format: {0}")]
    InvalidFormat(String),

    #[error("Internal system error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, WolinError>;
