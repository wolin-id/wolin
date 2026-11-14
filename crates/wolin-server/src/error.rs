use axum::{
    Json,
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::json;
use wolin_core::WolinError;

#[derive(Debug)]
pub enum LdpError {
    BadRequest(String),
    Unauthenticated(String),
    Forbidden(String),
    NotFound(String),
    MethodNotAllowed {
        allow: &'static str,
        message: String,
    },
    NotAcceptable(String),
    Conflict(String),
    PreconditionFailed(String),
    PayloadTooLarge(String),
    UnsupportedMediaType(String),
    Internal(String),
}

impl From<WolinError> for LdpError {
    fn from(err: WolinError) -> Self {
        match err {
            WolinError::Unauthenticated(msg) => Self::Unauthenticated(msg),
            WolinError::Unauthorized(msg) => Self::Forbidden(msg),
            WolinError::NotFound(msg) => Self::NotFound(msg),
            WolinError::InvalidFormat(msg) => Self::BadRequest(msg),
            WolinError::Storage(msg) | WolinError::Semantic(msg) | WolinError::Internal(msg) => {
                Self::Internal(msg)
            }
        }
    }
}

impl IntoResponse for LdpError {
    fn into_response(self) -> Response {
        let (status, code, detail, www_auth, allow_hdr) = match self {
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, "bad_request", msg, None, None),
            Self::Unauthenticated(msg) => (
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                msg,
                Some(r#"Bearer realm="wolin""#),
                None,
            ),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, "forbidden", msg, None, None),
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, "not_found", msg, None, None),
            Self::MethodNotAllowed { allow, message } => (
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                message,
                None,
                Some(allow),
            ),
            Self::NotAcceptable(msg) => (
                StatusCode::NOT_ACCEPTABLE,
                "not_acceptable",
                msg,
                None,
                None,
            ),
            Self::Conflict(msg) => (StatusCode::CONFLICT, "conflict", msg, None, None),
            Self::PreconditionFailed(msg) => (
                StatusCode::PRECONDITION_FAILED,
                "precondition_failed",
                msg,
                None,
                None,
            ),
            Self::PayloadTooLarge(msg) => (
                StatusCode::PAYLOAD_TOO_LARGE,
                "payload_too_large",
                msg,
                None,
                None,
            ),
            Self::UnsupportedMediaType(msg) => (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "unsupported_media_type",
                msg,
                None,
                None,
            ),
            Self::Internal(_internal_detail) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal server error".to_string(),
                None,
                None,
            ),
        };

        let mut resp = (
            status,
            Json(json!({
                "error": code,
                "message": detail,
                "status": status.as_u16(),
            })),
        )
            .into_response();

        if let Some(challenge) = www_auth {
            resp.headers_mut().insert(
                header::WWW_AUTHENTICATE,
                HeaderValue::from_static(challenge),
            );
        }
        if let Some(allow) = allow_hdr {
            resp.headers_mut()
                .insert(header::ALLOW, HeaderValue::from_static(allow));
        }

        resp
    }
}
