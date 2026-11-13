use std::sync::Arc;

use axum::{
    body::to_bytes,
    extract::{Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use wolin_mcp::protocol::{JsonRpcId, JsonRpcResponse, PARSE_ERROR};

use crate::{auth::extract_principal_for_request, error::LdpError, AppState};

/// Handle Native MCP JSON-RPC 2.0 requests (`POST /mcp`) over Streamable HTTP.
///
/// Enforces fail-closed OIDC/ZITADEL (`Bearer` / `DPoP`) and W3C `DID` authentication
/// prior to reading or dispatching the JSON-RPC payload through [`wolin_mcp::McpAgentServer`].
pub async fn handle_mcp_post(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Result<Response, LdpError> {
    if req.uri().query().is_some() {
        return Err(LdpError::BadRequest(
            "Query parameters are not permitted on the /mcp endpoint".to_string(),
        ));
    }

    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Authenticate caller first (fail-closed 401 on malformed/expired/forged credentials).
    let principal = extract_principal_for_request(&method, &uri, &headers, &state).await?;

    // Validate Content-Type when present (must be application/json).
    if let Some(raw_ct) = headers.get(header::CONTENT_TYPE) {
        let ct_str = raw_ct
            .to_str()
            .map_err(|_| LdpError::BadRequest("Malformed Content-Type header".to_string()))?;
        let media = ct_str
            .split(';')
            .next()
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase();
        if media != "application/json" {
            return Err(LdpError::UnsupportedMediaType(format!(
                "MCP JSON-RPC endpoint requires 'Content-Type: application/json', got '{media}'"
            )));
        }
    }

    let max_bytes = state
        .config
        .max_body_bytes
        .min(state.mcp_server.config().max_message_bytes);
    let body_bytes = to_bytes(req.into_body(), max_bytes).await.map_err(|_| {
        LdpError::PayloadTooLarge(format!(
            "MCP JSON-RPC request body exceeds maximum allowed size of {max_bytes} bytes"
        ))
    })?;

    let Ok(raw_json) = std::str::from_utf8(&body_bytes) else {
        let parse_err = JsonRpcResponse::error(
            JsonRpcId::Null,
            PARSE_ERROR,
            "Invalid UTF-8 in JSON-RPC request payload",
        );
        let payload = serde_json::to_vec(&parse_err)
            .map_err(|e| LdpError::Internal(format!("JSON-RPC error serialize failed: {e}")))?;
        return Ok(build_json_response(StatusCode::OK, payload));
    };

    let might_mutate_catalog = raw_json.contains("wolin_write_resource");
    let response_opt = state
        .mcp_server
        .handle_jsonrpc_str(&principal, raw_json)
        .await;

    if might_mutate_catalog {
        state.sync_catalog_from_store().await?;
    }

    match response_opt {
        Some(resp_json) => Ok(build_json_response(StatusCode::OK, resp_json.into_bytes())),
        None => {
            // JSON-RPC 2.0 notification (no `id`): per MCP Streamable HTTP spec, return 202 Accepted.
            let mut resp = StatusCode::ACCEPTED.into_response();
            attach_security_headers(resp.headers_mut());
            Ok(resp)
        }
    }
}

/// Handle MCP HTTP+SSE transport discovery (`GET /mcp/sse`).
///
/// Validates caller credentials (if provided) and emits the standard MCP `endpoint` SSE event
/// pointing to `/mcp` for JSON-RPC 2.0 message submission.
pub async fn handle_mcp_sse(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Result<Response, LdpError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();
    let _principal = extract_principal_for_request(&method, &uri, &headers, &state).await?;
    validate_sse_accept(&headers)?;

    let sse_frame = "event: endpoint\ndata: /mcp\n\n";
    let mut resp = (StatusCode::OK, sse_frame).into_response();
    let hdrs = resp.headers_mut();
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    hdrs.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-store, must-revalidate"),
    );
    hdrs.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    hdrs.insert(
        HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    Ok(resp)
}

fn validate_sse_accept(headers: &HeaderMap) -> Result<(), LdpError> {
    let accept_vals: Vec<&HeaderValue> = headers.get_all(header::ACCEPT).iter().collect();
    if accept_vals.is_empty() {
        return Ok(());
    }

    let mut accepts_sse = false;
    for hv in accept_vals {
        let s = hv
            .to_str()
            .map_err(|_| LdpError::BadRequest("Malformed Accept header".to_string()))?;
        for item in s.split(',') {
            let mut parts = item.trim().split(';');
            let media = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
            if media.is_empty() {
                continue;
            }
            let mut q_nonzero = true;
            for param in parts {
                if let Some((k, v)) = param.split_once('=') {
                    if k.trim().eq_ignore_ascii_case("q") {
                        let q: f32 = v.trim().parse().map_err(|_| {
                            LdpError::BadRequest("Invalid q weight in Accept header".to_string())
                        })?;
                        if !(0.0..=1.0).contains(&q) {
                            return Err(LdpError::BadRequest(
                                "Accept q weight must be between 0.0 and 1.0".to_string(),
                            ));
                        }
                        q_nonzero = q > 0.0;
                    }
                }
            }
            if q_nonzero && matches!(media.as_str(), "text/event-stream" | "text/*" | "*/*") {
                accepts_sse = true;
            }
        }
    }

    if accepts_sse {
        Ok(())
    } else {
        Err(LdpError::NotAcceptable(
            "MCP SSE endpoint requires Accept compatible with 'text/event-stream'".to_string(),
        ))
    }
}

fn build_json_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut resp = (status, body).into_response();
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    attach_security_headers(resp.headers_mut());
    resp
}

fn attach_security_headers(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
}
