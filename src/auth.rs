//! Token auth matching Node `middleware/auth.js`.
//!
//! Headers: `user-token` / `admin-token`.
//! Comparison: SHA-512(raw token bytes) timing-safe-equal against configured hex hash.

use crate::config::Config;
use crate::error::{self, PccsError};
use crate::headers;
use axum::extract::State;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use sha2::{Digest, Sha512};
use subtle::ConstantTimeEq;

fn parse_expected_hash(hex_hash: &str) -> Option<Vec<u8>> {
    if hex_hash.len() != 128 || !hex_hash.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    hex::decode(hex_hash).ok()
}

pub fn verify_token(raw_token: Option<&str>, expected_hex: &str) -> Result<(), PccsError> {
    let expected = parse_expected_hash(expected_hex).ok_or(error::UNAUTHORIZED)?;
    let token = raw_token.filter(|t| !t.is_empty()).ok_or(error::UNAUTHORIZED)?;
    let digest = Sha512::digest(token.as_bytes());
    if digest.as_slice().len() != expected.len()
        || bool::from(digest.as_slice().ct_eq(expected.as_slice())) == false
    {
        return Err(error::UNAUTHORIZED);
    }
    Ok(())
}

pub fn header_token<'a>(headers: &'a axum::http::HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

#[derive(Clone)]
pub struct AppState {
    pub config: std::sync::Arc<Config>,
    pub cache: std::sync::Arc<crate::cache::Cache>,
}

pub async fn require_user(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, PccsError> {
    let token = header_token(req.headers(), headers::USER_TOKEN);
    verify_token(token, &state.config.user_token_hash)?;
    Ok(next.run(req).await)
}

pub async fn require_admin(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, PccsError> {
    let token = header_token(req.headers(), headers::ADMIN_TOKEN);
    verify_token(token, &state.config.admin_token_hash)?;
    Ok(next.run(req).await)
}

/// Attach `Request-ID` (client-supplied or generated UUID without dashes).
pub async fn add_request_id(req: Request<axum::body::Body>, next: Next) -> Response {
    let id = req
        .headers()
        .get(headers::REQUEST_ID)
        .and_then(|v| v.to_str().ok())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| uuid::Uuid::new_v4().simple().to_string());

    let mut response = next.run(req).await;
    if let Ok(val) = axum::http::HeaderValue::from_str(&id) {
        response.headers_mut().insert(headers::REQUEST_ID, val);
    }
    response
}

/// Node `v3EolWarning.js` — Warning header on every v3 request.
pub async fn v3_eol_warning(req: Request<axum::body::Body>, next: Next) -> Response {
    let mut response = next.run(req).await;
    if let Ok(val) = axum::http::HeaderValue::from_str(headers::V3_EOL_WARNING) {
        response.headers_mut().insert(headers::WARNING, val);
    }
    response
}
