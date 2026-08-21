//! PCCS status codes and error type, matching Node `pccs_status_code.js` + `error.js`.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug, Clone)]
pub struct PccsError {
    pub status: StatusCode,
    pub message: &'static str,
}

impl PccsError {
    pub const fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
}

impl std::fmt::Display for PccsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}

impl std::error::Error for PccsError {}

impl IntoResponse for PccsError {
    fn into_response(self) -> Response {
        (self.status, self.message).into_response()
    }
}

pub const SUCCESS: (u16, &str) = (200, "Operation successful.");
pub const INVALID_REQ: PccsError =
    PccsError::new(StatusCode::BAD_REQUEST, "Invalid request parameters.");
pub const UNAUTHORIZED: PccsError =
    PccsError::new(StatusCode::UNAUTHORIZED, "Authentication failed.");
pub const NO_CACHE_DATA: PccsError = PccsError::new(
    StatusCode::NOT_FOUND,
    "No cache data for this platform.",
);
pub const CONTENT_TOO_LARGE: PccsError =
    PccsError::new(StatusCode::PAYLOAD_TOO_LARGE, "Content too large.");
fn status(code: u16) -> StatusCode {
    StatusCode::from_u16(code).expect("valid PCCS status")
}

pub fn integrity_error() -> PccsError {
    PccsError::new(status(460), "The integrity of the data can't be verified.")
}
pub fn platform_unknown() -> PccsError {
    PccsError::new(status(461), "The platform was not found in the cache.")
}
pub fn certs_unavailable() -> PccsError {
    PccsError::new(status(462), "Certificates are not available for certain TCBs.")
}
pub const PCS_V3_REACHED_EOL: PccsError = PccsError::new(
    StatusCode::GONE,
    "The Intel PCS API version 3 reached planned EOL. Accordingly, collateral from this API version cannot be retrieved any longer.",
);
pub const INTERNAL_ERROR: PccsError = PccsError::new(
    StatusCode::INTERNAL_SERVER_ERROR,
    "Internal server error occurred.",
);
pub const SERVICE_UNAVAILABLE: PccsError = PccsError::new(
    StatusCode::SERVICE_UNAVAILABLE,
    "Server is currently unable to process the request.",
);
pub const PCS_ACCESS_FAILURE: PccsError = PccsError::new(
    StatusCode::BAD_GATEWAY,
    "Unable to retrieve the collateral from the Intel SGX PCS.",
);

pub fn success_body() -> &'static str {
    SUCCESS.1
}
