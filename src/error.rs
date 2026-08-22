//! PCCS status codes and error type, matching Node `pccs_status_code.js` + `error.js`.

use axum::extract::rejection::JsonRejection;
use axum::extract::{FromRequest, Request};
use axum::http::header::{HeaderValue, CONTENT_TYPE};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Express `res.send(string)` labels error bodies `text/html`.
const ERROR_CONTENT_TYPE: &str = "text/html; charset=utf-8";

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
        let mut resp = (self.status, self.message).into_response();
        resp.headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static(ERROR_CONTENT_TYPE));
        resp
    }
}

/// `axum::Json` with PCCS error bodies: an oversize body is `413 Content too
/// large.`, a missing/wrong content type or unparseable JSON is
/// `400 Invalid request parameters.` — the same answers Node gives.
///
/// Body collection is bounded by `RequestTimeoutSeconds`, the body half of
/// Node's `server.requestTimeout` (the header half is hyper's
/// `header_read_timeout`); a client that stalls part-way through the body gets
/// `408`. This bounds *receiving* only — never the handler, because Node's
/// `requestTimeout` does not cancel response production and doing so here would
/// abort a slow LAZY upstream fill or an admin `/refresh` mid-write.
pub struct PccsJson<T>(pub T);

impl<T> FromRequest<crate::auth::AppState> for PccsJson<T>
where
    axum::Json<T>: FromRequest<crate::auth::AppState, Rejection = JsonRejection>,
{
    type Rejection = PccsError;

    async fn from_request(
        req: Request,
        state: &crate::auth::AppState,
    ) -> Result<Self, Self::Rejection> {
        let budget = std::time::Duration::from_secs(state.config.request_timeout_secs);
        let read = axum::Json::<T>::from_request(req, state);
        let Ok(result) = tokio::time::timeout(budget, read).await else {
            tracing::warn!("timed out reading request body");
            return Err(REQUEST_TIMEOUT);
        };
        match result {
            Ok(axum::Json(value)) => Ok(Self(value)),
            Err(rejection) => {
                if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    Err(CONTENT_TOO_LARGE)
                } else {
                    tracing::debug!("invalid JSON body: {rejection}");
                    Err(INVALID_REQ)
                }
            }
        }
    }
}

pub const SUCCESS: (u16, &str) = (200, "Operation successful.");
pub const INVALID_REQ: PccsError =
    PccsError::new(StatusCode::BAD_REQUEST, "Invalid request parameters.");
pub const UNAUTHORIZED: PccsError =
    PccsError::new(StatusCode::UNAUTHORIZED, "Authentication failed.");
pub const NO_CACHE_DATA: PccsError =
    PccsError::new(StatusCode::NOT_FOUND, "No cache data for this platform.");
pub const CONTENT_TOO_LARGE: PccsError =
    PccsError::new(StatusCode::PAYLOAD_TOO_LARGE, "Content too large.");
pub const REQUEST_TIMEOUT: PccsError =
    PccsError::new(StatusCode::REQUEST_TIMEOUT, "Request Timeout");
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
    PccsError::new(
        status(462),
        "Certificates are not available for certain TCBs.",
    )
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

/// Express `res.send(string)` sets `Content-Type: text/html; charset=utf-8`.
/// Returning a bare `&str` from axum would say `text/plain`, so success bodies
/// go through this to stay byte-for-byte compatible with Node.
pub fn text_html(status: StatusCode, body: impl Into<axum::body::Body>) -> Response {
    let mut resp = (status, body.into()).into_response();
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(ERROR_CONTENT_TYPE));
    resp
}

pub fn success_response() -> Response {
    text_html(StatusCode::OK, SUCCESS.1)
}

pub fn success_body() -> &'static str {
    SUCCESS.1
}
