//! HTTP handlers — 1:1 with Node controllers (query names, headers, status, bodies).

use crate::auth::AppState;
use crate::error::{self, PccsBytes, PccsError, PccsJson};
use crate::headers;
use crate::store::RegisteredPlatform;
use crate::validate::{self, PlatformsSource};
use axum::extract::{FromRequestParts, MatchedPath, OriginalUri, Request, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use std::collections::HashMap;

/// Query extractor with Node semantics: duplicated names keep the FIRST value
/// (`middleware/filterDuplicatedParams.js`) and a malformed query string is a
/// PCCS `400 Invalid request parameters.`, not axum's plain-text rejection.
pub struct PccsQuery(pub HashMap<String, String>);

impl<S: Send + Sync> FromRequestParts<S> for PccsQuery {
    type Rejection = PccsError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        validate::query_params(parts.uri.query()).map(Self)
    }
}

fn first<'a>(q: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    q.get(key).map(|s| s.as_str())
}

fn version(uri: &Uri) -> Result<u32, PccsError> {
    validate::api_version_from_url(uri.path())
}

fn insert(h: &mut HeaderMap, name: &'static str, value: &str) {
    if let Ok(v) = HeaderValue::from_str(value) {
        h.insert(name, v);
    }
}

fn text(status: StatusCode, headers: HeaderMap, body: impl Into<String>) -> Response {
    (status, headers, body.into()).into_response()
}

fn bytes(status: StatusCode, headers: HeaderMap, body: Vec<u8>) -> Response {
    (status, headers, body).into_response()
}

fn json_value(status: StatusCode, headers: HeaderMap, value: &Value, raw_body: &str) -> Response {
    let mut h = headers;
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(headers::CONTENT_TYPE_JSON));
    let body = if raw_body.is_empty() {
        serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec())
    } else {
        raw_body.as_bytes().to_vec()
    };
    (status, h, body).into_response()
}

// --------------- AMD KDS ---------------

fn amd_response(rec: crate::cache::AmdKdsResponse) -> Response {
    let status = StatusCode::from_u16(rec.status).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = HeaderMap::new();
    if let Some(value) = rec.content_type.as_deref() {
        insert(&mut headers, "content-type", value);
    }
    if let Some(value) = rec.content_disposition.as_deref() {
        insert(&mut headers, "content-disposition", value);
    }
    if let Some(value) = rec.retry_after.as_deref() {
        insert(&mut headers, "retry-after", value);
    }
    bytes(status, headers, rec.body)
}

fn original_path_and_query(uri: &Uri) -> String {
    match uri.query() {
        Some(query) => format!("{}?{query}", uri.path()),
        None => uri.path().to_string(),
    }
}

pub async fn get_amd_kds(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    Ok(amd_response(state.cache.get_amd_kds(&original_path_and_query(&uri)).await?))
}

pub async fn get_nvidia_rim(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    Ok(amd_response(state.cache.get_nvidia_rim(&original_path_and_query(&uri)).await?))
}

// --------------- NVIDIA OCSP ---------------

pub async fn post_nvidia_ocsp(
    State(state): State<AppState>,
    headers: HeaderMap,
    PccsBytes(body): PccsBytes,
) -> Result<Response, PccsError> {
    let content_type =
        headers.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok()).unwrap_or("");
    let media = content_type.split(';').next().unwrap_or("").trim();
    if !media.eq_ignore_ascii_case("application/ocsp-request") {
        return Err(error::INVALID_REQ);
    }
    if body.is_empty() {
        return Err(error::INVALID_REQ);
    }
    Ok(amd_response(state.cache.get_nvidia_ocsp(&body).await?))
}

// --------------- CORS ---------------

/// `Access-Control-Expose-Headers`: every custom header a browser client may
/// need to read. dcap-qvl's `getHeader` pulls the Intel issuer chains and
/// `SGX-TCBm` from collateral responses; without an expose entry the browser
/// hides non-safelisted headers even when the origin is allowed.
const CORS_EXPOSE_HEADERS: &str = concat!(
    "Retry-After, Request-ID, Warning, ",
    "SGX-TCBm, SGX-FMSPC, SGX-PCK-Certificate-CA-Type, ",
    "SGX-PCK-Certificate-Issuer-Chain, SGX-PCK-CRL-Issuer-Chain, ",
    "TCB-Info-Issuer-Chain, SGX-TCB-Info-Issuer-Chain, SGX-Enclave-Identity-Issuer-Chain"
);

fn insert_cors(headers: &mut HeaderMap) {
    insert(headers, "access-control-allow-origin", "*");
    insert(headers, "access-control-allow-methods", "GET, HEAD, POST, PUT, OPTIONS");
    insert(headers, "access-control-allow-headers", "Content-Type, user-token, admin-token");
    insert(headers, "access-control-expose-headers", CORS_EXPOSE_HEADERS);
    insert(headers, "access-control-max-age", "86400");
}

fn is_nras_path(path: &str) -> bool {
    path == "/nvidia/nras" || path.starts_with("/nvidia/nras/")
}

/// Path prefixes of the Intel collateral routers (see `create_app`).
const INTEL_PREFIXES: &[&str] =
    &["/sgx/certification/v3", "/sgx/certification/v4", "/tdx/certification/v4"];

/// CORS scope: the public, signed-collateral endpoints (Intel, AMD, NVIDIA)
/// that browser clients such as dcap-qvl fetch. Operator endpoints
/// (`platforms`, `platformcollateral`, `refresh`), `/healthz` and unmatched
/// routes are deliberately excluded.
fn is_collateral_path(path: &str) -> bool {
    // AMD KDS and NVIDIA RIM read-through caches.
    if path.starts_with("/vcek/") || path.starts_with("/vlek/") || path.starts_with("/v1/rim/") {
        return true;
    }
    // NVIDIA OCSP cache and the NRAS proxy.
    if path == "/ocsp" || is_nras_path(path) {
        return true;
    }
    // Intel collateral leaves. `GET /appraisalpolicy` is a public read; only
    // its PUT is admin-guarded, and a CORS header on that 401 is harmless.
    let Some(rest) = INTEL_PREFIXES.iter().find_map(|p| path.strip_prefix(p)) else {
        return false;
    };
    matches!(
        rest,
        "/pckcert"
            | "/pckcrl"
            | "/tcb"
            | "/qe/identity"
            | "/qve/identity"
            | "/rootcacrl"
            | "/crl"
            | "/appraisalpolicy"
    )
}

/// Collateral-scoped CORS. The matched endpoints only serve public,
/// Intel/AMD/NVIDIA-signed collateral, and auth uses non-ambient
/// `user-token`/`admin-token` headers, so a static
/// `Access-Control-Allow-Origin: *` exposes nothing sensitive and stays valid
/// on CDN-cached copies (no `Vary: Origin` needed). OPTIONS preflight is
/// answered here for collateral paths so it does not depend on a matching
/// route. `Cache-Control: no-store` stays scoped to the nonce-bound
/// `/nvidia/nras` proxy. Wraps `DefaultBodyLimit` so 413 still gets ACAO, but
/// sits inside `add_request_id` so preflight (answered without calling next)
/// still gets a fresh id.
pub async fn cors(req: Request, next: Next) -> Response {
    if !is_collateral_path(req.uri().path()) {
        return next.run(req).await;
    }
    let nras = is_nras_path(req.uri().path());
    if req.method() == Method::OPTIONS {
        let mut headers = HeaderMap::new();
        insert_cors(&mut headers);
        if nras {
            insert(&mut headers, "cache-control", "no-store");
        }
        return (StatusCode::NO_CONTENT, headers).into_response();
    }
    let mut response = next.run(req).await;
    insert_cors(response.headers_mut());
    if nras {
        insert(response.headers_mut(), "cache-control", "no-store");
    }
    response
}

// --------------- Intel collateral Cache-Control ---------------

/// MatchedPath templates (see `metrics::ROUTES`) whose responses a CDN may
/// cache: platform-independent Intel collateral. pckcert, AMD, NVIDIA, health,
/// admin and unmatched routes are deliberately absent.
const CACHEABLE_COLLATERAL: &[&str] = &[
    "/sgx/certification/v3/pckcrl",
    "/sgx/certification/v3/tcb",
    "/sgx/certification/v3/qe/identity",
    "/sgx/certification/v3/qve/identity",
    "/sgx/certification/v3/rootcacrl",
    "/sgx/certification/v4/pckcrl",
    "/sgx/certification/v4/tcb",
    "/sgx/certification/v4/qe/identity",
    "/sgx/certification/v4/qve/identity",
    "/sgx/certification/v4/rootcacrl",
    "/tdx/certification/v4/tcb",
    "/tdx/certification/v4/qe/identity",
];

/// Opt-in `Cache-Control` for cacheable collateral: `public, max-age=N` on 200,
/// `no-store` on anything else, so a CDN never keeps a 404 or 5xx. It replaces
/// any `Cache-Control` already on the response.
pub async fn collateral_cache_control(
    State(max_age): State<u64>,
    req: Request,
    next: Next,
) -> Response {
    let cacheable = matches!(*req.method(), Method::GET | Method::HEAD)
        && req
            .extensions()
            .get::<MatchedPath>()
            .is_some_and(|path| CACHEABLE_COLLATERAL.contains(&path.as_str()));
    let mut response = next.run(req).await;
    if cacheable {
        let value = if response.status() == StatusCode::OK {
            HeaderValue::from_str(&format!("public, max-age={max_age}"))
                .expect("numeric Cache-Control value")
        } else {
            HeaderValue::from_static("no-store")
        };
        response.headers_mut().insert(header::CACHE_CONTROL, value);
    }
    response
}

// --------------- NVIDIA NRAS (GPU attestation) ---------------

pub async fn post_nvidia_nras_attest_gpu(
    State(state): State<AppState>,
    PccsJson(body): PccsJson<Value>,
) -> Result<Response, PccsError> {
    Ok(amd_response(state.cache.get_nvidia_nras(&body).await?))
}

// --------------- pckcert ---------------

pub async fn get_pckcert(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    let version = version(&uri)?;
    let qeid = validate::qeid(first(&q, "qeid"))?;
    let cpusvn = validate::cpusvn(first(&q, "cpusvn"))?;
    let pcesvn = validate::pcesvn(first(&q, "pcesvn"))?;
    let pceid = validate::pceid(first(&q, "pceid"))?;
    let _enc = validate::encrypted_ppid(first(&q, "encrypted_ppid"))?;

    let rec =
        state.cache.get_pckcert(&qeid, &cpusvn, &pcesvn, &pceid, _enc.as_deref(), version).await?;

    let mut h = HeaderMap::new();
    insert(&mut h, headers::SGX_TCBM, &rec.tcbm);
    insert(&mut h, headers::SGX_FMSPC, &rec.fmspc);
    insert(&mut h, headers::SGX_PCK_CERTIFICATE_CA_TYPE, &rec.ca);
    insert(&mut h, headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN, &rec.issuer_chain);
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(headers::CONTENT_TYPE_PEM));
    Ok(text(StatusCode::OK, h, rec.cert))
}

// --------------- pckcrl ---------------

pub async fn get_pckcrl(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    let version = version(&uri)?;
    let ca = validate::pck_ca(first(&q, "ca"))?;
    let encoding = first(&q, "encoding").map(|s| s.to_string());
    let rec = state.cache.get_pckcrl(&ca, version).await?;

    let mut h = HeaderMap::new();
    insert(&mut h, headers::SGX_PCK_CRL_ISSUER_CHAIN, &rec.issuer_chain);

    let der = encoding.as_deref().map(|s| s.eq_ignore_ascii_case("DER")).unwrap_or(false);
    if der {
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(headers::CONTENT_TYPE_CRL));
        Ok(bytes(StatusCode::OK, h, rec.pckcrl))
    } else {
        // Node: Buffer.from(pckcrl, 'utf8').toString('hex') + application/x-pem-file
        h.insert(header::CONTENT_TYPE, HeaderValue::from_static(headers::CONTENT_TYPE_PEM));
        Ok(text(StatusCode::OK, h, hex::encode(&rec.pckcrl)))
    }
}

// --------------- tcb ---------------

async fn get_tcb(
    state: &AppState,
    q: &HashMap<String, String>,
    uri: &Uri,
    prod_type: u8,
) -> Result<Response, PccsError> {
    let version = version(uri)?;
    let fmspc = validate::fmspc(first(q, "fmspc"))?;
    let update = validate::update_type(first(q, "update"), false)?;
    let rec = state.cache.get_tcb(prod_type, &fmspc, version, update).await?;
    let mut h = HeaderMap::new();
    insert(&mut h, headers::tcb_issuer_chain_name(version), &rec.issuer_chain);
    Ok(json_value(StatusCode::OK, h, &rec.tcbinfo, &rec.raw_body))
}

pub async fn get_sgx_tcb(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    get_tcb(&state, &q, &uri, 0).await
}

pub async fn get_tdx_tcb(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    get_tcb(&state, &q, &uri, 1).await
}

// --------------- identity ---------------

async fn get_identity(
    state: &AppState,
    q: &HashMap<String, String>,
    uri: &Uri,
    enclave_id: u8,
) -> Result<Response, PccsError> {
    let version = version(uri)?;
    let update = validate::update_type(first(q, "update"), false)?;
    let rec = state.cache.get_identity(enclave_id, version, update).await?;
    let mut h = HeaderMap::new();
    insert(&mut h, headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN, &rec.issuer_chain);
    Ok(json_value(StatusCode::OK, h, &rec.identity, &rec.raw_body))
}

pub async fn get_qe_identity(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    get_identity(&state, &q, &uri, 1).await
}

pub async fn get_qve_identity(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    get_identity(&state, &q, &uri, 2).await
}

pub async fn get_tdqe_identity(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    get_identity(&state, &q, &uri, 3).await
}

// --------------- rootcacrl / crl ---------------

pub async fn get_rootcacrl(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    let version = version(&uri)?;
    let crl = state.cache.get_rootcacrl(version).await?;
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(headers::CONTENT_TYPE_CRL));
    // Node: hex-encode for backward compatibility
    Ok(text(StatusCode::OK, h, hex::encode(crl)))
}

pub async fn get_crl(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    let version = version(&uri)?;
    let Some(crl_uri) = first(&q, "uri") else {
        tracing::error!("uri is not valid : ");
        return Err(error::INVALID_REQ);
    };
    if !validate::is_valid_crl_uri(crl_uri) {
        tracing::error!("uri is not valid : {crl_uri}");
        return Err(error::INVALID_REQ);
    }
    let crl = state.cache.get_crl(crl_uri, version).await?;
    let mut h = HeaderMap::new();
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(headers::CONTENT_TYPE_CRL));
    Ok(bytes(StatusCode::OK, h, crl))
}

// --------------- platforms ---------------

pub async fn post_platforms(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
    PccsJson(body): PccsJson<Value>,
) -> Result<Response, PccsError> {
    let _update = validate::update_type(first(&q, "update"), true)?;
    // Node `PLATFORM_REG_SCHEMA` is `type: 'object'`; an array is a 400.
    let reg = validate::platform_reg(&body)?;

    state
        .cache
        .register_platform(
            RegisteredPlatform {
                qe_id: reg.qe_id,
                pce_id: reg.pce_id,
                cpu_svn: reg.cpu_svn,
                pce_svn: reg.pce_svn,
                enc_ppid: reg.enc_ppid,
                platform_manifest: reg.platform_manifest,
                state: 0,
            },
            _update,
        )
        .await?;

    Ok(error::success_response())
}

pub async fn get_platforms(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
) -> Result<Response, PccsError> {
    let src = validate::platforms_source(first(&q, "source"))?;
    // Every branch is a full RocksDB prefix scan; keep it off the runtime.
    let cache = state.cache.clone();
    let platforms_json: Value = tokio::task::spawn_blocking(move || match src {
        PlatformsSource::Reg => cache
            .store
            .take_registered(0)
            .map(|l| serde_json::to_value(l).unwrap_or(Value::Array(vec![]))),
        PlatformsSource::RegNa => cache
            .store
            .take_registered(1)
            .map(|l| serde_json::to_value(l).unwrap_or(Value::Array(vec![]))),
        PlatformsSource::Fmspc(fmspcs) => {
            Ok(serde_json::to_value(cache.store.cached_platforms_by_fmspc(&fmspcs))
                .unwrap_or(Value::Array(vec![])))
        }
    })
    .await
    .map_err(|_| error::INTERNAL_ERROR)??;
    let count = platforms_json.as_array().map(|a| a.len()).unwrap_or(0);
    let mut h = HeaderMap::new();
    insert(&mut h, headers::PLATFORM_COUNT, &count.to_string());
    // Node reaches Express `res.json` here (`res.send(array)` delegates to it),
    // which labels the body `application/json; charset=utf-8` — unlike the
    // collateral GETs, which set the bare `application/json` themselves.
    h.insert(header::CONTENT_TYPE, HeaderValue::from_static(headers::CONTENT_TYPE_JSON_UTF8));
    let body = serde_json::to_vec(&platforms_json).unwrap_or_else(|_| b"[]".to_vec());
    Ok((StatusCode::OK, h, body).into_response())
}

// --------------- platformcollateral ---------------

pub async fn put_platform_collateral(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    PccsJson(body): PccsJson<Value>,
) -> Result<Response, PccsError> {
    let version = version(&uri)?;
    state.cache.store.put_platform_collateral(&body, version)?;
    Ok(error::success_response())
}

// --------------- refresh ---------------

pub async fn refresh(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
) -> Result<Response, PccsError> {
    state.cache.refresh(first(&q, "type"), first(&q, "fmspc")).await?;
    Ok(error::success_response())
}

// --------------- appraisalpolicy ---------------

pub async fn put_appraisal_policy(
    State(state): State<AppState>,
    PccsJson(body): PccsJson<Value>,
) -> Result<Response, PccsError> {
    let id = state.cache.store.put_appraisal_policy(&body)?;
    Ok(error::text_html(StatusCode::OK, id))
}

pub async fn get_appraisal_policy(
    State(state): State<AppState>,
    PccsQuery(q): PccsQuery,
) -> Result<Response, PccsError> {
    let fmspc = validate::fmspc(first(&q, "fmspc"))?;
    let policies = state.cache.store.get_default_policies(&fmspc)?;
    Ok(error::text_html(StatusCode::OK, policies))
}

pub async fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}

/// Paths that consume a request body. Everything else — every GET, `/refresh`,
/// and unmatched routes — must not carry one.
fn route_expects_body(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::POST, "/sgx/certification/v3/platforms" | "/sgx/certification/v4/platforms")
            | (
                &Method::PUT,
                "/sgx/certification/v3/platformcollateral"
                    | "/sgx/certification/v4/platformcollateral"
            )
            | (
                &Method::PUT,
                "/sgx/certification/v3/appraisalpolicy" | "/sgx/certification/v4/appraisalpolicy"
            )
            | (&Method::POST, "/ocsp")
            | (&Method::POST, "/nvidia/nras/attest/gpu")
    )
}

/// A client advertised a body: non-zero Content-Length, or a chunked body.
fn request_carries_body(headers: &HeaderMap) -> bool {
    if let Some(len) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
    {
        if len > 0 {
            return true;
        }
    }
    headers
        .get(header::TRANSFER_ENCODING)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.to_ascii_lowercase().split(',').any(|part| part.trim() == "chunked"))
}

/// Routes that take no body answer 413 when the request advertises one.
pub async fn reject_unexpected_body(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let has_body = request_carries_body(req.headers());
    if has_body && !route_expects_body(&method, &path) {
        return error::CONTENT_TOO_LARGE.into_response();
    }
    let response = next.run(req).await;
    response
}

/// `/pckcrl/` and the like must not match `/pckcrl`. A trailing slash is 404.
pub async fn reject_trailing_slash(req: Request, next: Next) -> Response {
    let path = req.uri().path();
    if path.len() > 1 && path.ends_with('/') {
        return StatusCode::NOT_FOUND.into_response();
    }
    let response = next.run(req).await;
    response
}
