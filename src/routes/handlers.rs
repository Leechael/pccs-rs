//! HTTP handlers — 1:1 with Node controllers (query names, headers, status, bodies).

use crate::auth::AppState;
use crate::error::{self, PccsError, PccsJson};
use crate::headers;
use crate::store::RegisteredPlatform;
use crate::validate::{self, PlatformsSource};
use axum::extract::{FromRequestParts, OriginalUri, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
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
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(headers::CONTENT_TYPE_JSON),
    );
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

pub async fn get_amd_kds(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    let path_and_query = match uri.query() {
        Some(query) => format!("{}?{query}", uri.path()),
        None => uri.path().to_string(),
    };
    Ok(amd_response(
        state.cache.get_amd_kds(&path_and_query).await?,
    ))
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

    let rec = state
        .cache
        .get_pckcert(&qeid, &cpusvn, &pcesvn, &pceid, _enc.as_deref(), version)
        .await?;

    let mut h = HeaderMap::new();
    insert(&mut h, headers::SGX_TCBM, &rec.tcbm);
    insert(&mut h, headers::SGX_FMSPC, &rec.fmspc);
    insert(&mut h, headers::SGX_PCK_CERTIFICATE_CA_TYPE, &rec.ca);
    insert(
        &mut h,
        headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
        &rec.issuer_chain,
    );
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(headers::CONTENT_TYPE_PEM),
    );
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

    let der = encoding
        .as_deref()
        .map(|s| s.eq_ignore_ascii_case("DER"))
        .unwrap_or(false);
    if der {
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(headers::CONTENT_TYPE_CRL),
        );
        Ok(bytes(StatusCode::OK, h, rec.pckcrl))
    } else {
        // Node: Buffer.from(pckcrl, 'utf8').toString('hex') + application/x-pem-file
        h.insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static(headers::CONTENT_TYPE_PEM),
        );
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
    let rec = state
        .cache
        .get_tcb(prod_type, &fmspc, version, update)
        .await?;
    let mut h = HeaderMap::new();
    insert(
        &mut h,
        headers::tcb_issuer_chain_name(version),
        &rec.issuer_chain,
    );
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
    let rec = state
        .cache
        .get_identity(enclave_id, version, update)
        .await?;
    let mut h = HeaderMap::new();
    insert(
        &mut h,
        headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN,
        &rec.issuer_chain,
    );
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
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(headers::CONTENT_TYPE_CRL),
    );
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
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(headers::CONTENT_TYPE_CRL),
    );
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
        PlatformsSource::Fmspc(fmspcs) => Ok(serde_json::to_value(
            cache.store.cached_platforms_by_fmspc(&fmspcs),
        )
        .unwrap_or(Value::Array(vec![]))),
    })
    .await
    .map_err(|_| error::INTERNAL_ERROR)??;
    let count = platforms_json.as_array().map(|a| a.len()).unwrap_or(0);
    let mut h = HeaderMap::new();
    insert(&mut h, headers::PLATFORM_COUNT, &count.to_string());
    // Node reaches Express `res.json` here (`res.send(array)` delegates to it),
    // which labels the body `application/json; charset=utf-8` — unlike the
    // collateral GETs, which set the bare `application/json` themselves.
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(headers::CONTENT_TYPE_JSON_UTF8),
    );
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
    state
        .cache
        .refresh(first(&q, "type"), first(&q, "fmspc"))
        .await?;
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
