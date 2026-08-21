//! HTTP handlers — 1:1 with Node controllers (query names, headers, status, bodies).

use crate::auth::AppState;
use crate::error::{self, PccsError};
use crate::headers;
use crate::store::RegisteredPlatform;
use crate::validate::{self, PlatformsSource};
use axum::extract::{OriginalUri, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::Value;
use std::collections::HashMap;

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

fn json_value(status: StatusCode, headers: HeaderMap, value: &Value) -> Response {
    let mut h = headers;
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(headers::CONTENT_TYPE_JSON),
    );
    let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    (status, h, body).into_response()
}

// --------------- pckcert ---------------

pub async fn get_pckcert(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
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
    Query(q): Query<HashMap<String, String>>,
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
    let rec = state.cache.get_tcb(prod_type, &fmspc, version, update).await?;
    let mut h = HeaderMap::new();
    insert(&mut h, headers::tcb_issuer_chain_name(version), &rec.issuer_chain);
    Ok(json_value(StatusCode::OK, h, &rec.tcbinfo))
}

pub async fn get_sgx_tcb(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    get_tcb(&state, &q, &uri, 0).await
}

pub async fn get_tdx_tcb(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
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
    insert(
        &mut h,
        headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN,
        &rec.issuer_chain,
    );
    Ok(json_value(StatusCode::OK, h, &rec.identity))
}

pub async fn get_qe_identity(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    get_identity(&state, &q, &uri, 1).await
}

pub async fn get_qve_identity(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    OriginalUri(uri): OriginalUri,
) -> Result<Response, PccsError> {
    get_identity(&state, &q, &uri, 2).await
}

pub async fn get_tdqe_identity(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
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
    Query(q): Query<HashMap<String, String>>,
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
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<Value>,
) -> Result<Response, PccsError> {
    let _update = validate::update_type(first(&q, "update"), true)?;

    // Node schema is a single object (PLATFORM_REG_SCHEMA). Also accept a 1-element array.
    let obj = if let Some(arr) = body.as_array() {
        arr.first().cloned().ok_or(error::INVALID_REQ)?
    } else if body.is_object() {
        body
    } else {
        return Err(error::INVALID_REQ);
    };

    let qe_id = obj
        .get("qe_id")
        .and_then(|x| x.as_str())
        .ok_or(error::INVALID_REQ)?;
    let pce_id = obj
        .get("pce_id")
        .and_then(|x| x.as_str())
        .ok_or(error::INVALID_REQ)?;
    if qe_id.is_empty() || qe_id.len() > 260 {
        return Err(error::INVALID_REQ);
    }
    let _ = validate::pceid(Some(pce_id))?;

    let manifest = obj
        .get("platform_manifest")
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let (cpu_svn, pce_svn, enc_ppid, manifest) = if !manifest.is_empty() {
        (String::new(), String::new(), String::new(), manifest.to_string())
    } else {
        let cpu = obj.get("cpu_svn").and_then(|x| x.as_str()).unwrap_or("");
        let pce = obj.get("pce_svn").and_then(|x| x.as_str()).unwrap_or("");
        let enc = obj.get("enc_ppid").and_then(|x| x.as_str()).unwrap_or("");
        if cpu.is_empty() || pce.is_empty() || enc.is_empty() {
            return Err(error::INVALID_REQ);
        }
        let cpu = validate::cpusvn(Some(cpu))?;
        let pce = validate::pcesvn(Some(pce))?;
        let enc = validate::encrypted_ppid(Some(enc))?.unwrap_or_default();
        (cpu, pce, enc, String::new())
    };

    state
        .cache
        .register_platform(
            RegisteredPlatform {
                qe_id: qe_id.to_string(),
                pce_id: pce_id.to_string(),
                cpu_svn,
                pce_svn,
                enc_ppid,
                platform_manifest: manifest,
                state: 0,
            },
            _update,
        )
        .await?;

    Ok((StatusCode::OK, error::success_body()).into_response())
}

pub async fn get_platforms(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response, PccsError> {
    let src = validate::platforms_source(first(&q, "source"))?;
    let platforms_json: Value = match src {
        PlatformsSource::Reg => {
            let list = state.cache.store.take_registered(0);
            serde_json::to_value(list).unwrap_or(Value::Array(vec![]))
        }
        PlatformsSource::RegNa => {
            let list = state.cache.store.take_registered(1);
            serde_json::to_value(list).unwrap_or(Value::Array(vec![]))
        }
        PlatformsSource::Fmspc(fmspcs) => {
            let list = state.cache.store.cached_platforms_by_fmspc(&fmspcs);
            serde_json::to_value(list).unwrap_or(Value::Array(vec![]))
        }
    };
    let count = platforms_json.as_array().map(|a| a.len()).unwrap_or(0);
    let mut h = HeaderMap::new();
    insert(&mut h, headers::PLATFORM_COUNT, &count.to_string());
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(headers::CONTENT_TYPE_JSON),
    );
    let body = serde_json::to_vec(&platforms_json).unwrap_or_else(|_| b"[]".to_vec());
    Ok((StatusCode::OK, h, body).into_response())
}

// --------------- platformcollateral ---------------

pub async fn put_platform_collateral(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Json(body): Json<Value>,
) -> Result<Response, PccsError> {
    let version = version(&uri)?;
    state.cache.store.put_platform_collateral(&body, version)?;
    Ok((StatusCode::OK, error::success_body()).into_response())
}

// --------------- refresh ---------------

pub async fn refresh(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response, PccsError> {
    let typ = first(&q, "type");
    if let Some(t) = typ {
        if t != "certs" {
            tracing::error!("Invalid refresh type : {t}");
            return Err(error::INVALID_REQ);
        }
    }
    state.cache.refresh(typ, first(&q, "fmspc")).await?;
    Ok((StatusCode::OK, error::success_body()).into_response())
}

// --------------- appraisalpolicy ---------------

pub async fn put_appraisal_policy(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Result<Response, PccsError> {
    let id = state.cache.store.put_appraisal_policy(&body)?;
    Ok((StatusCode::OK, id).into_response())
}

pub async fn get_appraisal_policy(
    State(state): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Result<Response, PccsError> {
    let fmspc = validate::fmspc(first(&q, "fmspc"))?;
    let policies = state.cache.store.get_default_policies(&fmspc)?;
    Ok((StatusCode::OK, policies).into_response())
}

pub async fn not_found() -> Response {
    StatusCode::NOT_FOUND.into_response()
}
