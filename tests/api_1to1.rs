//! 1:1 HTTP API tests against the in-process axum app (no network, no Intel PCS).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use http_body_util::BodyExt;
use pccs_rs::config::CacheMode;
use pccs_rs::config::{Config, DEFAULT_ADMIN_TOKEN, DEFAULT_USER_TOKEN};
use pccs_rs::{create_app_from_config, headers};
use serde_json::json;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

fn app() -> axum::Router {
    create_app_from_config(Config::test_default())
}

async fn send(
    app: axum::Router,
    req: Request<Body>,
) -> (StatusCode, axum::http::HeaderMap, bytes::Bytes) {
    let resp = app.oneshot(req).await.expect("oneshot");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    (status, headers, body)
}

fn get(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .body(Body::empty())
        .unwrap()
}

fn get_admin(path: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(path)
        .header(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)
        .body(Body::empty())
        .unwrap()
}

fn post_user(path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(path)
        .header(headers::USER_TOKEN, DEFAULT_USER_TOKEN)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

/// A synthetic PCK certificate carrying the Intel SGX X.509 extension
/// (`1.2.840.113741.1.13.1`): PPID 0x11*16, PCEID 4444, FMSPC 1234567890AB,
/// CPUSVN 0x22*16, PCESVN 0x3333, issued by a "PCK Platform CA".
/// PCK cert selection reads its TCB from here, never from `tcbm`.
const PCK_PEM: &str = "-----BEGIN CERTIFICATE-----\nMIICPDCCAjOgAwIBAgIBATAKBggqhkjOPQQDAjAkMSIwIAYDVQQDDBlJbnRlbCBT\nR1ggUENLIFBsYXRmb3JtIENBMAAwJDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBD\nZXJ0aWZpY2F0ZTAAo4IByzCCAccwggHDBgkqhkiG+E0BDQEEggG0MIIBsDAeBgoq\nhkiG+E0BDQEBBBARERERERERERERERERERERMBAGCiqGSIb4TQENAQMEAkREMBQG\nCiqGSIb4TQENAQQEBhI0VniQqzCCAWQGCiqGSIb4TQENAQIwggFUMBAGCyqGSIb4\nTQENAQIBAgEiMBAGCyqGSIb4TQENAQICAgEiMBAGCyqGSIb4TQENAQIDAgEiMBAG\nCyqGSIb4TQENAQIEAgEiMBAGCyqGSIb4TQENAQIFAgEiMBAGCyqGSIb4TQENAQIG\nAgEiMBAGCyqGSIb4TQENAQIHAgEiMBAGCyqGSIb4TQENAQIIAgEiMBAGCyqGSIb4\nTQENAQIJAgEiMBAGCyqGSIb4TQENAQIKAgEiMBAGCyqGSIb4TQENAQILAgEiMBAG\nCyqGSIb4TQENAQIMAgEiMBAGCyqGSIb4TQENAQINAgEiMBAGCyqGSIb4TQENAQIO\nAgEiMBAGCyqGSIb4TQENAQIPAgEiMBAGCyqGSIb4TQENAQIQAgEiMBEGCyqGSIb4\nTQENAQIRAgIzMzAfBgsqhkiG+E0BDQECEgQQIiIiIiIiIiIiIiIiIiIiIjAAAwEA\n-----END CERTIFICATE-----\n";
const PCK_CPUSVN: &str = "22222222222222222222222222222222";
const PCK_PCESVN: &str = "3333";
const PCK_PCEID: &str = "4444";
const PCK_FMSPC: &str = "1234567890AB";

/// A TCB info whose single level exactly matches `PCK_PEM`'s TCB.
fn pck_tcb_info() -> serde_json::Value {
    let comps: Vec<serde_json::Value> = (0..16).map(|_| json!({ "svn": 0x22 })).collect();
    json!({
        "id": "SGX",
        "fmspc": PCK_FMSPC,
        "pceId": PCK_PCEID,
        "tcbType": 0,
        "tcbLevels": [{
            "tcb": { "sgxtcbcomponents": comps, "pcesvn": 0x3333 },
            "tcbStatus": "UpToDate"
        }]
    })
}

/// A structurally valid JWS-like appraisal policy (Node parses segment[1] as
/// base64url JSON and reads `policy_payload.policy_array[].environment.class_id`).
fn jws_policy(class_id: &str, marker: &str) -> String {
    use base64::Engine;
    let payload = json!({
        "policy_payload": json!({
            "policy_array": [{ "environment": { "class_id": class_id } }],
            "marker": marker
        })
        .to_string()
    });
    let seg = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.to_string());
    format!("eyJhbGciOiJFUzI1NiJ9.{seg}.c2lnbmF0dXJl")
}

const CLASS_ID_SGX: &str = "3123ec35-8d38-4ea5-87a5-d6c48b567570";

fn put_admin(path: &str, body: serde_json::Value) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(path)
        .header(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap()
}

const PCKCERT: &str = "/sgx/certification/v4/pckcert?qeid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&cpusvn=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&pcesvn=CCCC&pceid=DDDD";
const TCB: &str = "/sgx/certification/v4/tcb?fmspc=ABCDABCDABCD";
const QE: &str = "/sgx/certification/v4/qe/identity";
const PCKCRL: &str = "/sgx/certification/v4/pckcrl?ca=processor";

#[tokio::test]
async fn every_documented_route_is_registered() {
    let routes: &[(&str, &str)] = &[
        ("POST", "/sgx/certification/v3/platforms"),
        ("GET", "/sgx/certification/v3/platforms"),
        ("PUT", "/sgx/certification/v3/platformcollateral"),
        ("GET", "/sgx/certification/v3/pckcert"),
        ("GET", "/sgx/certification/v3/pckcrl"),
        ("GET", "/sgx/certification/v3/tcb"),
        ("GET", "/sgx/certification/v3/qe/identity"),
        ("GET", "/sgx/certification/v3/qve/identity"),
        ("GET", "/sgx/certification/v3/rootcacrl"),
        ("GET", "/sgx/certification/v3/crl"),
        ("POST", "/sgx/certification/v3/refresh"),
        ("GET", "/sgx/certification/v3/refresh"),
        ("PUT", "/sgx/certification/v3/appraisalpolicy"),
        ("GET", "/sgx/certification/v3/appraisalpolicy"),
        ("POST", "/sgx/certification/v4/platforms"),
        ("GET", "/sgx/certification/v4/platforms"),
        ("PUT", "/sgx/certification/v4/platformcollateral"),
        ("GET", "/sgx/certification/v4/pckcert"),
        ("GET", "/sgx/certification/v4/pckcrl"),
        ("GET", "/sgx/certification/v4/tcb"),
        ("GET", "/sgx/certification/v4/qe/identity"),
        ("GET", "/sgx/certification/v4/qve/identity"),
        ("GET", "/sgx/certification/v4/rootcacrl"),
        ("GET", "/sgx/certification/v4/crl"),
        ("POST", "/sgx/certification/v4/refresh"),
        ("GET", "/sgx/certification/v4/refresh"),
        ("PUT", "/sgx/certification/v4/appraisalpolicy"),
        ("GET", "/sgx/certification/v4/appraisalpolicy"),
        ("GET", "/tdx/certification/v4/tcb"),
        ("GET", "/tdx/certification/v4/qe/identity"),
    ];

    for (method, path) in routes {
        let req = Request::builder()
            .method(*method)
            .uri(*path)
            .header(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)
            .header(headers::USER_TOKEN, DEFAULT_USER_TOKEN)
            .header("content-type", "application/json")
            .body(if *method == "GET" {
                Body::empty()
            } else {
                Body::from("{}")
            })
            .unwrap();
        let (status, _, _) = send(app(), req).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {path} should be registered, got {status}"
        );
        assert_ne!(
            status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path} method not allowed"
        );
    }
}

#[tokio::test]
async fn unknown_route_is_404() {
    let (status, headers, _) = send(app(), get("/no/such/route")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(headers.get(headers::REQUEST_ID).is_some());
    assert!(headers.get("x-powered-by").is_none());
}

/// Node `addRequestId.js` looks the header up as `Request-ID` on the
/// already-lowercased `req.headers`, so it never finds one: every response
/// carries a freshly generated UUID. A client-supplied id is not echoed.
#[tokio::test]
async fn request_id_is_always_generated() {
    let req = Request::builder()
        .method("GET")
        .uri("/no/such/route")
        .header(headers::REQUEST_ID, "abc123clientid")
        .body(Body::empty())
        .unwrap();
    let (_, headers, _) = send(app(), req).await;
    let id = headers
        .get(headers::REQUEST_ID)
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_ne!(id, "abc123clientid");
    assert_eq!(id.len(), 32, "uuid without dashes");
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));

    let (_, headers2, _) = send(app(), get("/no/such/route")).await;
    assert_ne!(
        headers2.get(headers::REQUEST_ID).unwrap().to_str().unwrap(),
        id
    );
}

#[tokio::test]
async fn admin_auth_missing_and_wrong_are_401() {
    for path in [
        "/sgx/certification/v4/platforms",
        "/sgx/certification/v4/refresh",
    ] {
        let (status, _, body) = send(app(), get(path)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} missing token");
        assert_eq!(body.as_ref(), b"Authentication failed.");

        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header(headers::ADMIN_TOKEN, "wrong")
            .body(Body::empty())
            .unwrap();
        let (status, _, body) = send(app(), req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} wrong token");
        assert_eq!(body.as_ref(), b"Authentication failed.");
    }

    let (status, _, body) = send(app(), get_admin("/sgx/certification/v4/refresh")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"Operation successful.");
}

/// An unset token hash must fail closed: the endpoint answers 401 even when the
/// client sends the token that the built-in dev hash would accept.
#[tokio::test]
async fn unset_token_hash_rejects_every_request() {
    let mut cfg = Config::test_default();
    cfg.admin_token_hash = String::new();
    cfg.user_token_hash = "not-a-sha512-hash".into();
    let router = app_cfg(cfg);

    let (status, _, body) = send(
        router.clone(),
        get_admin("/sgx/certification/v4/platforms?source=reg"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.as_ref(), b"Authentication failed.");

    let (status, _, _) = send(
        router,
        post_user("/sgx/certification/v4/platforms", json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn oversize_and_malformed_bodies_are_pccs_errors() {
    let mut cfg = Config::test_default();
    cfg.max_body_size = 1024;
    let router = app_cfg(cfg);

    let big = Request::builder()
        .method("PUT")
        .uri("/sgx/certification/v4/platformcollateral")
        .header(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)
        .header("content-type", "application/json")
        .body(Body::from(format!("{{\"x\":\"{}\"}}", "a".repeat(4096))))
        .unwrap();
    let (status, h, body) = send(router.clone(), big).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body.as_ref(), b"Content too large.");
    assert_eq!(
        h.get(axum::http::header::CONTENT_TYPE).unwrap(),
        "text/html; charset=utf-8"
    );

    for (ctype, payload) in [("application/json", "{not json"), ("text/plain", "{}")] {
        let req = Request::builder()
            .method("PUT")
            .uri("/sgx/certification/v4/platformcollateral")
            .header(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)
            .header("content-type", ctype)
            .body(Body::from(payload))
            .unwrap();
        let (status, _, body) = send(router.clone(), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{ctype}");
        assert_eq!(body.as_ref(), b"Invalid request parameters.");
    }
}

#[tokio::test]
async fn user_auth_on_post_platforms() {
    let req = Request::builder()
        .method("POST")
        .uri("/sgx/certification/v4/platforms")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let (status, _, _) = send(app(), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn seeded_v4_pckcert_tcb_identity_pckcrl_200_with_intel_headers() {
    // pckcert
    let (status, h, body) = send(app(), get(PCKCERT)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "pckcert {}",
        String::from_utf8_lossy(&body)
    );
    assert!(h.get(headers::SGX_TCBM).is_some());
    assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), "ABCDABCDABCD");
    // The seed says "processor" in lowercase; every writer normalises the CA
    // type, so the served header must be the uppercase PROCESSOR / PLATFORM
    // that Intel's clients expect.
    assert_eq!(
        h.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).unwrap(),
        "PROCESSOR"
    );
    assert!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).is_some());
    assert_eq!(
        h.get(axum::http::header::CONTENT_TYPE).unwrap(),
        headers::CONTENT_TYPE_PEM
    );
    assert!(h.get(headers::REQUEST_ID).is_some());
    assert!(body
        .windows(b"BEGIN CERTIFICATE".len())
        .any(|w| w == b"BEGIN CERTIFICATE"));
    assert!(h.get("x-powered-by").is_none());

    // tcb
    let (status, h, body) = send(app(), get(TCB)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::TCB_INFO_ISSUER_CHAIN).is_some());
    assert_eq!(
        h.get(axum::http::header::CONTENT_TYPE).unwrap(),
        headers::CONTENT_TYPE_JSON
    );
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v.get("tcbInfo").is_some());

    // qe identity
    let (status, h, body) = send(app(), get(QE)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN).is_some());
    assert_eq!(
        h.get(axum::http::header::CONTENT_TYPE).unwrap(),
        headers::CONTENT_TYPE_JSON
    );
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v.get("enclaveIdentity").is_some());

    // pckcrl
    let (status, h, _) = send(app(), get(PCKCRL)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::SGX_PCK_CRL_ISSUER_CHAIN).is_some());
    assert_eq!(
        h.get(axum::http::header::CONTENT_TYPE).unwrap(),
        headers::CONTENT_TYPE_PEM
    );

    // pckcrl DER
    let (status, h, _) = send(
        app(),
        get("/sgx/certification/v4/pckcrl?ca=platform&encoding=DER"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.get(axum::http::header::CONTENT_TYPE).unwrap(),
        headers::CONTENT_TYPE_CRL
    );
}

#[tokio::test]
async fn v3_requests_include_warning_header() {
    let (status, h, _) = send(
        app(),
        get("/sgx/certification/v3/pckcert?qeid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&cpusvn=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&pcesvn=CCCC&pceid=DDDD"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let warn = h
        .get(headers::WARNING)
        .expect("Warning header")
        .to_str()
        .unwrap();
    assert!(warn.contains("PCS API version 3 is no longer available"));
    assert!(warn.starts_with("299 - "));

    // v3 tcb uses SGX-TCB-Info-Issuer-Chain (not TCB-Info-Issuer-Chain)
    let (status, h, _) = send(app(), get("/sgx/certification/v3/tcb?fmspc=ABCDABCDABCD")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::WARNING).is_some());
    assert!(h.get(headers::SGX_TCB_INFO_ISSUER_CHAIN).is_some());
    assert!(h.get(headers::TCB_INFO_ISSUER_CHAIN).is_none());
}

#[tokio::test]
async fn v3_cache_miss_is_410() {
    let (status, h, body) = send(app(), get("/sgx/certification/v3/tcb?fmspc=FFFFFFFFFFFF")).await;
    assert_eq!(status, StatusCode::GONE);
    assert!(h.get(headers::WARNING).is_some());
    assert!(String::from_utf8_lossy(&body).contains("planned EOL"));
}

#[tokio::test]
async fn v4_cache_miss_is_404() {
    let (status, _, body) = send(app(), get("/sgx/certification/v4/tcb?fmspc=FFFFFFFFFFFF")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body.as_ref(), b"No cache data for this platform.");
}

#[tokio::test]
async fn invalid_query_params_are_400() {
    let cases = [
        "/sgx/certification/v4/pckcert?qeid=&cpusvn=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&pcesvn=CCCC&pceid=DDDD",
        "/sgx/certification/v4/pckcert?qeid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&cpusvn=bad&pcesvn=CCCC&pceid=DDDD",
        "/sgx/certification/v4/pckcrl?ca=invalidCa",
        "/sgx/certification/v4/tcb?fmspc=invalidFmspc",
        "/sgx/certification/v4/tcb?fmspc=ABCDABCDABCD&update=all",
        "/sgx/certification/v4/qe/identity?update=invalidUpdate",
        "/sgx/certification/v4/crl",
        "/sgx/certification/v4/crl?uri=https://example.com/IntelSGXRootCA.crl",
    ];
    for path in cases {
        let (status, _, body) = send(app(), get(path)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(body.as_ref(), b"Invalid request parameters.");
    }
}

#[tokio::test]
async fn put_collateral_then_get_pckcert_is_cache_hit() {
    let router = app();
    let qeid = "11111111111111111111111111111111";
    let body = json!({
        "platforms": [{
            "qe_id": qeid,
            "pce_id": PCK_PCEID,
            "cpu_svn": PCK_CPUSVN,
            "pce_svn": PCK_PCESVN,
            "enc_ppid": "F".repeat(768)
        }],
        "collaterals": {
            "version": 4,
            "pck_certs": [{
                "qe_id": qeid,
                "pce_id": PCK_PCEID,
                "enc_ppid": "F".repeat(768),
                "certs": [{
                    "tcb": { "pcesvn": 0x3333 },
                    "tcbm": format!("{PCK_CPUSVN}{PCK_PCESVN}"),
                    "cert": PCK_PEM
                }]
            }],
            "tcbinfos": [{
                "fmspc": PCK_FMSPC,
                "sgx_tcbinfo": { "tcbInfo": pck_tcb_info(), "signature": "sig" }
            }],
            "certificates": {
                "SGX-PCK-Certificate-Issuer-Chain": {
                    "PLATFORM": "put-collateral-issuer-chain"
                }
            }
        }
    });

    let (status, _, body_txt) = send(
        router.clone(),
        put_admin("/sgx/certification/v4/platformcollateral", body),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&body_txt)
    );
    assert_eq!(body_txt.as_ref(), b"Operation successful.");

    let path = format!(
        "/sgx/certification/v4/pckcert?qeid={qeid}&cpusvn={PCK_CPUSVN}&pcesvn={PCK_PCESVN}&pceid={PCK_PCEID}"
    );
    let (status, h, cert) = send(router.clone(), get(&path)).await;
    assert_eq!(status, StatusCode::OK);
    // fmspc and CA come from the certificate, as in Node.
    assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), PCK_FMSPC);
    assert_eq!(
        h.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).unwrap(),
        "PLATFORM"
    );
    assert_eq!(
        h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
        "put-collateral-issuer-chain"
    );
    assert_eq!(
        h.get(headers::SGX_TCBM).unwrap(),
        format!("{PCK_CPUSVN}{PCK_PCESVN}").as_str()
    );
    assert!(String::from_utf8_lossy(&cert).contains("BEGIN CERTIFICATE"));

    // A raw TCB that was never PUT is selected locally from the stored pool.
    let lower = "11111111111111111111111111111111";
    let path = format!(
        "/sgx/certification/v4/pckcert?qeid={qeid}&cpusvn={lower}&pcesvn=1100&pceid={PCK_PCEID}"
    );
    let (status, _, body) = send(router.clone(), get(&path)).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "a raw TCB below every cert must not select one: {}",
        String::from_utf8_lossy(&body)
    );

    // A raw TCB above the cert's TCB selects it and is cached.
    let higher = "33333333333333333333333333333333";
    let path = format!(
        "/sgx/certification/v4/pckcert?qeid={qeid}&cpusvn={higher}&pcesvn=4444&pceid={PCK_PCEID}"
    );
    let (status, h, _) = send(router.clone(), get(&path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.get(headers::SGX_TCBM).unwrap(),
        format!("{PCK_CPUSVN}{PCK_PCESVN}").as_str()
    );

    // GET /platforms?source=[fmspc] returns only Node's six columns.
    let (status, h, body) = send(
        router,
        get_admin(&format!(
            "/sgx/certification/v4/platforms?source=%5B{PCK_FMSPC}%5D"
        )),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.get(headers::PLATFORM_COUNT).unwrap(), "2");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let row = v.as_array().unwrap()[0].as_object().unwrap();
    let mut fields: Vec<&str> = row.keys().map(|k| k.as_str()).collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        vec![
            "cpu_svn",
            "enc_ppid",
            "pce_id",
            "pce_svn",
            "platform_manifest",
            "qe_id"
        ]
    );
}

/// Finding A: the signed TCB info body must come back byte-for-byte, including
/// key order, so its signature still verifies.
#[tokio::test]
async fn put_collateral_preserves_tcbinfo_byte_order() {
    let router = app();
    let qeid = "22222222222222222222222222222222";
    // Deliberately NOT alphabetical, and not the order any sort would produce.
    let tcb_info = json!({
        "tcbType": 0,
        "id": "SGX",
        "zebra": "last-alphabetically-but-second-in-document-order",
        "pceId": PCK_PCEID,
        "fmspc": PCK_FMSPC,
        "tcbLevels": pck_tcb_info()["tcbLevels"],
        "aardvark": "first-alphabetically-but-last-in-document-order"
    });
    let signed = json!({ "tcbInfo": tcb_info, "signature": "deadbeef" });
    let expected = serde_json::to_string(&signed).unwrap();
    assert!(
        expected.find("\"zebra\"").unwrap() < expected.find("\"aardvark\"").unwrap(),
        "fixture must not be alphabetically ordered"
    );

    let body = json!({
        "platforms": [{
            "qe_id": qeid, "pce_id": PCK_PCEID,
            "cpu_svn": PCK_CPUSVN, "pce_svn": PCK_PCESVN,
            "enc_ppid": "F".repeat(768)
        }],
        "collaterals": {
            "version": 4,
            "pck_certs": [{
                "qe_id": qeid, "pce_id": PCK_PCEID, "enc_ppid": "F".repeat(768),
                "certs": [{
                    "tcb": { "pcesvn": 0x3333 },
                    "tcbm": format!("{PCK_CPUSVN}{PCK_PCESVN}"),
                    "cert": PCK_PEM
                }]
            }],
            "tcbinfos": [{ "fmspc": PCK_FMSPC, "sgx_tcbinfo": signed }],
            "certificates": {
                "SGX-PCK-Certificate-Issuer-Chain": { "PLATFORM": "chain" },
                "TCB-Info-Issuer-Chain": "tcb-chain"
            }
        }
    });
    let (status, _, txt) = send(
        router.clone(),
        put_admin("/sgx/certification/v4/platformcollateral", body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&txt));

    let (status, h, got) = send(
        router,
        get(&format!("/sgx/certification/v4/tcb?fmspc={PCK_FMSPC}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.get(headers::TCB_INFO_ISSUER_CHAIN).unwrap(), "tcb-chain");
    assert_eq!(
        String::from_utf8_lossy(&got),
        expected,
        "GET /tcb must return the exact bytes that were PUT"
    );
}

/// Finding I: the collateral body is schema-checked before anything is stored.
#[tokio::test]
async fn put_collateral_rejects_schema_violations() {
    let base = json!({
        "platforms": [{ "qe_id": "AA", "pce_id": "0000" }],
        "collaterals": {
            "version": 4,
            "pck_certs": [{
                "qe_id": "AA", "pce_id": "0000", "enc_ppid": "",
                "certs": [{ "tcb": {}, "tcbm": "0".repeat(36), "cert": "x" }]
            }],
            "tcbinfos": [{ "fmspc": "ABCDABCDABCD" }],
            "certificates": { "SGX-PCK-Certificate-Issuer-Chain": { "PROCESSOR": "c" } }
        }
    });
    let mut cases = Vec::new();
    let mut c = base.clone();
    c["collaterals"]["pck_certs"][0]["certs"][0]["tcbm"] = json!("nothex");
    cases.push(("tcbm not 36 hex", c));
    let mut c = base.clone();
    c["platforms"][0]["pce_id"] = json!("zzzz");
    cases.push(("pce_id not hex", c));
    let mut c = base.clone();
    c["collaterals"].as_object_mut().unwrap().remove("tcbinfos");
    cases.push(("tcbinfos missing", c));
    let mut c = base.clone();
    c["collaterals"]
        .as_object_mut()
        .unwrap()
        .remove("certificates");
    cases.push(("certificates missing", c));
    cases.push((
        "platforms not an array",
        json!({ "platforms": {}, "collaterals": {} }),
    ));

    for (what, body) in cases {
        let (status, _, txt) = send(
            app(),
            put_admin("/sgx/certification/v4/platformcollateral", body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{what}");
        assert_eq!(txt.as_ref(), b"Invalid request parameters.");
    }
}

/// OFFLINE queues the registration without contacting an upstream. (LAZY with
/// no upstream now fails the POST, as Node does — it has no queue at all.)
#[tokio::test]
async fn post_then_get_platforms_reg_queue() {
    let mut cfg = cfg_empty();
    cfg.cache_mode = CacheMode::Offline;
    let router = app_cfg(cfg);
    let body = json!({
        "qe_id": "QEIDQEIDQEIDQEIDQEIDQEIDQEIDQEID",
        "pce_id": "0001",
        "cpu_svn": "00000000000000000000000000000001",
        "pce_svn": "0001",
        "enc_ppid": "A".repeat(768)
    });
    let (status, _, txt) = send(
        router.clone(),
        post_user("/sgx/certification/v4/platforms", body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&txt));

    let (status, h, body) =
        send(router.clone(), get_admin("/sgx/certification/v4/platforms")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.get(headers::PLATFORM_COUNT).unwrap(), "1");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v.as_array().unwrap().len(), 1);

    // Node deletes NEW registrations on GET source=reg
    let (status, h, body) = send(router, get_admin("/sgx/certification/v4/platforms")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.get(headers::PLATFORM_COUNT).unwrap(), "0");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v.as_array().unwrap().is_empty());
}

/// Node `PLATFORM_REG_SCHEMA` is `type: 'object'` — an array is a 400.
#[tokio::test]
async fn post_platforms_rejects_arrays_and_bad_fields() {
    let mut cfg = cfg_empty();
    cfg.cache_mode = CacheMode::Offline;
    let router = app_cfg(cfg);
    let ok = json!({
        "qe_id": "QEID", "pce_id": "0001",
        "cpu_svn": "00000000000000000000000000000001",
        "pce_svn": "0001", "enc_ppid": "A".repeat(768)
    });
    for body in [
        json!([ok.clone()]),
        json!("string"),
        json!({ "qe_id": "QEID", "pce_id": "zzzz" }),
        json!({ "qe_id": "", "pce_id": "0001" }),
    ] {
        let (status, _, txt) = send(
            router.clone(),
            post_user("/sgx/certification/v4/platforms", body),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(txt.as_ref(), b"Invalid request parameters.");
    }
    let (status, _, _) = send(router, post_user("/sgx/certification/v4/platforms", ok)).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn tdx_seeded_routes() {
    let (status, h, _) = send(app(), get("/tdx/certification/v4/tcb?fmspc=ABCDABCDABCD")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::TCB_INFO_ISSUER_CHAIN).is_some());

    let (status, h, _) = send(app(), get("/tdx/certification/v4/qe/identity")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN).is_some());
}

#[tokio::test]
async fn qve_identity_and_rootcacrl_and_crl() {
    let (status, h, _) = send(app(), get("/sgx/certification/v4/qve/identity")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN).is_some());

    let (status, h, _) = send(app(), get("/sgx/certification/v4/rootcacrl")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.get(axum::http::header::CONTENT_TYPE).unwrap(),
        headers::CONTENT_TYPE_CRL
    );

    let (status, h, _) = send(
        app(),
        get("/sgx/certification/v4/crl?uri=https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.get(axum::http::header::CONTENT_TYPE).unwrap(),
        headers::CONTENT_TYPE_CRL
    );
}

#[tokio::test]
async fn appraisal_policy_put_get() {
    let router = app();
    let (status, _, body) = send(
        router.clone(),
        get("/sgx/certification/v4/appraisalpolicy?fmspc=ABCDABCDABCD"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body).contains("seed.policy.default"));

    let policy = jws_policy(CLASS_ID_SGX, "first");
    let (status, _, id) = send(
        router.clone(),
        put_admin(
            "/sgx/certification/v4/appraisalpolicy",
            json!({ "is_default": true, "fmspc": "aaaaaaaaaaaa", "policy": policy }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&id));
    assert_eq!(id.len(), 96); // sha384 hex

    let (status, _, body) = send(
        router.clone(),
        get("/sgx/certification/v4/appraisalpolicy?fmspc=AAAAAAAAAAAA"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(String::from_utf8_lossy(&body), policy);

    // A second default for the same fmspc clears the first one's is_default.
    let policy2 = jws_policy(CLASS_ID_SGX, "second");
    let (status, _, id2) = send(
        router.clone(),
        put_admin(
            "/sgx/certification/v4/appraisalpolicy",
            json!({ "is_default": true, "fmspc": "AAAAAAAAAAAA", "policy": policy2 }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_ne!(id2, id);
    let (status, _, body) = send(
        router.clone(),
        get("/sgx/certification/v4/appraisalpolicy?fmspc=AAAAAAAAAAAA"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        String::from_utf8_lossy(&body),
        policy2,
        "only the newest default is returned"
    );

    // Re-PUTting the same policy upserts by id instead of appending.
    let (status, _, id3) = send(
        router.clone(),
        put_admin(
            "/sgx/certification/v4/appraisalpolicy",
            json!({ "is_default": true, "fmspc": "AAAAAAAAAAAA", "policy": policy2 }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(id3, id2);
    let (_, _, body) = send(
        router.clone(),
        get("/sgx/certification/v4/appraisalpolicy?fmspc=AAAAAAAAAAAA"),
    )
    .await;
    assert_eq!(String::from_utf8_lossy(&body), policy2);

    // Node validates the policy payload: no '.', bad base64url, or an unknown
    // class_id are all 400.
    for bad in [
        json!({ "is_default": true, "fmspc": "AAAAAAAAAAAA", "policy": "nodots" }),
        json!({ "is_default": true, "fmspc": "AAAAAAAAAAAA", "policy": "a.!!!.c" }),
        json!({ "is_default": true, "fmspc": "zzzz", "policy": policy2.clone() }),
        json!({ "fmspc": "AAAAAAAAAAAA", "policy": policy2.clone() }),
        json!({
            "is_default": true, "fmspc": "AAAAAAAAAAAA",
            "policy": jws_policy("00000000-0000-0000-0000-000000000000", "x")
        }),
    ] {
        let (status, _, txt) = send(
            router.clone(),
            put_admin("/sgx/certification/v4/appraisalpolicy", bad),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(txt.as_ref(), b"Invalid request parameters.");
    }
}

#[tokio::test]
async fn refresh_invalid_type_400() {
    let req = Request::builder()
        .method("GET")
        .uri("/sgx/certification/v4/refresh?type=all")
        .header(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)
        .body(Body::empty())
        .unwrap();
    let (status, _, _) = send(app(), req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn platforms_source_fmspc_list() {
    let (status, h, _) = send(
        app(),
        get_admin("/sgx/certification/v4/platforms?source=%5BABCDABCDABCD%5D"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.get(headers::PLATFORM_COUNT).unwrap(), "1");
}

fn cfg_empty() -> Config {
    let mut c = Config::test_default();
    c.no_seed = true;
    c
}

fn app_cfg(cfg: Config) -> axum::Router {
    create_app_from_config(cfg)
}

async fn spawn_mock(
    tcb_sig: Arc<RwLock<String>>,
    calls: Arc<AtomicU64>,
) -> (String, tokio::task::JoinHandle<()>) {
    use axum::routing::get;
    use axum::Router as AxumRouter;
    let tcb_sig2 = tcb_sig.clone();
    let calls_t = calls.clone();
    let calls_i = calls.clone();
    let calls_p = calls.clone();
    let app = AxumRouter::new()
        .route(
            "/sgx/certification/v4/tcb",
            get(move || {
                let tcb_sig = tcb_sig2.clone();
                let calls = calls_t.clone();
                async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    let sig = tcb_sig.read().await.clone();
                    let body = format!(
                        "{{\n  \"signature\":\"{sig}\",\n  \"tcbInfo\":{{\"id\":\"SGX\",\"fmspc\":\"00A067110000\"}}\n}}"
                    );
                    let mut resp = axum::response::Response::new(axum::body::Body::from(body));
                    resp.headers_mut().insert(
                        headers::TCB_INFO_ISSUER_CHAIN,
                        axum::http::HeaderValue::from_static("mock-tcb-chain"),
                    );
                    resp.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        axum::http::HeaderValue::from_static("application/json"),
                    );
                    resp
                }
            }),
        )
        .route(
            "/sgx/certification/v4/qe/identity",
            get(move || {
                let calls = calls_i.clone();
                async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    let body = "{\n  \"signature\":\"mock-qe\",\n  \"enclaveIdentity\":{\"id\":\"QE\"}\n}";
                    let mut resp = axum::response::Response::new(axum::body::Body::from(body));
                    resp.headers_mut().insert(
                        headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN,
                        axum::http::HeaderValue::from_static("mock-qe-chain"),
                    );
                    resp.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        axum::http::HeaderValue::from_static("application/json"),
                    );
                    resp
                }
            }),
        )
        .route(
            "/sgx/certification/v4/pckcert",
            get(move || {
                let calls = calls_p.clone();
                async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    let mut resp = axum::response::Response::new(axum::body::Body::from(
                        "-----BEGIN CERTIFICATE-----\nMOCKPCK\n-----END CERTIFICATE-----\n",
                    ));
                    resp.headers_mut().insert(headers::SGX_TCBM, axum::http::HeaderValue::from_static("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCC"));
                    resp.headers_mut().insert(headers::SGX_FMSPC, axum::http::HeaderValue::from_static("00A067110000"));
                    resp.headers_mut().insert(headers::SGX_PCK_CERTIFICATE_CA_TYPE, axum::http::HeaderValue::from_static("processor"));
                    resp.headers_mut().insert(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN, axum::http::HeaderValue::from_static("mock-pck-chain"));
                    resp
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}/sgx/certification/v4/"), h)
}

#[tokio::test]
async fn rocksdb_survives_reopen() {
    let cfg = Config::test_default();
    let path = cfg.db_path.clone();
    let router = app_cfg(cfg.clone());
    let (status, _, _) = send(router, get(TCB)).await;
    assert_eq!(status, StatusCode::OK);

    let mut cfg2 = Config::test_default();
    cfg2.db_path = path;
    cfg2.no_seed = true;
    let router2 = app_cfg(cfg2);
    let (status, h, body) = send(router2, get(TCB)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::TCB_INFO_ISSUER_CHAIN).is_some());
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v.get("tcbInfo").is_some());
}

#[tokio::test]
async fn lazy_miss_fetches_mock_then_hit() {
    let sig = Arc::new(RwLock::new("first".to_string()));
    let calls = Arc::new(AtomicU64::new(0));
    let (uri, _h) = spawn_mock(sig, calls.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    let path = "/sgx/certification/v4/tcb?fmspc=00A067110000";
    let (status, _, body) = send(router.clone(), get(path)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let expected = b"{\n  \"signature\":\"first\",\n  \"tcbInfo\":{\"id\":\"SGX\",\"fmspc\":\"00A067110000\"}\n}";
    assert_eq!(body.as_ref(), expected);

    let (status, _, body) = send(router, get(path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "second GET must be RocksDB hit"
    );
    assert_eq!(body.as_ref(), expected);
}

#[tokio::test]
async fn lazy_cache_preserves_identity_body_bytes() {
    let sig = Arc::new(RwLock::new("unused".to_string()));
    let calls = Arc::new(AtomicU64::new(0));
    let (uri, _h) = spawn_mock(sig, calls.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    let path = "/sgx/certification/v4/qe/identity";
    let expected = b"{\n  \"signature\":\"mock-qe\",\n  \"enclaveIdentity\":{\"id\":\"QE\"}\n}";

    let (status, _, body) = send(router.clone(), get(path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), expected);
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    let (status, _, body) = send(router, get(path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), expected);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        1,
        "second GET must be RocksDB hit"
    );
}

#[tokio::test]
async fn offline_miss_is_404_no_upstream() {
    let sig = Arc::new(RwLock::new("x".into()));
    let calls = Arc::new(AtomicU64::new(0));
    let (uri, _h) = spawn_mock(sig, calls.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Offline;
    let (status, _, body) = send(
        app_cfg(cfg),
        get("/sgx/certification/v4/tcb?fmspc=00A067110000"),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body.as_ref(), b"No cache data for this platform.");
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn req_pckcert_miss_is_461() {
    let mut cfg = cfg_empty();
    cfg.cache_mode = CacheMode::Req;
    let (status, _, body) = send(
        app_cfg(cfg),
        get("/sgx/certification/v4/pckcert?qeid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&cpusvn=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&pcesvn=CCCC&pceid=DDDD"),
    )
    .await;
    assert_eq!(status.as_u16(), 461);
    assert_eq!(body.as_ref(), b"The platform was not found in the cache.");
}

#[tokio::test]
async fn put_collateral_then_get_tcb_and_identity() {
    let router = app();
    let qeid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let body = json!({
        "platforms": [{
            "qe_id": qeid,
            "pce_id": PCK_PCEID,
            "cpu_svn": PCK_CPUSVN,
            "pce_svn": PCK_PCESVN,
            "enc_ppid": "F".repeat(768)
        }],
        "collaterals": {
            "version": 4,
            "pck_certs": [{
                "qe_id": qeid,
                "pce_id": PCK_PCEID,
                "enc_ppid": "F".repeat(768),
                "certs": [{
                    "tcb": { "pcesvn": 0x3333 },
                    "tcbm": format!("{PCK_CPUSVN}{PCK_PCESVN}"),
                    "cert": PCK_PEM
                }]
            }],
            "tcbinfos": [{
                "fmspc": PCK_FMSPC,
                "sgx_tcbinfo": { "tcbInfo": pck_tcb_info(), "signature": "put-tcb" }
            }],
            "qeidentity": json!({"enclaveIdentity":{"id":"QE-PUT"},"signature":"put-qe"}).to_string(),
            "certificates": {
                "SGX-PCK-Certificate-Issuer-Chain": { "PLATFORM": "put-pck-issuer" },
                "TCB-Info-Issuer-Chain": "put-tcb-issuer",
                "SGX-Enclave-Identity-Issuer-Chain": "put-qe-issuer"
            }
        }
    });
    let (status, _, txt) = send(
        router.clone(),
        put_admin("/sgx/certification/v4/platformcollateral", body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&txt));

    let (status, h, body) = send(
        router.clone(),
        get(&format!("/sgx/certification/v4/tcb?fmspc={PCK_FMSPC}")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.get(headers::TCB_INFO_ISSUER_CHAIN).unwrap(),
        "put-tcb-issuer"
    );
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["signature"], "put-tcb");

    let (status, h, body) = send(router, get("/sgx/certification/v4/qe/identity")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.get(headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN).unwrap(),
        "put-qe-issuer"
    );
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["enclaveIdentity"]["id"], "QE-PUT");
}

#[tokio::test]
async fn refresh_updates_value_from_mock() {
    let sig = Arc::new(RwLock::new("before".to_string()));
    let calls = Arc::new(AtomicU64::new(0));
    let (uri, _h) = spawn_mock(sig.clone(), calls.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    let path = "/sgx/certification/v4/tcb?fmspc=00A067110000";
    let (status, _, body) = send(router.clone(), get(path)).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["signature"], "before");

    *sig.write().await = "after".into();
    let (status, _, _) = send(router.clone(), get_admin("/sgx/certification/v4/refresh")).await;
    assert_eq!(status, StatusCode::OK);

    let (status, _, body) = send(router, get(path)).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["signature"], "after");
}

/// Kills the child and removes its DB dir even when a test assertion panics.
struct ServerGuard {
    child: std::process::Child,
    db: std::path::PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.db);
    }
}

/// Spawns pccs-rs on a free port and waits until it answers. A bind-release
/// port can be stolen between the probe and the server's own bind, so an
/// early exit is retried with a fresh port.
async fn spawn_server() -> Option<(ServerGuard, String)> {
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http::<http_body_util::Empty<bytes::Bytes>>();
    for _ in 0..3 {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let db = std::env::temp_dir().join(format!("pccs-rs-e2e-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&db).unwrap();
        let cfg = db.join("empty.toml");
        std::fs::write(&cfg, "").unwrap();
        let child = std::process::Command::new(env!("CARGO_BIN_EXE_pccs-rs"))
            .args([
                "serve",
                "--config",
                cfg.to_str().unwrap(),
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--db-path",
                db.to_str().unwrap(),
                "--dev-tokens",
                "--no-seed",
                "--cache-mode",
                "offline",
            ])
            .env("PCCS_URI", "") // no upstream: pure OFFLINE-style serving
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn pccs-rs");
        let mut guard = ServerGuard { child, db };
        let url = format!("http://127.0.0.1:{port}");
        for _ in 0..100 {
            if guard.child.try_wait().unwrap().is_some() {
                break; // died before serving (e.g. lost the port race): retry
            }
            let req = Request::builder()
                .method("GET")
                .uri(format!("{url}/no/such/route"))
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap();
            if let Ok(resp) = client.request(req).await {
                // Even the 404 fallback carries a Request-ID: the app is up.
                if resp.headers().get(headers::REQUEST_ID).is_some() {
                    return Some((guard, url));
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
    None
}

/// End-to-end: the real binary serves the seeded cache over plain HTTP, the
/// load generator runs against it, and SIGTERM shuts it down cleanly.
#[tokio::test]
async fn binary_serves_seeded_cache_and_shuts_down_on_sigterm() {
    let (mut guard, url) = spawn_server().await.expect("pccs-rs never came up");
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build_http::<http_body_util::Empty<bytes::Bytes>>();

    // A cache miss in OFFLINE mode is a 404 with the Node body.
    let req = Request::builder()
        .method("GET")
        .uri(format!("{url}/sgx/certification/v4/tcb?fmspc=ABCDABCDABCD"))
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .unwrap();
    let resp = client.request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // The load generator runs its full main against this server.
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_loadgen"))
        .args([
            "--url",
            &url,
            "--duration",
            "1",
            "--concurrency",
            "2",
            "--warmup",
            "1",
        ])
        .output()
        .expect("run loadgen");
    assert!(
        out.status.success(),
        "loadgen failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("rps:"), "{stdout}");
    assert!(stdout.contains("p99_ms:"), "{stdout}");

    // SIGTERM → graceful shutdown, exit code 0. (The guard still kills and
    // cleans up if any assertion above panicked.)
    let status = std::process::Command::new("kill")
        .args(["-TERM", &guard.child.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    let waited = tokio::time::timeout(std::time::Duration::from_secs(15), async move {
        loop {
            if let Some(status) = guard.child.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("server did not exit after SIGTERM");
    assert!(waited.success(), "graceful shutdown must exit 0: {waited}");
}

#[tokio::test]
#[ignore]
async fn live_phala_tcb_and_qe_identity() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = cfg_empty();
    cfg.uri = "https://pccs.phala.network/sgx/certification/v4/".into();
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    let (status, _, body) = send(
        router.clone(),
        get("/sgx/certification/v4/tcb?fmspc=00A067110000"),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "live tcb {}",
        String::from_utf8_lossy(&body)
    );
    let (status, _, body) = send(router, get("/sgx/certification/v4/qe/identity")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "live qe {}",
        String::from_utf8_lossy(&body)
    );
}

/// Finding F: N concurrent misses on the same key must produce ONE upstream
/// request. The mock sleeps so every task is guaranteed to miss the store
/// before the first fetch completes.
async fn spawn_slow_mock(calls: Arc<AtomicU64>) -> (String, tokio::task::JoinHandle<()>) {
    use axum::routing::get as axget;
    let calls_t = calls.clone();
    let calls_i = calls.clone();
    let app = axum::Router::new()
        .route(
            "/sgx/certification/v4/tcb",
            axget(move || {
                let calls = calls_t.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    let mut resp = axum::response::Response::new(axum::body::Body::from(
                        "{\"tcbInfo\":{\"id\":\"SGX\"},\"signature\":\"slow\"}",
                    ));
                    resp.headers_mut().insert(
                        headers::TCB_INFO_ISSUER_CHAIN,
                        axum::http::HeaderValue::from_static("slow-chain"),
                    );
                    resp
                }
            }),
        )
        .route(
            "/sgx/certification/v4/qe/identity",
            axget(move || {
                let calls = calls_i.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                    let mut resp = axum::response::Response::new(axum::body::Body::from(
                        "{\"enclaveIdentity\":{\"id\":\"QE\"},\"signature\":\"slow\"}",
                    ));
                    resp.headers_mut().insert(
                        headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN,
                        axum::http::HeaderValue::from_static("slow-chain"),
                    );
                    resp
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}/sgx/certification/v4/"), h)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_misses_issue_one_upstream_fetch() {
    let calls = Arc::new(AtomicU64::new(0));
    let (uri, _h) = spawn_slow_mock(calls.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);

    let mut tasks = Vec::new();
    for _ in 0..50 {
        let r = router.clone();
        tasks.push(tokio::spawn(async move {
            send(r, get("/sgx/certification/v4/tcb?fmspc=00A067110000")).await
        }));
    }
    for t in tasks {
        let (status, _, body) = t.await.unwrap();
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            String::from_utf8_lossy(&body),
            "{\"tcbInfo\":{\"id\":\"SGX\"},\"signature\":\"slow\"}"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "50 concurrent identical misses must collapse into one upstream fetch"
    );

    // Different keys are not serialised behind each other.
    calls.store(0, Ordering::SeqCst);
    let a = tokio::spawn({
        let r = router.clone();
        async move { send(r, get("/sgx/certification/v4/qe/identity")).await }
    });
    let b = tokio::spawn({
        let r = router.clone();
        async move { send(r, get("/sgx/certification/v4/tcb?fmspc=00A067110001")).await }
    });
    let _ = a.await.unwrap();
    let _ = b.await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

/// A `/tcb` upstream that records when each request starts and finishes, can be
/// switched to failing, and sleeps so overlapping refreshes would be visible.
///
/// `log` gets `"start"` / `"end"` pushed around every handled request; if two
/// refreshes ran concurrently the log would contain `start, start, …` rather
/// than strictly alternating pairs.
async fn spawn_refresh_mock(
    fail: Arc<AtomicBool>,
    log: Arc<tokio::sync::Mutex<Vec<&'static str>>>,
) -> (String, tokio::task::JoinHandle<()>) {
    use axum::routing::get;
    let app = axum::Router::new().route(
        "/sgx/certification/v4/tcb",
        get(move || {
            let fail = fail.clone();
            let log = log.clone();
            async move {
                log.lock().await.push("start");
                tokio::time::sleep(std::time::Duration::from_millis(150)).await;
                let failing = fail.load(Ordering::SeqCst);
                log.lock().await.push("end");
                if failing {
                    return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
                let body = "{\n  \"signature\":\"mock\",\n  \"tcbInfo\":{\"id\":\"SGX\",\"fmspc\":\"00A067110000\"}\n}";
                let mut resp = axum::response::Response::new(axum::body::Body::from(body));
                resp.headers_mut().insert(
                    headers::TCB_INFO_ISSUER_CHAIN,
                    axum::http::HeaderValue::from_static("mock-tcb-chain"),
                );
                resp.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                resp
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let h = tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    (format!("http://{addr}/sgx/certification/v4/"), h)
}

/// Intel PCCS 2026-09-04 commit 4d077a7 security fix: Express allowed `//` in
/// URLs which bypassed app-level middleware while still matching route handlers.
///
/// Axum behavior: duplicate slashes cause routes to NOT MATCH at all (404), which
/// is inherently safe—no handler runs, so no auth bypass is possible. This test
/// verifies that Axum's routing is NOT vulnerable to the class of bypass Intel fixed:
///
/// - Normal paths WITH auth work (200/OK or other success based on payload)
/// - Normal paths WITHOUT auth fail with 401
/// - Double-slash paths return 404 (route doesn't match), proving no handler bypass
#[tokio::test]
async fn auth_not_bypassed_by_duplicate_slashes() {
    let router = app();

    // Protected admin routes: expected status when authed (may be 200, 400, etc.)
    // The key test is: without auth = 401, with auth = not 401 or 404
    let admin_test_cases = [
        ("GET", "/sgx/certification/v4/platforms?source=reg"),
        ("PUT", "/sgx/certification/v4/platformcollateral"),
        ("GET", "/sgx/certification/v4/refresh"),
        ("POST", "/sgx/certification/v4/refresh"),
        ("PUT", "/sgx/certification/v4/appraisalpolicy"),
    ];

    for (method, path) in &admin_test_cases {
        // Normal path WITHOUT auth: must be 401
        let req = Request::builder()
            .method(*method)
            .uri(*path)
            .header("content-type", "application/json")
            .body(if *method == "GET" {
                Body::empty()
            } else {
                Body::from("{}")
            })
            .unwrap();
        let (status, _, body) = send(router.clone(), req).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "{method} {path} without token must be 401"
        );
        assert_eq!(body.as_ref(), b"Authentication failed.");

        // Normal path WITH valid auth: must NOT be 401 or 404 (auth passed, handler ran)
        let req = Request::builder()
            .method(*method)
            .uri(*path)
            .header(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)
            .header("content-type", "application/json")
            .body(if *method == "GET" {
                Body::empty()
            } else {
                Body::from("{}")
            })
            .unwrap();
        let (status, _, _) = send(router.clone(), req).await;
        assert!(
            status != StatusCode::UNAUTHORIZED && status != StatusCode::NOT_FOUND,
            "{method} {path} with valid token got {status}; must not be 401 (auth bypass) or 404 (route not found)"
        );

        // Double-slash variant: must be 404 (route doesn't match)
        // This proves Axum is NOT vulnerable to the Express bypass class
        let double_slash_path = path.replace("/v4/", "/v4//");
        let req = Request::builder()
            .method(*method)
            .uri(&double_slash_path)
            .header("content-type", "application/json")
            .body(if *method == "GET" {
                Body::empty()
            } else {
                Body::from("{}")
            })
            .unwrap();
        let (status, _, _) = send(router.clone(), req).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {double_slash_path} must be 404 (route not matched); if 401 or 200, handler ran (bypass!)"
        );

        // Double-slash WITH auth: still 404 (route never matches, so auth never runs)
        let req = Request::builder()
            .method(*method)
            .uri(&double_slash_path)
            .header(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)
            .header("content-type", "application/json")
            .body(if *method == "GET" {
                Body::empty()
            } else {
                Body::from("{}")
            })
            .unwrap();
        let (status, _, _) = send(router.clone(), req).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {double_slash_path} even with auth must be 404"
        );
    }

    // Protected user route: POST /platforms
    let req = Request::builder()
        .method("POST")
        .uri("/sgx/certification/v4/platforms")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let (status, _, _) = send(router.clone(), req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let req = Request::builder()
        .method("POST")
        .uri("/sgx/certification/v4/platforms")
        .header(headers::USER_TOKEN, DEFAULT_USER_TOKEN)
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let (status, _, _) = send(router.clone(), req).await;
    assert_ne!(status, StatusCode::UNAUTHORIZED);

    // Double-slash: 404
    let req = Request::builder()
        .method("POST")
        .uri("/sgx/certification/v4//platforms")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let (status, _, _) = send(router.clone(), req).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "double-slash POST must be 404"
    );
}

/// Finding G: concurrent refreshes are serialised, and an upstream failure is
/// reported instead of swallowed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_is_serialised_and_propagates_failures() {
    let fail = Arc::new(AtomicBool::new(false));
    let log = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let (uri, _h) = spawn_refresh_mock(fail.clone(), log.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Lazy;
    cfg.upstream_max_attempts = 1;
    let router = app_cfg(cfg);

    // Seed one TCB info, so a later /refresh actually has something to refresh.
    let (status, _, _) = send(
        router.clone(),
        get("/sgx/certification/v4/tcb?fmspc=00A067110000"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    log.lock().await.clear();

    // --- serialisation -----------------------------------------------------
    // Two refreshes fired together. Each does one 150ms upstream call, so if
    // `refresh_lock` did not hold they would overlap and the log would read
    // start,start,end,end.
    let a = tokio::spawn({
        let r = router.clone();
        async move { send(r, get_admin("/sgx/certification/v4/refresh")).await }
    });
    let b = tokio::spawn({
        let r = router.clone();
        async move { send(r, get_admin("/sgx/certification/v4/refresh")).await }
    });
    for t in [a, b] {
        let (status, _, _) = t.await.unwrap();
        assert_eq!(status, StatusCode::OK);
    }
    let events = log.lock().await.clone();
    assert_eq!(
        events.len(),
        4,
        "each refresh should make exactly one upstream tcb call: {events:?}"
    );
    assert_eq!(
        events,
        vec!["start", "end", "start", "end"],
        "refreshes must not interleave: {events:?}"
    );

    // --- failure propagation ----------------------------------------------
    // The same cached TCB info, but the upstream now 500s. Node's
    // refreshOneTcb turns that into PCCS_STATUS_SERVICE_UNAVAILABLE.
    fail.store(true, Ordering::SeqCst);
    let (status, _, body) = send(router.clone(), get_admin("/sgx/certification/v4/refresh")).await;
    assert_eq!(
        status,
        StatusCode::SERVICE_UNAVAILABLE,
        "a failing upstream must surface as 503, not a silent 200"
    );
    assert_eq!(
        body.as_ref(),
        b"Server is currently unable to process the request."
    );

    // And it recovers once the upstream does.
    fail.store(false, Ordering::SeqCst);
    let (status, _, _) = send(router, get_admin("/sgx/certification/v4/refresh")).await;
    assert_eq!(status, StatusCode::OK);
}

/// Finding I: OFFLINE mode validates parameters before answering 503.
#[tokio::test]
async fn offline_refresh_validates_before_503() {
    let mut cfg = cfg_empty();
    cfg.cache_mode = CacheMode::Offline;
    let router = app_cfg(cfg);

    let (status, _, body) = send(
        router.clone(),
        get_admin("/sgx/certification/v4/refresh?type=certs&fmspc=nothex"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.as_ref(), b"Invalid request parameters.");

    let (status, _, _) = send(router, get_admin("/sgx/certification/v4/refresh")).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
}

/// Finding I: duplicated query parameters take the FIRST value, an empty
/// `encrypted_ppid` is a 400, and unmatched v3 paths still get the Warning.
#[tokio::test]
async fn query_parsing_matches_node() {
    // first occurrence wins: a valid fmspc followed by junk still resolves
    let (status, _, _) = send(
        app(),
        get("/sgx/certification/v4/tcb?fmspc=ABCDABCDABCD&fmspc=nothex"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // ...and junk first is a 400 even when a valid value follows
    let (status, _, _) = send(
        app(),
        get("/sgx/certification/v4/tcb?fmspc=nothex&fmspc=ABCDABCDABCD"),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    // encrypted_ppid present but empty fails isHex('', 768)
    let (status, _, body) = send(app(), get(&format!("{PCKCERT}&encrypted_ppid="))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body.as_ref(), b"Invalid request parameters.");

    // absent is fine
    let (status, _, _) = send(app(), get(PCKCERT)).await;
    assert_eq!(status, StatusCode::OK);

    // unmatched v3 path still carries the EOL Warning (Node app.use)
    let (status, h, _) = send(app(), get("/sgx/certification/v3/no-such-thing")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        h.get(headers::WARNING).is_some(),
        "unmatched v3 paths must carry the EOL Warning header"
    );
}

/// A v3 upstream means only v3 routes exist: the v4 nest is not mounted
/// (Node's `pcs_version` gate).
#[tokio::test]
async fn v3_upstream_mounts_no_v4_routes() {
    let mut cfg = Config::test_default();
    cfg.uri = "https://example.test/sgx/certification/v3/".into();
    cfg.cache_mode = CacheMode::Offline;
    let router = app_cfg(cfg);

    let (status, _, _) = send(router.clone(), get(TCB)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "v4 must not be mounted");

    // v3 routes still answer (seeded TCB info).
    let (status, h, _) = send(router, get("/sgx/certification/v3/tcb?fmspc=ABCDABCDABCD")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::WARNING).is_some());
}

/// LAZY /pckcert miss against a PCCS upstream: filled, headers normalised,
/// and the second identical GET is a pure store hit.
#[tokio::test]
async fn lazy_pckcert_fill_from_pccs_then_hit() {
    let sig = Arc::new(RwLock::new("unused".to_string()));
    let calls = Arc::new(AtomicU64::new(0));
    let (uri, _h) = spawn_mock(sig, calls.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    // A LAZY miss needs the encrypted PPID to fill from a PCCS upstream.
    let path = format!(
        "/sgx/certification/v4/pckcert?qeid=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&cpusvn=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB&pcesvn=CCCC&pceid=DDDD&encrypted_ppid={}",
        "E".repeat(768)
    );

    let (status, h, body) = send(router.clone(), get(&path)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), "00A067110000");
    // The mock sends "processor" in lowercase; the served header is the
    // normalised uppercase form.
    assert_eq!(
        h.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).unwrap(),
        "PROCESSOR"
    );
    assert_eq!(
        h.get(headers::SGX_TCBM).unwrap(),
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCC"
    );
    assert!(String::from_utf8_lossy(&body).contains("BEGIN CERTIFICATE"));
    let pck_calls = calls.load(Ordering::Relaxed);

    let (status, _, _) = send(router, get(&path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        calls.load(Ordering::Relaxed),
        pck_calls,
        "second GET is a store hit"
    );
}

/// A request body that delivers one chunk and then never completes, without
/// ever signalling end-of-stream — i.e. a client that stalls mid-body.
struct StalledBody(Option<bytes::Bytes>);

impl hyper::body::Body for StalledBody {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        if let Some(b) = self.0.take() {
            return std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(b))));
        }
        std::task::Poll::Pending
    }
}

/// `RequestTimeoutSeconds` bounds *receiving* the request body and answers 408,
/// the way Node's `server.requestTimeout` does. It must not be implemented as a
/// handler-cancelling timeout layer: that would abort a slow LAZY upstream fill
/// or an admin `/refresh` mid-write (see `store_pckcerts`).
#[tokio::test]
async fn stalled_request_body_is_408_with_request_id() {
    let mut cfg = Config::test_default();
    cfg.request_timeout_secs = 1;
    let router = app_cfg(cfg);

    let req = Request::builder()
        .method("POST")
        .uri("/sgx/certification/v4/platforms")
        .header("content-type", "application/json")
        .header("user-token", DEFAULT_USER_TOKEN)
        .body(Body::new(StalledBody(Some(bytes::Bytes::from_static(
            b"{\"qe_id\":",
        )))))
        .unwrap();

    let started = std::time::Instant::now();
    let (status, h, body) = send(router, req).await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(body.as_ref(), b"Request Timeout");
    // The 408 is produced inside the app, so it still carries a Request-ID.
    assert!(h.get(headers::REQUEST_ID).is_some());
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "must time out at RequestTimeoutSeconds, not hang"
    );
}
