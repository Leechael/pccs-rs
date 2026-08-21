//! 1:1 HTTP API tests against the in-process axum app (no network, no Intel PCS).

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use pccs_rs::config::{Config, DEFAULT_ADMIN_TOKEN, DEFAULT_USER_TOKEN};
use pccs_rs::{create_app_from_config, headers};
use serde_json::json;
use tower::ServiceExt;
use pccs_rs::config::CacheMode;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::RwLock;

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

#[tokio::test]
async fn request_id_echo_and_generated() {
    let req = Request::builder()
        .method("GET")
        .uri("/no/such/route")
        .header(headers::REQUEST_ID, "abc123clientid")
        .body(Body::empty())
        .unwrap();
    let (_, headers, _) = send(app(), req).await;
    assert_eq!(
        headers.get(headers::REQUEST_ID).unwrap().to_str().unwrap(),
        "abc123clientid"
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
    assert_eq!(status, StatusCode::OK, "pckcert {}", String::from_utf8_lossy(&body));
    assert!(h.get(headers::SGX_TCBM).is_some());
    assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), "ABCDABCDABCD");
    assert!(h.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).is_some());
    assert!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).is_some());
    assert_eq!(
        h.get(axum::http::header::CONTENT_TYPE).unwrap(),
        headers::CONTENT_TYPE_PEM
    );
    assert!(h.get(headers::REQUEST_ID).is_some());
    assert!(body.windows(b"BEGIN CERTIFICATE".len()).any(|w| w == b"BEGIN CERTIFICATE"));
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
    let (status, h, _) = send(app(), get("/sgx/certification/v4/pckcrl?ca=platform&encoding=DER")).await;
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
    let warn = h.get(headers::WARNING).expect("Warning header").to_str().unwrap();
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
    let (status, h, body) = send(
        app(),
        get("/sgx/certification/v3/tcb?fmspc=FFFFFFFFFFFF"),
    )
    .await;
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
    let cpusvn = "22222222222222222222222222222222";
    let pcesvn = "3333";
    let pceid = "4444";
    let body = json!({
        "platforms": [{
            "qe_id": qeid,
            "pce_id": pceid,
            "cpu_svn": cpusvn,
            "pce_svn": pcesvn,
            "enc_ppid": "F".repeat(768),
            "fmspc": "1234567890AB",
            "ca": "platform",
            "issuer_chain": "put-collateral-issuer-chain"
        }],
        "collaterals": {
            "pck_certs": [{
                "qe_id": qeid,
                "pce_id": pceid,
                "certs": [{
                    "tcbm": format!("{cpusvn}{pcesvn}"),
                    "cert": "-----BEGIN CERTIFICATE-----\nPUTCOLLATERAL\n-----END CERTIFICATE-----\n"
                }]
            }]
        }
    });

    let (status, _, body_txt) = send(
        router.clone(),
        put_admin("/sgx/certification/v4/platformcollateral", body),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body_txt));
    assert_eq!(body_txt.as_ref(), b"Operation successful.");

    let path = format!(
        "/sgx/certification/v4/pckcert?qeid={qeid}&cpusvn={cpusvn}&pcesvn={pcesvn}&pceid={pceid}"
    );
    let (status, h, cert) = send(router, get(&path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), "1234567890AB");
    assert_eq!(
        h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
        "put-collateral-issuer-chain"
    );
    assert!(String::from_utf8_lossy(&cert).contains("PUTCOLLATERAL"));
}

#[tokio::test]
async fn post_then_get_platforms_reg_queue() {
    let router = app();
    let body = json!({
        "qe_id": "QEIDQEIDQEIDQEIDQEIDQEIDQEIDQEID",
        "pce_id": "0001",
        "cpu_svn": "00000000000000000000000000000001",
        "pce_svn": "0001",
        "enc_ppid": "A".repeat(768)
    });
    let (status, _, _) = send(
        router.clone(),
        post_user("/sgx/certification/v4/platforms", body),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, h, body) = send(router.clone(), get_admin("/sgx/certification/v4/platforms")).await;
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

    let (status, _, id) = send(
        router.clone(),
        put_admin(
            "/sgx/certification/v4/appraisalpolicy",
            json!({
                "is_default": true,
                "fmspc": "aaaaaaaaaaaa",
                "policy": "new.policy.value"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(id.len(), 96); // sha384 hex

    let (status, _, body) = send(
        router,
        get("/sgx/certification/v4/appraisalpolicy?fmspc=AAAAAAAAAAAA"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), b"new.policy.value");
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
                    let body = serde_json::json!({"tcbInfo":{"fmspc":"00A067110000","id":"SGX"},"signature":sig});
                    let mut resp = axum::response::Response::new(axum::body::Body::from(body.to_string()));
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
                    let body = serde_json::json!({"enclaveIdentity":{"id":"QE"},"signature":"mock-qe"});
                    let mut resp = axum::response::Response::new(axum::body::Body::from(body.to_string()));
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
    let mut cfg = Config::test_default();
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
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["signature"], "first");

    let (status, _, body) = send(router, get(path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(calls.load(Ordering::Relaxed), 1, "second GET must be RocksDB hit");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["signature"], "first");
}

#[tokio::test]
async fn offline_miss_is_404_no_upstream() {
    let sig = Arc::new(RwLock::new("x".into()));
    let calls = Arc::new(AtomicU64::new(0));
    let (uri, _h) = spawn_mock(sig, calls.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Offline;
    let (status, _, body) = send(app_cfg(cfg), get("/sgx/certification/v4/tcb?fmspc=00A067110000")).await;
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
    let body = json!({
        "platforms": [{
            "qe_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "pce_id": "0001",
            "cpu_svn": "00000000000000000000000000000001",
            "pce_svn": "0001",
            "enc_ppid": "F".repeat(768),
            "fmspc": "00AABBCCDDEE"
        }],
        "collaterals": {
            "tcbinfos": [{
                "fmspc": "00AABBCCDDEE",
                "sgx_tcbinfo": {"tcbInfo":{"fmspc":"00AABBCCDDEE","id":"SGX"},"signature":"put-tcb"}
            }],
            "qeidentity": {"enclaveIdentity":{"id":"QE-PUT"},"signature":"put-qe"},
            "certificates": {
                "TCB-Info-Issuer-Chain": "put-tcb-issuer",
                "SGX-Enclave-Identity-Issuer-Chain": "put-qe-issuer"
            }
        }
    });
    let (status, _, _) = send(router.clone(), put_admin("/sgx/certification/v4/platformcollateral", body)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, h, body) = send(router.clone(), get("/sgx/certification/v4/tcb?fmspc=00AABBCCDDEE")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.get(headers::TCB_INFO_ISSUER_CHAIN).unwrap(), "put-tcb-issuer");
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(v["signature"], "put-tcb");

    let (status, h, body) = send(router, get("/sgx/certification/v4/qe/identity")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.get(headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN).unwrap(), "put-qe-issuer");
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

#[tokio::test]
#[ignore]
async fn live_phala_tcb_and_qe_identity() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut cfg = cfg_empty();
    cfg.uri = "https://pccs.phala.network/sgx/certification/v4/".into();
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    let (status, _, body) = send(router.clone(), get("/sgx/certification/v4/tcb?fmspc=00A067110000")).await;
    assert_eq!(status, StatusCode::OK, "live tcb {}", String::from_utf8_lossy(&body));
    let (status, _, body) = send(router, get("/sgx/certification/v4/qe/identity")).await;
    assert_eq!(status, StatusCode::OK, "live qe {}", String::from_utf8_lossy(&body));
}
