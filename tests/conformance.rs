//! Black-box HTTP conformance: a real pccs-rs listener plus an in-process fake
//! Intel PCS v4 upstream. No outbound network.

use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use pccs_rs::config::{CacheMode, Config, DEFAULT_ADMIN_TOKEN, DEFAULT_USER_TOKEN};
use pccs_rs::headers;
use pccs_rs::server::serve_http;
use pccs_rs::{app_state, create_app};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const PCK_PEM: &str = include_str!("fixtures/pck-synthetic.pem");
const CRL_DER: &[u8] = include_bytes!("fixtures/crl-synthetic.der");

const QEID: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const CPUSVN: &str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
const PCESVN: &str = "CCCC";
const PCEID: &str = "DDDD";
const FMSPC: &str = "00A067110000";
const ENCRYPTED_PPID: &str = "EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE";

const FIXTURE_TCB: &str =
    r#"{"tcbInfo":{"id":"SGX","fmspc":"00A067110000"},"signature":"tcb-sig"}"#;
const FIXTURE_TDX_TCB: &str =
    r#"{"tcbInfo":{"id":"TDX","fmspc":"00A067110000"},"signature":"tdx-tcb-sig"}"#;
const FIXTURE_QE: &str = r#"{"enclaveIdentity":{"id":"QE"},"signature":"qe-sig"}"#;
const FIXTURE_QVE: &str = r#"{"enclaveIdentity":{"id":"QVE"},"signature":"qve-sig"}"#;
const FIXTURE_TDQE: &str = r#"{"enclaveIdentity":{"id":"TD_QE"},"signature":"tdqe-sig"}"#;

#[derive(Clone, Copy, Debug)]
enum Script {
    Fixture,
    Empty200,
    Status(u16),
}

#[derive(Clone)]
struct FakePcs {
    script: Arc<Mutex<Script>>,
    delay: Arc<Mutex<Duration>>,
    calls: Arc<Mutex<HashMap<String, u64>>>,
    total: Arc<AtomicU64>,
}

impl FakePcs {
    fn new() -> Self {
        Self {
            script: Arc::new(Mutex::new(Script::Fixture)),
            delay: Arc::new(Mutex::new(Duration::ZERO)),
            calls: Arc::new(Mutex::new(HashMap::new())),
            total: Arc::new(AtomicU64::new(0)),
        }
    }

    fn set_script(&self, script: Script) {
        *self.script.lock().unwrap() = script;
    }

    fn set_delay(&self, delay: Duration) {
        *self.delay.lock().unwrap() = delay;
    }

    fn total(&self) -> u64 {
        self.total.load(Ordering::SeqCst)
    }

    fn count(&self, kind: &str) -> u64 {
        *self.calls.lock().unwrap().get(kind).unwrap_or(&0)
    }

    fn record(&self, kind: &str) {
        self.total.fetch_add(1, Ordering::SeqCst);
        *self.calls.lock().unwrap().entry(kind.to_string()).or_insert(0) += 1;
    }
}

fn classify(path: &str) -> &'static str {
    if path.contains("/pckcerts") {
        "pckcerts"
    } else if path.contains("/pckcert") {
        "pckcert"
    } else if path.contains("/pckcrl") {
        "pckcrl"
    } else if path.contains("/qve/identity") {
        "qve"
    } else if path.contains("/tdx/") && path.contains("/qe/identity") {
        "tdqe"
    } else if path.contains("/qe/identity") {
        "qe"
    } else if path.contains("/tdx/") && path.contains("/tcb") {
        "tdx-tcb"
    } else if path.contains("/tcb") {
        "tcb"
    } else if path.contains("rootcacrl") {
        "rootcacrl"
    } else {
        "other"
    }
}

fn fixture_for(kind: &str) -> Response {
    match kind {
        "pckcert" => {
            let mut resp = PCK_PEM.to_string().into_response();
            resp.headers_mut().insert(
                headers::SGX_TCBM,
                HeaderValue::from_static("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCC"),
            );
            resp.headers_mut().insert(headers::SGX_FMSPC, HeaderValue::from_static(FMSPC));
            resp.headers_mut().insert(
                headers::SGX_PCK_CERTIFICATE_CA_TYPE,
                HeaderValue::from_static("processor"),
            );
            resp.headers_mut().insert(
                headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
                HeaderValue::from_static("fake-pck-chain"),
            );
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static(headers::CONTENT_TYPE_PEM),
            );
            resp
        }
        "tcb" => json_chain(FIXTURE_TCB, headers::TCB_INFO_ISSUER_CHAIN, "fake-tcb-chain"),
        "tdx-tcb" => {
            json_chain(FIXTURE_TDX_TCB, headers::TCB_INFO_ISSUER_CHAIN, "fake-tdx-tcb-chain")
        }
        "qe" => json_chain(FIXTURE_QE, headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN, "fake-qe-chain"),
        "qve" => {
            json_chain(FIXTURE_QVE, headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN, "fake-qve-chain")
        }
        "tdqe" => {
            json_chain(FIXTURE_TDQE, headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN, "fake-tdqe-chain")
        }
        "pckcrl" | "rootcacrl" => {
            let mut resp = CRL_DER.to_vec().into_response();
            if kind == "pckcrl" {
                resp.headers_mut().insert(
                    headers::SGX_PCK_CRL_ISSUER_CHAIN,
                    HeaderValue::from_static("fake-pckcrl-chain"),
                );
            }
            resp.headers_mut().insert(
                axum::http::header::CONTENT_TYPE,
                HeaderValue::from_static(headers::CONTENT_TYPE_CRL),
            );
            resp
        }
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

fn json_chain(body: &'static str, chain_name: &'static str, chain: &'static str) -> Response {
    let mut resp = body.to_string().into_response();
    resp.headers_mut().insert(chain_name, HeaderValue::from_static(chain));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static(headers::CONTENT_TYPE_JSON),
    );
    resp
}

async fn spawn_fake(fake: FakePcs) -> String {
    let app =
        axum::Router::new().fallback(get(move |req: axum::http::Request<axum::body::Body>| {
            let fake = fake.clone();
            async move {
                let path = req.uri().path().to_string();
                let kind = classify(&path);
                let delay = *fake.delay.lock().unwrap();
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                fake.record(kind);
                let script = *fake.script.lock().unwrap();
                match script {
                    Script::Empty200 => StatusCode::OK.into_response(),
                    Script::Status(code) => StatusCode::from_u16(code)
                        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
                        .into_response(),
                    Script::Fixture => fixture_for(kind),
                }
            }
        }));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}/sgx/certification/v4/")
}

struct Harness {
    base: String,
    addr: std::net::SocketAddr,
    fake: FakePcs,
    _db: tempfile::TempDir,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

async fn start_harness() -> Harness {
    start_harness_with(|_cfg| {}).await
}

async fn start_harness_with(tune: impl FnOnce(&mut Config)) -> Harness {
    let fake = FakePcs::new();
    let uri = spawn_fake(fake.clone()).await;
    let db = tempfile::tempdir().unwrap();
    let mut cfg = Config::test_default();
    cfg.no_seed = true;
    cfg.seed = None;
    cfg.uri = uri;
    cfg.db_path = db.path().to_path_buf();
    cfg.cache_mode = CacheMode::Lazy;
    cfg.upstream_max_attempts = 1;
    cfg.pool_refetch_on_new_tcb = false;
    cfg.scheduled_pool_refresh = false;
    cfg.host = "127.0.0.1".into();
    cfg.port = 0;
    tune(&mut cfg);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = create_app(app_state(cfg.clone()));
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        serve_http(listener, app, &cfg, async {
            let _ = stop_rx.await;
        })
        .await;
    });
    wait_for_port(addr).await;
    Harness { base: format!("http://{addr}"), addr, fake, _db: db, shutdown: Some(stop_tx) }
}

async fn wait_for_port(addr: std::net::SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("server at {addr} never accepted a connection");
}

async fn http(
    base: &str,
    method: &str,
    path: &str,
    extra: &[(&str, &str)],
    body: Option<Bytes>,
) -> (StatusCode, HeaderMap, Bytes) {
    let uri: Uri = format!("{base}{path}").parse().unwrap();
    let mut builder = Request::builder().method(method).uri(uri).header("connection", "close");
    for (name, value) in extra {
        builder = builder.header(*name, *value);
    }
    let req = match body {
        Some(bytes) => builder.body(Full::new(bytes)).unwrap(),
        None => builder.body(Full::new(Bytes::new())).unwrap(),
    };
    let client = Client::builder(TokioExecutor::new()).build_http();
    let resp = client.request(req).await.expect("http request");
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await.expect("body").to_bytes();
    (status, headers, body)
}

async fn get(h: &Harness, path: &str) -> (StatusCode, HeaderMap, Bytes) {
    http(&h.base, "GET", path, &[], None).await
}

async fn get_admin(h: &Harness, path: &str) -> (StatusCode, HeaderMap, Bytes) {
    http(&h.base, "GET", path, &[(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)], None).await
}

fn pckcert_path() -> String {
    format!(
        "/sgx/certification/v4/pckcert?qeid={QEID}&cpusvn={CPUSVN}&pcesvn={PCESVN}&pceid={PCEID}&encrypted_ppid={ENCRYPTED_PPID}"
    )
}

struct CollateralCase {
    path: String,
    kind: &'static str,
    json_key: Option<&'static str>,
    chain: Option<&'static str>,
    content_type: &'static str,
}

fn collateral_cases() -> Vec<CollateralCase> {
    vec![
        CollateralCase {
            path: pckcert_path(),
            kind: "pckcert",
            json_key: None,
            chain: Some(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN),
            content_type: headers::CONTENT_TYPE_PEM,
        },
        CollateralCase {
            path: "/sgx/certification/v4/pckcrl?ca=processor".into(),
            kind: "pckcrl",
            json_key: None,
            chain: Some(headers::SGX_PCK_CRL_ISSUER_CHAIN),
            content_type: headers::CONTENT_TYPE_PEM,
        },
        CollateralCase {
            path: format!("/sgx/certification/v4/tcb?fmspc={FMSPC}"),
            kind: "tcb",
            json_key: Some("tcbInfo"),
            chain: Some(headers::TCB_INFO_ISSUER_CHAIN),
            content_type: headers::CONTENT_TYPE_JSON,
        },
        CollateralCase {
            path: format!("/tdx/certification/v4/tcb?fmspc={FMSPC}"),
            kind: "tdx-tcb",
            json_key: Some("tcbInfo"),
            chain: Some(headers::TCB_INFO_ISSUER_CHAIN),
            content_type: headers::CONTENT_TYPE_JSON,
        },
        CollateralCase {
            path: "/sgx/certification/v4/qe/identity".into(),
            kind: "qe",
            json_key: Some("enclaveIdentity"),
            chain: Some(headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN),
            content_type: headers::CONTENT_TYPE_JSON,
        },
        CollateralCase {
            path: "/sgx/certification/v4/qve/identity".into(),
            kind: "qve",
            json_key: Some("enclaveIdentity"),
            chain: Some(headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN),
            content_type: headers::CONTENT_TYPE_JSON,
        },
        CollateralCase {
            path: "/tdx/certification/v4/qe/identity".into(),
            kind: "tdqe",
            json_key: Some("enclaveIdentity"),
            chain: Some(headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN),
            content_type: headers::CONTENT_TYPE_JSON,
        },
        CollateralCase {
            path: "/sgx/certification/v4/rootcacrl".into(),
            kind: "rootcacrl",
            json_key: None,
            chain: None,
            content_type: headers::CONTENT_TYPE_CRL,
        },
    ]
}

fn public_routes() -> &'static [(&'static str, &'static str)] {
    &[
        ("GET", "/sgx/certification/v4/pckcert"),
        ("GET", "/sgx/certification/v4/pckcrl"),
        ("GET", "/sgx/certification/v4/tcb"),
        ("GET", "/sgx/certification/v4/qe/identity"),
        ("GET", "/sgx/certification/v4/qve/identity"),
        ("GET", "/sgx/certification/v4/rootcacrl"),
        ("GET", "/sgx/certification/v4/crl"),
        ("GET", "/sgx/certification/v4/appraisalpolicy"),
        ("GET", "/sgx/certification/v4/platforms"),
        ("GET", "/sgx/certification/v4/refresh"),
        ("POST", "/sgx/certification/v4/refresh"),
        ("POST", "/sgx/certification/v4/platforms"),
        ("PUT", "/sgx/certification/v4/platformcollateral"),
        ("PUT", "/sgx/certification/v4/appraisalpolicy"),
        ("GET", "/tdx/certification/v4/tcb"),
        ("GET", "/tdx/certification/v4/qe/identity"),
        ("GET", "/healthz/live"),
        ("GET", "/healthz/ready"),
        ("GET", "/healthz/startup"),
        ("GET", "/vcek/v1/Genoa/cert_chain"),
        ("GET", "/vlek/v1/Genoa/cert_chain"),
        ("GET", "/v1/rim/some-id"),
        ("POST", "/ocsp"),
        ("POST", "/nvidia/nras/attest/gpu"),
    ]
}

#[tokio::test]
async fn public_collateral_routes_status_headers_body_and_cache_hit() {
    let h = start_harness().await;
    for case in collateral_cases() {
        let before = h.fake.count(case.kind);
        let (status, headers, body) = get(&h, &case.path).await;
        assert_eq!(status, StatusCode::OK, "{} {}", case.path, String::from_utf8_lossy(&body));
        assert!(headers.get(headers::REQUEST_ID).is_some(), "{}", case.path);
        assert_eq!(
            headers.get(axum::http::header::CONTENT_TYPE).map(|v| v.as_bytes()),
            Some(case.content_type.as_bytes()),
            "{}",
            case.path
        );
        if let Some(name) = case.chain {
            assert!(headers.get(name).is_some(), "{} missing {name}", case.path);
        }
        if case.kind == "pckcert" {
            assert!(headers.get(headers::SGX_TCBM).is_some());
            assert_eq!(headers.get(headers::SGX_FMSPC).unwrap(), FMSPC);
            assert_eq!(headers.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).unwrap(), "PROCESSOR");
            assert!(body.windows(b"BEGIN CERTIFICATE".len()).any(|w| w == b"BEGIN CERTIFICATE"));
        }
        if let Some(key) = case.json_key {
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert!(v.get(key).is_some(), "{} body missing {key}", case.path);
        }
        if case.kind == "rootcacrl" {
            let hex = String::from_utf8(body.to_vec()).unwrap();
            assert_eq!(hex, hex::encode(CRL_DER));
        }
        assert_eq!(h.fake.count(case.kind), before + 1, "first {} must hit upstream", case.kind);

        let (status, _, _) = get(&h, &case.path).await;
        assert_eq!(status, StatusCode::OK, "second {}", case.path);
        assert_eq!(h.fake.count(case.kind), before + 1, "second {} must be a cache hit", case.kind);
    }
}

#[tokio::test]
async fn unexpected_body_on_no_body_routes_is_413() {
    let h = start_harness().await;
    let payload = Bytes::from_static(b"not-empty");
    for (method, path) in public_routes() {
        if matches!(
            (*method, *path),
            ("POST", "/sgx/certification/v4/platforms")
                | ("PUT", "/sgx/certification/v4/platformcollateral")
                | ("PUT", "/sgx/certification/v4/appraisalpolicy")
                | ("POST", "/ocsp")
                | ("POST", "/nvidia/nras/attest/gpu")
        ) {
            continue;
        }
        let (status, _, body) = http(&h.base, method, path, &[], Some(payload.clone())).await;
        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{method} {path}");
        assert_eq!(body.as_ref(), b"Content too large.");
    }

    let (status, _, body) =
        http(&h.base, "GET", "/sgx/certification/v4/tcb?fmspc=00A067110000", &[], Some(payload))
            .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body.as_ref(), b"Content too large.");
}

#[tokio::test]
async fn over_limit_body_on_body_route_is_still_413() {
    let h = start_harness_with(|cfg| cfg.max_body_size = 64).await;
    let big = Bytes::from(vec![b'x'; 256]);
    let (status, _, body) = http(
        &h.base,
        "POST",
        "/sgx/certification/v4/platforms",
        &[(headers::USER_TOKEN, DEFAULT_USER_TOKEN), ("content-type", "application/json")],
        Some(big),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body.as_ref(), b"Content too large.");
}

#[tokio::test]
async fn default_receive_timeouts_are_thirty_and_sixty() {
    let cfg = Config::default();
    assert_eq!(cfg.headers_timeout_secs, 30);
    assert_eq!(cfg.request_timeout_secs, 60);
}

#[tokio::test]
async fn configured_header_timeout_closes_a_silent_client() {
    let h = start_harness_with(|cfg| cfg.headers_timeout_secs = 1).await;
    let mut stream = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1300)).await;
    let mut buf = [0u8; 8];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(n, 0, "silent client must be dropped after the header timeout");
}

#[tokio::test]
async fn configured_request_timeout_is_408_on_a_stalled_body() {
    let h = start_harness_with(|cfg| cfg.request_timeout_secs = 1).await;
    let mut stream = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let req = format!(
        "POST /sgx/certification/v4/platforms HTTP/1.1\r\n\
         Host: {}\r\n\
         user-token: {DEFAULT_USER_TOKEN}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: 64\r\n\
         Connection: close\r\n\r\n{{\"qe_id\":",
        h.addr
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    let started = std::time::Instant::now();
    let (status, _, body) = read_http_response(&mut stream).await;
    assert_eq!(status, 408);
    assert_eq!(body, b"Request Timeout");
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refresh_same_target_coalesces_to_one_upstream_run() {
    let h = start_harness().await;
    let (status, _, _) = get(&h, &format!("/sgx/certification/v4/tcb?fmspc={FMSPC}")).await;
    assert_eq!(status, StatusCode::OK);
    h.fake.set_delay(Duration::from_millis(200));
    let before = h.fake.total();

    let a = {
        let base = h.base.clone();
        tokio::spawn(async move {
            http(
                &base,
                "GET",
                "/sgx/certification/v4/refresh",
                &[(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)],
                None,
            )
            .await
        })
    };
    let b = {
        let base = h.base.clone();
        tokio::spawn(async move {
            http(
                &base,
                "GET",
                "/sgx/certification/v4/refresh",
                &[(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)],
                None,
            )
            .await
        })
    };
    let (sa, _, _) = a.await.unwrap();
    let (sb, _, _) = b.await.unwrap();
    assert_eq!(sa, StatusCode::OK);
    assert_eq!(sb, StatusCode::OK);
    let shared = h.fake.total() - before;

    let (status, _, _) = get_admin(&h, "/sgx/certification/v4/refresh").await;
    assert_eq!(status, StatusCode::OK);
    let sequential = h.fake.total() - before - shared;
    assert_eq!(
        shared, sequential,
        "two overlapping callers must share one run ({shared} vs {sequential})"
    );
    assert!(shared > 0, "refresh must still talk to the upstream");
}

#[tokio::test]
async fn empty_200_from_upstream_is_not_cached_on_json_and_crl() {
    let h = start_harness().await;
    h.fake.set_script(Script::Empty200);
    for path in [
        format!("/sgx/certification/v4/tcb?fmspc={FMSPC}"),
        "/sgx/certification/v4/qe/identity".to_string(),
        "/sgx/certification/v4/pckcrl?ca=processor".to_string(),
        "/sgx/certification/v4/rootcacrl".to_string(),
    ] {
        let before = h.fake.total();
        let (status, _, body) = get(&h, &path).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "{path}");
        assert_eq!(body.as_ref(), b"Unable to retrieve the collateral from the Intel SGX PCS.");
        let after_first = h.fake.total();
        assert!(after_first > before, "{path} must hit upstream");

        let (status, _, _) = get(&h, &path).await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "second {path}");
        assert!(h.fake.total() > after_first, "{path} must not be cached");
    }
}

#[tokio::test]
async fn fake_upstream_status_modes_are_not_cached() {
    let h = start_harness().await;
    for code in [404u16, 410, 429, 503] {
        h.fake.set_script(Script::Status(code));
        let path = format!("/sgx/certification/v4/tcb?fmspc={FMSPC}");
        let before = h.fake.count("tcb");
        let (status, _, _) = get(&h, &path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "upstream {code}");
        let (status, _, _) = get(&h, &path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "second upstream {code}");
        assert!(h.fake.count("tcb") >= before + 2, "status {code} must not cache");
    }
}

#[tokio::test]
async fn trailing_slash_is_404_on_every_route() {
    let h = start_harness().await;
    for (method, path) in public_routes() {
        let slashed = format!("{path}/");
        let (status, _, _) = http(&h.base, method, &slashed, &[], None).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {slashed}");

        let (status, _, _) = http(&h.base, method, path, &[], None).await;
        assert_ne!(status, StatusCode::NOT_FOUND, "{method} {path} without a slash must match");
    }
}

#[tokio::test]
async fn chunked_body_on_get_is_413() {
    let h = start_harness().await;
    let mut stream = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    stream
        .write_all(
            b"GET /healthz/live HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\nx\r\n0\r\n\r\n",
        )
        .await
        .unwrap();
    let (status, _, body) = read_http_response(&mut stream).await;
    assert_eq!(status, 413);
    assert_eq!(body, b"Content too large.");
}

#[tokio::test]
async fn unread_body_still_delivers_413() {
    let h = start_harness().await;
    let stream = tokio::net::TcpStream::connect(h.addr).await.unwrap();
    let (mut rd, mut wr) = stream.into_split();
    let head = format!(
        "GET /sgx/certification/v4/rootcacrl HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Length: 65536\r\n\r\n",
        h.addr
    );
    wr.write_all(head.as_bytes()).await.unwrap();

    let reader = async {
        let mut owned = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = rd.read(&mut tmp).await.expect("response read");
            assert_ne!(n, 0, "connection closed before the 413 response");
            owned.extend_from_slice(&tmp[..n]);
            if let Some(parsed) = try_parse_response(&owned) {
                return parsed;
            }
        }
    };
    let writer = async {
        let chunk = [b'x'; 256];
        for _ in 0..32 {
            wr.write_all(&chunk).await.ok();
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    };

    let ((status, _, body), _) = tokio::join!(reader, writer);
    assert_eq!(status, 413);
    assert_eq!(body, b"Content too large.");
}

async fn read_http_response(stream: &mut tokio::net::TcpStream) -> (u16, HeaderMap, Vec<u8>) {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 1024];
    loop {
        let n = stream.read(&mut tmp).await.expect("read");
        assert_ne!(n, 0, "connection closed before a complete response");
        buf.extend_from_slice(&tmp[..n]);
        if let Some(parsed) = try_parse_response(&buf) {
            return parsed;
        }
    }
}

fn try_parse_response(buf: &[u8]) -> Option<(u16, HeaderMap, Vec<u8>)> {
    let split = buf.windows(4).position(|w| w == b"\r\n\r\n")?;
    let head = std::str::from_utf8(&buf[..split]).ok()?;
    let mut lines = head.split("\r\n");
    let start = lines.next()?;
    let mut parts = start.split_whitespace();
    let _ = parts.next()?;
    let status: u16 = parts.next()?.parse().ok()?;
    let mut headers = HeaderMap::new();
    let mut content_len = 0usize;
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("content-length") {
            content_len = value.trim().parse().unwrap_or(0);
        }
        if let (Ok(n), Ok(v)) = (
            axum::http::HeaderName::from_bytes(name.trim().as_bytes()),
            HeaderValue::from_str(value.trim()),
        ) {
            headers.insert(n, v);
        }
    }
    let body_start = split + 4;
    if buf.len() < body_start + content_len {
        return None;
    }
    Some((status, headers, buf[body_start..body_start + content_len].to_vec()))
}
