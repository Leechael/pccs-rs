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
use std::sync::{Arc, Mutex};
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
    Request::builder().method("GET").uri(path).body(Body::empty()).unwrap()
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

/// Synthetic Intel boundary for migration lifecycle regressions. The real
/// HTTP handlers, selection and RocksDB store remain in the test path.
#[derive(Clone)]
struct MigrationPool {
    cert: String,
    tcbm: String,
    chain: String,
    not_available: bool,
    fail: bool,
    tcb_pceid: String,
    standard_available: bool,
    tcb_signature: String,
    standard_pceid: Option<String>,
    tdx_pceid: Option<String>,
    tdx_type: i64,
    requests: Arc<AtomicU64>,
}

impl Default for MigrationPool {
    fn default() -> Self {
        Self {
            cert: PCK_PEM.into(),
            tcbm: format!("{PCK_CPUSVN}{PCK_PCESVN}"),
            chain: "migration-pck-chain".into(),
            not_available: false,
            fail: false,
            tcb_pceid: PCK_PCEID.into(),
            standard_available: true,
            tcb_signature: "synthetic".into(),
            standard_pceid: None,
            tdx_pceid: None,
            tdx_type: 0,
            requests: Arc::new(AtomicU64::new(0)),
        }
    }
}

fn migration_tcb_response(p: &MigrationPool, update: &str, prod: u8) -> axum::response::Response {
    p.requests.fetch_add(1, Ordering::Relaxed);
    if update == "standard" && !p.standard_available {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut info = pck_tcb_info();
    let pceid = if prod == 1 {
        info["id"] = json!("TDX");
        info["tcbType"] = json!(p.tdx_type);
        info["tcbLevels"][0]["tcb"]["tdxtcbcomponents"] =
            json!((0..16).map(|_| json!({"svn": 0})).collect::<Vec<_>>());
        p.tdx_pceid.as_deref().unwrap_or(&p.tcb_pceid)
    } else if update == "standard" {
        p.standard_pceid.as_deref().unwrap_or(&p.tcb_pceid)
    } else {
        &p.tcb_pceid
    };
    info["pceId"] = json!(pceid);
    let mut resp =
        axum::Json(json!({"tcbInfo": info, "signature": p.tcb_signature})).into_response();
    resp.headers_mut()
        .insert(headers::TCB_INFO_ISSUER_CHAIN, "migration-tcb-chain".parse().unwrap());
    resp
}

async fn spawn_migration_intel(
    pool: Arc<RwLock<MigrationPool>>,
) -> (String, tokio::task::JoinHandle<()>) {
    let tcb_pool = pool.clone();
    let tdx_pool = pool.clone();
    let app = axum::Router::new()
        .route(
            "/sgx/certification/v4/pckcerts",
            axum::routing::post(move |axum::Json(payload): axum::Json<serde_json::Value>| {
                let pool = pool.clone();
                async move {
                    if payload["pceid"] != PCK_PCEID
                        || !["ABCD", "BCDE"]
                            .contains(&payload["platformManifest"].as_str().unwrap_or(""))
                    {
                        return StatusCode::BAD_REQUEST.into_response();
                    }
                    let p = pool.read().await.clone();
                    p.requests.fetch_add(1, Ordering::Relaxed);
                    if p.fail {
                        return StatusCode::BAD_GATEWAY.into_response();
                    }
                    let mut entries = vec![json!({"tcbm": p.tcbm, "cert": p.cert})];
                    if p.not_available {
                        entries.push(json!({"tcbm": "00", "cert": "Not%20available"}));
                    }
                    let mut resp = axum::Json(entries).into_response();
                    resp.headers_mut().insert(headers::SGX_FMSPC, PCK_FMSPC.parse().unwrap());
                    resp.headers_mut()
                        .insert(headers::SGX_PCK_CERTIFICATE_CA_TYPE, "platform".parse().unwrap());
                    resp.headers_mut().insert(
                        headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
                        p.chain.parse().unwrap(),
                    );
                    resp
                }
            }),
        )
        .route(
            "/sgx/certification/v4/tcb",
            axum::routing::get(
                move |axum::extract::Query(q): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| {
                    let pool = tcb_pool.clone();
                    async move {
                        let p = pool.read().await;
                        migration_tcb_response(
                            &p,
                            q.get("update").map(String::as_str).unwrap_or("standard"),
                            0,
                        )
                    }
                },
            ),
        );
    let app = app.route(
        "/tdx/certification/v4/tcb",
        axum::routing::get(
            move |axum::extract::Query(q): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >| {
                let pool = tdx_pool.clone();
                async move {
                    let p = pool.read().await;
                    migration_tcb_response(
                        &p,
                        q.get("update").map(String::as_str).unwrap_or("standard"),
                        1,
                    )
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}/sgx/certification/v4/"), handle)
}

fn migration_pck_path(cpu: &str) -> String {
    format!(
        "/sgx/certification/v4/pckcert?qeid=AA&cpusvn={cpu}&pcesvn={PCK_PCESVN}&pceid={PCK_PCEID}"
    )
}

async fn migration_platform_rows(router: &axum::Router) -> serde_json::Value {
    let (status, _, body) = send(
        router.clone(),
        get_admin(&format!("/sgx/certification/v4/platforms?source=%5B{PCK_FMSPC}%5D")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_slice(&body).unwrap()
}

// Intent: regression / migration safety, plan invariant 6. Manifest-only fill
// succeeds without inventing raw CPU/PCE SVN mappings; REQ clears its NEW row.
#[tokio::test]
async fn migration_manifest_registration_then_ppidless_get() {
    for mode in [CacheMode::Lazy, CacheMode::Req] {
        let pool = Arc::new(RwLock::new(MigrationPool::default()));
        let (uri, server) = spawn_migration_intel(pool.clone()).await;
        let mut cfg = cfg_empty();
        cfg.uri = uri;
        cfg.cache_mode = mode;
        let router = app_cfg(cfg);
        let (status, _, body) = send(
            router.clone(),
            post_user(
                "/sgx/certification/v4/platforms",
                json!({
                    "qe_id": "AA", "pce_id": PCK_PCEID, "platform_manifest": "ABCD"
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "mode {mode:?}: {}", String::from_utf8_lossy(&body));
        assert_eq!(body.as_ref(), b"Operation successful.");
        assert_eq!(migration_platform_rows(&router).await, json!([]), "no invented raw mapping");
        let (status, _, body) =
            send(router.clone(), get_admin("/sgx/certification/v4/platforms?source=reg")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap(), json!([]));
        // Subsequent retrieval must use the stored pool, not depend on Intel.
        pool.write().await.fail = true;
        let (status, h, body) = send(router.clone(), get(&migration_pck_path(PCK_CPUSVN))).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
        assert_eq!(h.get(headers::SGX_TCBM).unwrap(), format!("{PCK_CPUSVN}{PCK_PCESVN}").as_str());
        assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), PCK_FMSPC);
        assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).unwrap(), "PLATFORM");
        assert_eq!(
            h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
            "migration-pck-chain"
        );
        let rows = migration_platform_rows(&router).await;
        assert_eq!(rows[0]["cpu_svn"], PCK_CPUSVN);
        assert_eq!(rows[0]["pce_svn"], PCK_PCESVN);
        assert_eq!(rows[0]["platform_manifest"], "ABCD");
        assert_eq!(rows[0]["enc_ppid"], "");
        server.abort();
    }
}

// Intent: regression / Intel 1.24 parity. A known platform ALWAYS selects
// locally, or returns404; it never refetches with stored/client credentials.
// Omitted/full-zero/nonzero PPID is ignored for known platforms; an explicitly
// empty query value still fails controller validation. Unknown uses the client
// credential only. Assert HTTP outcomes/cache state AND no boundary requests.
#[tokio::test]
async fn migration_pck_get_matches_intel_known_platform_boundary() {
    let calls = Arc::new(AtomicU64::new(0));
    let upstream_calls = calls.clone();
    let expected_ppid = Arc::new(RwLock::new("E".repeat(768)));
    let expected_upstream = expected_ppid.clone();
    let ppid_app = axum::Router::new().route(
        "/sgx/certification/v4/pckcert",
        axum::routing::get(
            move |axum::extract::Query(q): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >| {
                let expected_upstream = expected_upstream.clone();
                let calls = upstream_calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::Relaxed);
                    if q.get("encrypted_ppid") != Some(&*expected_upstream.read().await) {
                        return StatusCode::BAD_REQUEST.into_response();
                    }
                    let mut resp = PCK_PEM.into_response();
                    resp.headers_mut().insert(
                        headers::SGX_TCBM,
                        format!("{PCK_CPUSVN}{PCK_PCESVN}").parse().unwrap(),
                    );
                    resp.headers_mut().insert(headers::SGX_FMSPC, PCK_FMSPC.parse().unwrap());
                    resp.headers_mut()
                        .insert(headers::SGX_PCK_CERTIFICATE_CA_TYPE, "platform".parse().unwrap());
                    resp.headers_mut().insert(
                        headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
                        "migration-pck-chain".parse().unwrap(),
                    );
                    resp
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ppid_server = tokio::spawn(async move { axum::serve(listener, ppid_app).await.unwrap() });
    let manifest = Arc::new(RwLock::new(MigrationPool::default()));
    let (manifest_uri, manifest_server) = spawn_migration_intel(manifest.clone()).await;
    for request_ppid in [None, Some("0".repeat(768)), Some("F".repeat(768)), Some(String::new())] {
        let effective_ppid = if request_ppid.as_deref() == Some(&"F".repeat(768)) {
            "F".repeat(768)
        } else {
            "E".repeat(768)
        };
        *expected_ppid.write().await = effective_ppid.clone();
        for (manifest, uri, complete) in [
            ("", format!("http://{addr}/sgx/certification/v4/"), false),
            ("ABCD", manifest_uri.clone(), false),
            ("ABCD", manifest_uri.clone(), true),
        ] {
            let mut cfg = cfg_empty();
            cfg.uri = uri;
            cfg.cache_mode = CacheMode::Lazy;
            let mut state = pccs_rs::app_state(cfg);
            // Exercise Intel policy with a loopback HTTP boundary, not the
            // separately supported PCCS mirror policy inferred from this host.
            Arc::get_mut(&mut state.cache).unwrap().is_intel = true;
            // A real persisted incomplete platform, as encountered after migration.
            state
                .cache
                .store
                .put_platform_pool(&pccs_rs::store::PlatformPool {
                    qe_id: "AA".into(),
                    pce_id: PCK_PCEID.into(),
                    enc_ppid: "E".repeat(768),
                    platform_manifest: manifest.into(),
                    fmspc: PCK_FMSPC.into(),
                    ca: "PLATFORM".into(),
                    issuer_chain: "migration-pck-chain".into(),
                    certs: if complete {
                        vec![pccs_rs::store::PlatformCert {
                            tcbm: format!("{PCK_CPUSVN}{PCK_PCESVN}"),
                            cert: PCK_PEM.into(),
                        }]
                    } else {
                        Vec::new()
                    },
                    ..Default::default()
                })
                .unwrap();
            if complete {
                let doc = json!({"tcbInfo": pck_tcb_info(), "signature": "synthetic"});
                state
                    .cache
                    .store
                    .put_tcb(&pccs_rs::store::TcbRecord {
                        prod_type: 0,
                        fmspc: PCK_FMSPC.into(),
                        version: 4,
                        update_type: "STANDARD".into(),
                        raw_body: doc.to_string(),
                        tcbinfo: doc,
                        issuer_chain: "migration-tcb-chain".into(),
                    })
                    .unwrap();
            }
            let router = pccs_rs::create_app(state);
            let mut path = migration_pck_path(PCK_CPUSVN);
            if let Some(ppid) = &request_ppid {
                path.push_str(&format!("&encrypted_ppid={ppid}"));
            }
            let (status, h, body) = send(router.clone(), get(&path)).await;
            let expected_status = if request_ppid.as_deref() == Some("") {
                StatusCode::BAD_REQUEST
            } else if complete {
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            };
            assert_eq!(
                status,
                expected_status,
                "known complete={complete}, manifest {manifest:?}: {}",
                String::from_utf8_lossy(&body)
            );
            if status != StatusCode::OK {
                assert_eq!(
                    body.as_ref(),
                    if status == StatusCode::BAD_REQUEST {
                        b"Invalid request parameters.".as_slice()
                    } else {
                        b"No cache data for this platform.".as_slice()
                    }
                );
                assert_eq!(migration_platform_rows(&router).await, json!([]));
                continue;
            }
            assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
            assert_eq!(
                h.get(headers::SGX_TCBM).unwrap(),
                format!("{PCK_CPUSVN}{PCK_PCESVN}").as_str()
            );
            assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), PCK_FMSPC);
            assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).unwrap(), "PLATFORM");
            assert_eq!(
                h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
                "migration-pck-chain"
            );
            let rows = migration_platform_rows(&router).await;
            assert_eq!(
                rows[0]["enc_ppid"],
                "E".repeat(768),
                "known PPID query does not replace stored credentials"
            );
            assert_eq!(rows[0]["platform_manifest"], manifest);
            assert_eq!(rows[0]["cpu_svn"], PCK_CPUSVN);
            let (status, _, cached) = send(router, get(&path)).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(cached, body);
        }
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0, "known Intel platform never calls boundary");
    assert_eq!(
        manifest.read().await.requests.load(Ordering::Relaxed),
        0,
        "known Manifest pool never calls Intel boundary"
    );
    *expected_ppid.write().await = "E".repeat(768);
    let mut cfg = cfg_empty();
    cfg.uri = format!("http://{addr}/sgx/certification/v4/");
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    for (qeid, credential, expected) in [
        ("BB", None, StatusCode::NOT_FOUND),
        ("CC", Some("0".repeat(768)), StatusCode::NOT_FOUND),
        ("DD", Some(String::new()), StatusCode::BAD_REQUEST),
        ("EE", Some("E".repeat(768)), StatusCode::OK),
    ] {
        let mut path = migration_pck_path(PCK_CPUSVN).replace("qeid=AA", &format!("qeid={qeid}"));
        if let Some(ppid) = credential {
            path.push_str(&format!("&encrypted_ppid={ppid}"));
        }
        let (status, _, body) = send(router.clone(), get(&path)).await;
        assert_eq!(status, expected, "unknown platform {qeid}: {}", String::from_utf8_lossy(&body));
        assert_eq!(
            body.as_ref(),
            match expected {
                StatusCode::OK => PCK_PEM.as_bytes(),
                StatusCode::BAD_REQUEST => b"Invalid request parameters.",
                _ => b"No cache data for this platform.",
            }
        );
    }
    let fetched = calls.load(Ordering::Relaxed);
    let (status, _, body) =
        send(router.clone(), get(&migration_pck_path(PCK_CPUSVN).replace("qeid=AA", "qeid=EE")))
            .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
    let (status, _, _) =
        send(router, get(&migration_pck_path(&"33".repeat(16)).replace("qeid=AA", "qeid=EE")))
            .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "mirror forwards PPID-less raw miss; this mock requires caller PPID"
    );
    assert_eq!(calls.load(Ordering::Relaxed), fetched + 1);
    ppid_server.abort();
    manifest_server.abort();
}

// Intent: regression / invariant. PCCS mirrors forward missing raw keys when
// local selection is unavailable, even without enrollment credentials. A known
// upstream ignores caller PPID, so that value cannot replace retained metadata.
#[tokio::test]
async fn migration_mirror_missing_raw_preserves_inventory_and_credentials() {
    for initial_ppid in [Some("E".repeat(768)), None] {
        let calls = Arc::new(AtomicU64::new(0));
        let upstream_calls = calls.clone();
        let expected_initial = initial_ppid.clone();
        let upstream = axum::Router::new().route(
            "/sgx/certification/v4/pckcert",
            axum::routing::get(
                move |axum::extract::Query(q): axum::extract::Query<
                    std::collections::HashMap<String, String>,
                >| {
                    let calls = upstream_calls.clone();
                    let initial = expected_initial.clone();
                    async move {
                        let call = calls.fetch_add(1, Ordering::Relaxed);
                        assert_eq!(q["qeid"], "AA");
                        assert_eq!(q["pceid"], PCK_PCEID);
                        assert_eq!(q["pcesvn"], PCK_PCESVN);
                        let (cert, tcbm) = if call == 0 {
                            assert_eq!(q.get("encrypted_ppid"), initial.as_ref());
                            (PCK_PEM.to_string(), format!("{PCK_CPUSVN}{PCK_PCESVN}"))
                        } else if call == 1 {
                            assert_eq!(q.get("encrypted_ppid"), Some(&"F".repeat(768)));
                            (migration_pck_with_cpu(0x11), format!("{}3333", "11".repeat(16)))
                        } else if call == 2 {
                            assert!(!q.contains_key("encrypted_ppid"), "do not send saved PPID");
                            (PCK_PEM.to_string(), format!("{PCK_CPUSVN}{PCK_PCESVN}"))
                        } else {
                            return StatusCode::BAD_GATEWAY.into_response();
                        };
                        let mut resp = cert.into_response();
                        for (name, value) in [
                            (headers::SGX_TCBM, tcbm.as_str()),
                            (headers::SGX_FMSPC, PCK_FMSPC),
                            (headers::SGX_PCK_CERTIFICATE_CA_TYPE, "platform"),
                            (headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN, "mirror-chain"),
                        ] {
                            resp.headers_mut().insert(name, value.parse().unwrap());
                        }
                        resp
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
        let mut cfg = cfg_empty();
        cfg.uri = format!("http://{addr}/sgx/certification/v4/");
        cfg.cache_mode = CacheMode::Lazy;
        let state = pccs_rs::app_state(cfg);
        let cache = state.cache.clone();
        let router = pccs_rs::create_app(state);
        let first_path = initial_ppid
            .as_ref()
            .map(|ppid| format!("{}&encrypted_ppid={ppid}", migration_pck_path(PCK_CPUSVN)))
            .unwrap_or_else(|| migration_pck_path(PCK_CPUSVN));
        let lower = "11".repeat(16);
        let higher = "33".repeat(16);
        for (path, expected_cert, expected_tcbm) in [
            (first_path, PCK_PEM.to_string(), format!("{PCK_CPUSVN}{PCK_PCESVN}")),
            (
                format!("{}&encrypted_ppid={}", migration_pck_path(&lower), "F".repeat(768)),
                migration_pck_with_cpu(0x11),
                format!("{lower}{PCK_PCESVN}"),
            ),
            (migration_pck_path(&higher), PCK_PEM.to_string(), format!("{PCK_CPUSVN}{PCK_PCESVN}")),
        ] {
            let (status, h, body) = send(router.clone(), get(&path)).await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
            assert_eq!(body.as_ref(), expected_cert.as_bytes());
            assert_eq!(h.get(headers::SGX_TCBM).unwrap(), expected_tcbm.as_str());
            assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), PCK_FMSPC);
            assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).unwrap(), "PLATFORM");
            assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(), "mirror-chain");
        }
        assert_eq!(calls.load(Ordering::Relaxed), 3);
        assert!(cache
            .store
            .get_tcb(0, PCK_FMSPC, 4, pccs_rs::validate::UpdateType::Standard)
            .is_none());
        let pool = cache.store.get_platform_pool("AA", PCK_PCEID).unwrap();
        assert_eq!(pool.certs.len(), 2, "single-cert fetch must retain full inventory");
        assert_eq!(pool.raw_tcbs.len(), 3);
        assert_eq!(pool.enc_ppid, initial_ppid.clone().unwrap_or_default());
        assert!(pool.platform_manifest.is_empty());
        let rows = migration_platform_rows(&router).await;
        assert_eq!(rows.as_array().unwrap().len(), 3);
        for cpu in [PCK_CPUSVN, &lower, &higher] {
            let rec = cache.store.get_pckcert("AA", cpu, PCK_PCESVN, PCK_PCEID).unwrap();
            assert_eq!(rec.encrypted_ppid, initial_ppid);
            assert!(rec.platform_manifest.is_empty());
            assert!(rows.as_array().unwrap().iter().any(|row| {
                row["cpu_svn"] == cpu
                    && row["enc_ppid"] == initial_ppid.clone().unwrap_or_default()
                    && row["platform_manifest"] == ""
            }));
            let (status, _, _) = send(router.clone(), get(&migration_pck_path(cpu))).await;
            assert_eq!(status, StatusCode::OK);
        }
        assert_eq!(calls.load(Ordering::Relaxed), 3, "all raw GETs are tracked cache hits");
        server.abort();
    }
}

// Intent: regression / Intel parity. A previous unknown GET failure is an
// upstream negative-cache entry, not a ban on local selection after a valid
// Manifest POST. Use the SAME raw key immediately, with no TTL sleeps.
#[tokio::test]
async fn migration_manifest_post_bypasses_prior_unknown_get_failure() {
    for credential in [None, Some("0".repeat(768))] {
        let pool = Arc::new(RwLock::new(MigrationPool::default()));
        let (uri, server) = spawn_migration_intel(pool.clone()).await;
        let mut cfg = cfg_empty();
        cfg.uri = uri;
        cfg.cache_mode = CacheMode::Lazy;
        let mut state = pccs_rs::app_state(cfg);
        Arc::get_mut(&mut state.cache).unwrap().is_intel = true;
        let router = pccs_rs::create_app(state);
        let path = migration_pck_path(PCK_CPUSVN);
        let first = credential
            .as_ref()
            .map(|ppid| format!("{path}&encrypted_ppid={ppid}"))
            .unwrap_or_else(|| path.clone());
        let (status, _, _) = send(router.clone(), get(&first)).await;
        assert_eq!(
            status,
            if credential.is_none() { StatusCode::BAD_REQUEST } else { StatusCode::NOT_FOUND }
        );
        let (status, _, body) = send(
            router.clone(),
            post_user(
                "/sgx/certification/v4/platforms",
                json!({
                    "qe_id": "AA", "pce_id": PCK_PCEID, "platform_manifest": "ABCD"
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(migration_platform_rows(&router).await, json!([]));
        let calls = pool.read().await.requests.load(Ordering::Relaxed);
        let (status, h, body) = send(router.clone(), get(&path)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "known local selection must bypass old upstream error: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
        assert_eq!(h.get(headers::SGX_TCBM).unwrap(), format!("{PCK_CPUSVN}{PCK_PCESVN}").as_str());
        assert_eq!(
            h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
            "migration-pck-chain"
        );
        assert_eq!(pool.read().await.requests.load(Ordering::Relaxed), calls);
        let rows = migration_platform_rows(&router).await;
        assert_eq!(rows.as_array().unwrap().len(), 1);
        assert_eq!(rows[0]["cpu_svn"], PCK_CPUSVN);
        assert_eq!(rows[0]["platform_manifest"], "ABCD");
        server.abort();
    }
}

// Intent: regression / invariant, plan invariant 7. Refresh replaces all
// tracked selections, or fails without publishing an incompatible pool.
#[tokio::test]
async fn migration_refresh_reselects_or_retains_coherent_old_pool() {
    let pool = Arc::new(RwLock::new(MigrationPool::default()));
    let (uri, server) = spawn_migration_intel(pool.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg.clone());
    let (status, _, _) = send(
        router.clone(),
        post_user(
            "/sgx/certification/v4/platforms",
            json!({
                "qe_id": "AA", "pce_id": PCK_PCEID, "platform_manifest": "ABCD"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let higher = "33".repeat(16);
    for cpu in [PCK_CPUSVN, &higher] {
        let (status, _, body) = send(router.clone(), get(&migration_pck_path(cpu))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
    }
    assert_eq!(migration_platform_rows(&router).await.as_array().unwrap().len(), 2);
    // The new pool has distinct response bytes, mapping and issuer chain.
    let fresh_cert = format!("{PCK_PEM}\n");
    let fresh_tcbm = format!("{}3333", "11".repeat(16));
    {
        let mut p = pool.write().await;
        p.cert = fresh_cert.clone();
        p.tcbm = fresh_tcbm.clone();
        p.chain = "fresh-pck-chain".into();
    }
    let refresh = format!("/sgx/certification/v4/refresh?type=certs&fmspc={PCK_FMSPC}");
    let (status, _, body) = send(router.clone(), get_admin(&refresh)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    for cpu in [PCK_CPUSVN, &higher] {
        let (status, h, body) = send(router.clone(), get(&migration_pck_path(cpu))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), fresh_cert.as_bytes());
        assert_eq!(h.get(headers::SGX_TCBM).unwrap(), fresh_tcbm.as_str());
        assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(), "fresh-pck-chain");
    }
    let before = migration_platform_rows(&router).await;
    {
        let mut p = pool.write().await;
        // Valid transport shape, but a cert selection cannot parse.
        p.cert = "not an X.509 certificate".into();
        p.tcbm = format!("{}3333", "44".repeat(16));
        p.chain = "rejected-pck-chain".into();
    }
    let (status, _, body) = send(router.clone(), get_admin(&refresh)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "failed re-selection must fail refresh");
    assert_eq!(body.as_ref(), b"No cache data for this platform.");
    assert_eq!(
        migration_platform_rows(&router).await,
        before,
        "failed refresh preserves tracked raw levels"
    );
    // Cached responses AND selection for a previously unseen raw TCB must use
    // the retained pool. Merely retaining old success keys is insufficient.
    pool.write().await.fail = true;
    let unseen = "44".repeat(16);
    for cpu in [PCK_CPUSVN, &higher, &unseen] {
        let (status, h, body) = send(router.clone(), get(&migration_pck_path(cpu))).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(body.as_ref(), fresh_cert.as_bytes());
        assert_eq!(h.get(headers::SGX_TCBM).unwrap(), fresh_tcbm.as_str());
        assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(), "fresh-pck-chain");
        assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), PCK_FMSPC);
    }
    drop(router);
    let reopened = app_cfg(cfg);
    let (status, h, body) = send(reopened, get(&migration_pck_path(PCK_CPUSVN))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), fresh_cert.as_bytes());
    assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(), "fresh-pck-chain");
    server.abort();
}

/// Synthetic SGX cert with distinct component/octets CPUSVN. The existing
/// fixture is intentionally not cryptographically trusted; selection parses
/// these executable extension values, not the pool's tcbm label.
fn migration_pck_with_cpu(svn: u8) -> String {
    use base64::Engine;
    let body: String = PCK_PEM.lines().filter(|line| !line.starts_with("-----")).collect();
    let mut der = base64::engine::general_purpose::STANDARD.decode(body).unwrap();
    for component in 1..=16 {
        let needle = [
            0x06, 0x0B, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01, 0x02, component,
            0x02, 0x01, 0x22,
        ];
        let offset = der.windows(needle.len()).position(|w| w == needle).unwrap();
        der[offset + needle.len() - 1] = svn;
    }
    let mut octets = vec![0x04, 0x10];
    octets.extend([0x22; 16]);
    let offset = der.windows(octets.len()).position(|w| w == octets).unwrap();
    der[offset + 2..offset + 18].fill(svn);
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

fn migration_pck_with_ppid(cert: &str, ppid_byte: u8) -> String {
    use base64::Engine;
    let body: String = cert.lines().filter(|line| !line.starts_with("-----")).collect();
    let mut der = base64::engine::general_purpose::STANDARD.decode(body).unwrap();
    let mut needle = vec![0x04, 0x10];
    needle.extend([0x11; 16]);
    let offset = der.windows(needle.len()).position(|w| w == needle).unwrap();
    der[offset + 2..offset + 18].fill(ppid_byte);
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

// Intent: regression / migration safety. A PCCS single-cert refresh response is not
// a complete pool response: retain all existing certs/raw mappings while
// atomically merging selected refresh results and retaining all raw mappings.
#[tokio::test]
async fn migration_pccs_single_cert_refresh_preserves_pool_inventory() {
    let lower_cert = migration_pck_with_cpu(0x11);
    let fetched_cert = migration_pck_with_cpu(0x0E);
    let original_response = json!({ "cert": fetched_cert,
        "chain": "merged-pck-chain", "fmspc": PCK_FMSPC, "ca": "platform" });
    let response = Arc::new(RwLock::new(original_response.clone()));
    let reply = response.clone();
    let fail = Arc::new(AtomicBool::new(false));
    let failing = fail.clone();
    let block_second = Arc::new(AtomicBool::new(false));
    let blocking = block_second.clone();
    let blocked = Arc::new(tokio::sync::Notify::new());
    let blocked_mock = blocked.clone();
    let release = Arc::new(tokio::sync::Notify::new());
    let release_mock = release.clone();
    let upstream = axum::Router::new().route(
        "/sgx/certification/v4/pckcert",
        axum::routing::get(
            move |axum::extract::Query(q): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >| {
                let reply = reply.clone();
                let fail = failing.clone();
                let blocking = blocking.clone();
                let blocked = blocked_mock.clone();
                let release = release_mock.clone();
                async move {
                    if fail.load(Ordering::Relaxed)
                        || q.get("encrypted_ppid") != Some(&"E".repeat(768))
                    {
                        return StatusCode::BAD_GATEWAY.into_response();
                    }
                    let cpu = u8::from_str_radix(&q["cpusvn"][..2], 16).unwrap();
                    if cpu == 0x33 && blocking.swap(false, Ordering::Relaxed) {
                        blocked.notify_one();
                        release.notified().await;
                    }
                    let p = reply.read().await;
                    // The mirror's current selected cert is a new lower level;
                    // a single selected response is not a full-pool deletion.
                    let (cert, tcbm) =
                        (p["cert"].as_str().unwrap(), format!("{}3333", "0E".repeat(16)));
                    let mut resp = cert.to_string().into_response();
                    resp.headers_mut().insert(headers::SGX_TCBM, tcbm.parse().unwrap());
                    resp.headers_mut()
                        .insert(headers::SGX_FMSPC, p["fmspc"].as_str().unwrap().parse().unwrap());
                    resp.headers_mut().insert(
                        headers::SGX_PCK_CERTIFICATE_CA_TYPE,
                        p["ca"].as_str().unwrap().parse().unwrap(),
                    );
                    resp.headers_mut().insert(
                        headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
                        p["chain"].as_str().unwrap().parse().unwrap(),
                    );
                    resp
                }
            },
        ),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let mut cfg = cfg_empty();
    cfg.uri = format!("http://{addr}/sgx/certification/v4/");
    cfg.cache_mode = CacheMode::Lazy;
    let state = pccs_rs::app_state(cfg);
    state
        .cache
        .store
        .put_platform_pool(&pccs_rs::store::PlatformPool {
            qe_id: "AA".into(),
            pce_id: PCK_PCEID.into(),
            enc_ppid: "E".repeat(768),
            fmspc: PCK_FMSPC.into(),
            ca: "PLATFORM".into(),
            issuer_chain: "migration-pck-chain".into(),
            certs: vec![
                pccs_rs::store::PlatformCert {
                    tcbm: format!("{PCK_CPUSVN}{PCK_PCESVN}"),
                    cert: PCK_PEM.into(),
                },
                pccs_rs::store::PlatformCert {
                    tcbm: format!("{}3333", "11".repeat(16)),
                    cert: lower_cert.clone(),
                },
            ],
            ..Default::default()
        })
        .unwrap();
    let tcb = json!({"tcbInfo": pck_tcb_info(), "signature": "synthetic"});
    state
        .cache
        .store
        .put_tcb(&pccs_rs::store::TcbRecord {
            prod_type: 0,
            fmspc: PCK_FMSPC.into(),
            version: 4,
            update_type: "STANDARD".into(),
            raw_body: tcb.to_string(),
            tcbinfo: tcb,
            issuer_chain: "migration-tcb-chain".into(),
        })
        .unwrap();
    let router = pccs_rs::create_app(state);
    let higher = "33".repeat(16);
    for cpu in [PCK_CPUSVN, &higher] {
        let (status, _, body) = send(router.clone(), get(&migration_pck_path(cpu))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
    }
    let before = migration_platform_rows(&router).await;
    assert_eq!(before.as_array().unwrap().len(), 2);
    let refresh_path = format!("/sgx/certification/v4/refresh?type=certs&fmspc={PCK_FMSPC}");
    // Local selection handles these GETs; explicit refresh tests invalid
    // responses retain the full pool, raw inventory and selected GET metadata.
    for (field, bad) in [
        ("fmspc", "FFFFFFFFFFFF".to_string()),
        ("ca", "processor".to_string()),
        ("cert", migration_pck_with_ppid(&fetched_cert, 0x77)),
        ("cert", "opaque malformed cert".to_string()),
    ] {
        let mut candidate = original_response.clone();
        candidate[field] = json!(bad);
        *response.write().await = candidate;
        let (status, _, body) = send(router.clone(), get_admin(&refresh_path)).await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "reject incompatible {field}: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(body.as_ref(), b"No cache data for this platform.");
        assert_eq!(migration_platform_rows(&router).await, before);
        let (status, h, body) = send(router.clone(), get(&migration_pck_path(PCK_CPUSVN))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
        assert_eq!(
            h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
            "migration-pck-chain"
        );
    }
    *response.write().await = original_response;
    let (status, _, body) = send(router.clone(), get_admin(&refresh_path)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    for cpu in [PCK_CPUSVN, &higher] {
        let (status, h, body) = send(router.clone(), get(&migration_pck_path(cpu))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), fetched_cert.as_bytes());
        assert_eq!(h.get(headers::SGX_TCBM).unwrap(), format!("{}3333", "0E".repeat(16)).as_str());
    }
    let after = migration_platform_rows(&router).await;
    assert_eq!(
        after.as_array().unwrap().len(),
        2,
        "single-cert refresh retains both old raw mappings"
    );
    for row in before.as_array().unwrap() {
        assert!(after.as_array().unwrap().contains(row));
    }
    fail.store(true, Ordering::Relaxed);
    // Previously unselected certificates remain available for new raw TCBS,
    // proving full pool inventory, not merely old GET keys, was retained.
    for (cpu, expected) in [("11".repeat(16), lower_cert), ("23".repeat(16), PCK_PEM.into())] {
        let (status, h, body) = send(router.clone(), get(&migration_pck_path(&cpu))).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(body.as_ref(), expected.as_bytes());
        assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), PCK_FMSPC);
        assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(), "merged-pck-chain");
    }
    for cpu in [PCK_CPUSVN, &higher] {
        let (status, h, body) = send(router.clone(), get(&migration_pck_path(cpu))).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), fetched_cert.as_bytes());
        assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(), "merged-pck-chain");
    }
    // Deterministic external-boundary gate: after refreshing raw 22, pause
    // raw 33 upstream. Both select the SAME tcbm, so raw 33 must already have
    // the renewed body/header atomically, not wait for its own network fetch.
    let renewed = format!("{fetched_cert}\n");
    {
        let mut p = response.write().await;
        p["cert"] = json!(renewed);
        p["chain"] = json!("renewed-pck-chain");
    }
    fail.store(false, Ordering::Relaxed);
    block_second.store(true, Ordering::Relaxed);
    let r = router.clone();
    let refresh = tokio::spawn(async move {
        send(r, get_admin(&format!("/sgx/certification/v4/refresh?type=certs&fmspc={PCK_FMSPC}")))
            .await
    });
    tokio::time::timeout(std::time::Duration::from_secs(5), blocked.notified()).await.unwrap();
    let (status, h, body) = send(router.clone(), get(&migration_pck_path(&higher))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), renewed.as_bytes());
    assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(), "renewed-pck-chain");
    release.notify_one();
    let (status, _, body) = refresh.await.unwrap();
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    server.abort();
}

// Intent: regression / invariant. A failed certificate refresh must retain
// shared TCB collateral as well as the old pool/GET keys, so an unseen raw TCB
// can still select locally. Explicit cert refresh uses EARLY ephemerally and
// must not require the unrelated STANDARD endpoint to be available.
#[tokio::test]
async fn migration_cert_refresh_preserves_shared_tcb_on_selection_failure() {
    let pool = Arc::new(RwLock::new(MigrationPool::default()));
    let (uri, server) = spawn_migration_intel(pool.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    let (status, _, _) = send(
        router.clone(),
        post_user(
            "/sgx/certification/v4/platforms",
            json!({
                "qe_id": "AA", "pce_id": PCK_PCEID, "platform_manifest": "ABCD"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, old_cert) = send(router.clone(), get(&migration_pck_path(PCK_CPUSVN))).await;
    assert_eq!(status, StatusCode::OK);
    let tcb_path = format!("/sgx/certification/v4/tcb?fmspc={PCK_FMSPC}");
    let (status, _, old_standard) = send(router.clone(), get(&tcb_path)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, old_early) =
        send(router.clone(), get(&format!("{tcb_path}&update=early"))).await;
    assert_eq!(status, StatusCode::OK);
    pool.write().await.tcb_pceid = "5555".into();
    let refresh = format!("/sgx/certification/v4/refresh?type=certs&fmspc={PCK_FMSPC}");
    let (status, _, body) = send(router.clone(), get_admin(&refresh)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body.as_ref(), b"No cache data for this platform.");
    for (path, expected) in
        [(tcb_path.clone(), old_standard), (format!("{tcb_path}&update=early"), old_early)]
    {
        let (status, _, body) = send(router.clone(), get(&path)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, expected, "failed cert refresh must not poison shared TCB collateral");
    }
    pool.write().await.fail = true;
    let unseen = "33".repeat(16);
    let (status, h, body) = send(router.clone(), get(&migration_pck_path(&unseen))).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(body, old_cert);
    assert_eq!(h.get(headers::SGX_TCBM).unwrap(), format!("{PCK_CPUSVN}{PCK_PCESVN}").as_str());
    {
        let mut p = pool.write().await;
        p.fail = false;
        p.tcb_pceid = PCK_PCEID.into();
        p.standard_available = false;
        p.cert = format!("{PCK_PEM}\n");
        p.chain = "early-only-refresh-chain".into();
    }
    let (status, _, body) = send(router.clone(), get_admin(&refresh)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "cert refresh must not depend on STANDARD: {}",
        String::from_utf8_lossy(&body)
    );
    let (status, h, body) = send(router, get(&migration_pck_path(&unseen))).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), format!("{PCK_PEM}\n").as_bytes());
    assert_eq!(
        h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
        "early-only-refresh-chain"
    );
    server.abort();
}

// Intent: regression / Intel parity. TDX is collateral forwarding, not the
// SGX PCK selection algorithm: an integer type1 must retain its original body
// while actual PCK selection continues to use the separate SGX type0 document.
#[tokio::test]
async fn migration_tdx_nonzero_type_is_forwarded_without_sgx_selection() {
    let pool = Arc::new(RwLock::new(MigrationPool { tdx_type: 1, ..Default::default() }));
    let (uri, server) = spawn_migration_intel(pool.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    let (status, _, body) = send(
        router.clone(),
        post_user(
            "/sgx/certification/v4/platforms",
            json!({
                "qe_id": "AA", "pce_id": PCK_PCEID, "platform_manifest": "ABCD"
            }),
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "TDX integer type1 is not SGX selection: {}",
        String::from_utf8_lossy(&body)
    );
    assert_eq!(migration_platform_rows(&router).await, json!([]));
    let calls = pool.read().await.requests.load(Ordering::Relaxed);
    let mut info = pck_tcb_info();
    info["id"] = json!("TDX");
    info["tcbType"] = json!(1);
    info["tcbLevels"][0]["tcb"]["tdxtcbcomponents"] =
        json!((0..16).map(|_| json!({"svn": 0})).collect::<Vec<_>>());
    let expected = json!({"tcbInfo": info, "signature": "synthetic"}).to_string();
    for update in ["early", "standard"] {
        let (status, h, body) = send(
            router.clone(),
            get(&format!("/tdx/certification/v4/tcb?fmspc={PCK_FMSPC}&update={update}")),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_ref(), expected.as_bytes(), "TDX raw bytes retain nonzero type");
        assert_eq!(h.get(headers::TCB_INFO_ISSUER_CHAIN).unwrap(), "migration-tcb-chain");
    }
    let (status, h, body) = send(router, get(&migration_pck_path(PCK_CPUSVN))).await;
    assert_eq!(status, StatusCode::OK, "actual PCK selection still uses SGX type0");
    assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
    assert_eq!(h.get(headers::SGX_TCBM).unwrap(), format!("{PCK_CPUSVN}{PCK_PCESVN}").as_str());
    assert_eq!(pool.read().await.requests.load(Ordering::Relaxed), calls);
    server.abort();
}

// Intent: regression / invariant. Manifest-only registration has no requested
// or tracked raw TCB. Validate every staged document anyway: a bad STANDARD
// must not hide behind valid EARLY, nor may bad TDX shared metadata poison a
// same-FMSPC platform's served collateral or later local selection.
#[tokio::test]
async fn migration_manifest_registration_validates_all_staged_tcb_documents() {
    for bad_source in ["sgx_early", "sgx_standard", "tdx"] {
        let pool = Arc::new(RwLock::new(MigrationPool::default()));
        let (uri, server) = spawn_migration_intel(pool.clone()).await;
        let mut cfg = cfg_empty();
        cfg.uri = uri;
        cfg.cache_mode = CacheMode::Lazy;
        let mut state = pccs_rs::app_state(cfg);
        Arc::get_mut(&mut state.cache).unwrap().is_intel = true;
        let router = pccs_rs::create_app(state);
        let (status, _, _) = send(
            router.clone(),
            post_user(
                "/sgx/certification/v4/platforms",
                json!({
                    "qe_id": "AA", "pce_id": PCK_PCEID, "platform_manifest": "ABCD"
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "valid SGX and TDX type-0 documents accepted");
        assert_eq!(migration_platform_rows(&router).await, json!([]), "no invented raw TCB");
        let (status, _, old_cert) =
            send(router.clone(), get(&migration_pck_path(PCK_CPUSVN))).await;
        assert_eq!(status, StatusCode::OK);
        let old_rows = migration_platform_rows(&router).await;
        let mut saved = Vec::new();
        for prod in ["sgx", "tdx"] {
            for update in ["early", "standard"] {
                let path =
                    format!("/{prod}/certification/v4/tcb?fmspc={PCK_FMSPC}&update={update}");
                let (status, _, body) = send(router.clone(), get(&path)).await;
                assert_eq!(status, StatusCode::OK);
                let doc: serde_json::Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(doc["tcbInfo"]["id"], if prod == "sgx" { "SGX" } else { "TDX" });
                saved.push((path, body));
            }
        }
        {
            let mut p = pool.write().await;
            match bad_source {
                "sgx_early" => {
                    p.tcb_pceid = "5555".into();
                    p.standard_pceid = Some(PCK_PCEID.into());
                    p.tdx_pceid = Some(PCK_PCEID.into());
                }
                "sgx_standard" => p.standard_pceid = Some("5555".into()),
                "tdx" => p.tdx_pceid = Some("5555".into()),
                _ => unreachable!(),
            }
            p.tcb_signature = "must-not-publish".into();
        }
        let (status, _, body) = send(
            router.clone(),
            post_user(
                "/sgx/certification/v4/platforms",
                json!({
                    "qe_id": "BB", "pce_id": PCK_PCEID, "platform_manifest": "ABCD"
                }),
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "new no-raw platform must reject {bad_source}: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(body.as_ref(), b"No cache data for this platform.");
        assert_eq!(migration_platform_rows(&router).await, old_rows);
        for (path, expected) in saved {
            let (status, _, body) = send(router.clone(), get(&path)).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, expected, "rejected registration must preserve {path}");
        }
        pool.write().await.fail = true;
        let unseen = "33".repeat(16);
        let (status, h, body) = send(router.clone(), get(&migration_pck_path(&unseen))).await;
        assert_eq!(status, StatusCode::OK, "same-FMSPC platform remains locally selectable");
        assert_eq!(body, old_cert);
        assert_eq!(h.get(headers::SGX_TCBM).unwrap(), format!("{PCK_CPUSVN}{PCK_PCESVN}").as_str());
        let unknown = migration_pck_path(PCK_CPUSVN).replace("qeid=AA", "qeid=BB");
        let (status, _, body) = send(router, get(&unknown)).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "rejected registration must not leave a platform pool"
        );
        assert_eq!(body.as_ref(), b"Invalid request parameters.");
        server.abort();
    }
}

// Intent: regression / invariant. Two unknown GETs for different raw keys may
// publish in either order when the actual fetch credentials agree. Different
// credentials still make the late response stale. Gate only external HTTP.
#[tokio::test]
async fn migration_parallel_unknown_gets_check_actual_fetch_credentials() {
    for intel in [false, true] {
        for same_credentials in [true, false] {
            let blocked = Arc::new(tokio::sync::Notify::new());
            let release = Arc::new(tokio::sync::Notify::new());
            let calls = Arc::new(AtomicU64::new(0));
            let response = {
                let blocked = blocked.clone();
                let release = release.clone();
                let calls = calls.clone();
                move |q: std::collections::HashMap<String, String>| {
                    let blocked = blocked.clone();
                    let release = release.clone();
                    let calls = calls.clone();
                    async move {
                        assert_eq!(q["pceid"], PCK_PCEID);
                        let late = calls.fetch_add(1, Ordering::Relaxed) == 0;
                        assert_eq!(
                            q["encrypted_ppid"],
                            if late || same_credentials {
                                "E".repeat(768)
                            } else {
                                "F".repeat(768)
                            }
                        );
                        if late {
                            blocked.notify_one();
                            release.notified().await;
                        }
                        let tcbm = format!("{PCK_CPUSVN}{PCK_PCESVN}");
                        let mut resp = if intel {
                            axum::Json(json!([{"tcbm": tcbm, "cert": PCK_PEM}])).into_response()
                        } else {
                            PCK_PEM.into_response()
                        };
                        for (name, value) in [
                            (headers::SGX_TCBM, tcbm.as_str()),
                            (headers::SGX_FMSPC, PCK_FMSPC),
                            (headers::SGX_PCK_CERTIFICATE_CA_TYPE, "platform"),
                            (
                                headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
                                if late { "late-chain" } else { "published-chain" },
                            ),
                        ] {
                            resp.headers_mut().insert(name, value.parse().unwrap());
                        }
                        resp
                    }
                }
            };
            let upstream = axum::Router::new()
                .route(
                    if intel {
                        "/sgx/certification/v4/pckcerts"
                    } else {
                        "/sgx/certification/v4/pckcert"
                    },
                    axum::routing::get(move |axum::extract::Query(q)| response(q)),
                )
                .route(
                    "/sgx/certification/v4/tcb",
                    axum::routing::get(
                        |axum::extract::Query(q): axum::extract::Query<
                            std::collections::HashMap<String, String>,
                        >| async move {
                            migration_tcb_response(&MigrationPool::default(), &q["update"], 0)
                        },
                    ),
                )
                .route(
                    "/tdx/certification/v4/tcb",
                    axum::routing::get(
                        |axum::extract::Query(q): axum::extract::Query<
                            std::collections::HashMap<String, String>,
                        >| async move {
                            migration_tcb_response(&MigrationPool::default(), &q["update"], 1)
                        },
                    ),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server =
                tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
            let mut cfg = cfg_empty();
            cfg.uri = format!("http://{addr}/sgx/certification/v4/");
            cfg.cache_mode = CacheMode::Lazy;
            let mut state = pccs_rs::app_state(cfg);
            Arc::get_mut(&mut state.cache).unwrap().is_intel = intel;
            let cache = state.cache.clone();
            let router = pccs_rs::create_app(state);
            let late_cpu = "33".repeat(16);
            let r = router.clone();
            let late_path =
                format!("{}&encrypted_ppid={}", migration_pck_path(&late_cpu), "E".repeat(768));
            let pending = tokio::spawn(async move { send(r, get(&late_path)).await });
            tokio::time::timeout(std::time::Duration::from_secs(5), blocked.notified())
                .await
                .unwrap();
            let published_ppid = if same_credentials { "E".repeat(768) } else { "F".repeat(768) };
            let (status, _, body) = send(
                router.clone(),
                get(&format!("{}&encrypted_ppid={published_ppid}", migration_pck_path(PCK_CPUSVN))),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
            assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
            let published_rows = migration_platform_rows(&router).await;
            assert_eq!(published_rows.as_array().unwrap().len(), 1);
            release.notify_one();
            let (status, _, body) = pending.await.unwrap();
            assert_eq!(
                status,
                if same_credentials { StatusCode::OK } else { StatusCode::NOT_FOUND },
                "intel={intel}, same_credentials={same_credentials}: {}",
                String::from_utf8_lossy(&body)
            );
            assert_eq!(
                body.as_ref(),
                if same_credentials {
                    PCK_PEM.as_bytes()
                } else {
                    b"No cache data for this platform."
                }
            );
            let rows = migration_platform_rows(&router).await;
            if !same_credentials {
                assert_eq!(rows, published_rows, "late result must not mutate published platform");
                assert!(cache.store.get_pckcert("AA", &late_cpu, PCK_PCESVN, PCK_PCEID).is_none());
            }
            assert_eq!(rows.as_array().unwrap().len(), if same_credentials { 2 } else { 1 });
            for cpu in if same_credentials { vec![PCK_CPUSVN, &late_cpu] } else { vec![PCK_CPUSVN] }
            {
                let (status, h, body) = send(router.clone(), get(&migration_pck_path(cpu))).await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
                assert_eq!(
                    h.get(headers::SGX_TCBM).unwrap(),
                    format!("{PCK_CPUSVN}{PCK_PCESVN}").as_str()
                );
                assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), PCK_FMSPC);
                assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).unwrap(), "PLATFORM");
                assert_eq!(
                    h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
                    if same_credentials { "late-chain" } else { "published-chain" }
                );
                let rec = cache.store.get_pckcert("AA", cpu, PCK_PCESVN, PCK_PCEID).unwrap();
                assert_eq!(rec.encrypted_ppid.as_deref(), Some(published_ppid.as_str()));
                assert!(rec.platform_manifest.is_empty());
            }
            assert_eq!(calls.load(Ordering::Relaxed), 2, "both successful raw keys remain tracked");
            server.abort();
        }
    }
}

// Intent: regression / migration safety. A pool response fetched under M0
// must not overwrite a concurrent successful registration's M1 credentials.
// Exercise explicit Manifest/PPID refresh, an UNKNOWN client-credential GET,
// and a POST racing an identical-Manifest POST (which keeps the strict guard).
// Block only external requests, with no known-platform GET refills.
#[tokio::test]
async fn migration_stale_manifest_fetch_cannot_overwrite_new_registration() {
    for (mode, trigger) in [
        (CacheMode::Req, "refresh"),
        (CacheMode::Lazy, "unknown"),
        (CacheMode::Req, "mirror_refresh"),
        (CacheMode::Req, "raw_addition"),
        (CacheMode::Lazy, "same_manifest_post"),
    ] {
        let arm = Arc::new(AtomicBool::new(false));
        let armed = arm.clone();
        let blocked = Arc::new(tokio::sync::Notify::new());
        let blocked_mock = blocked.clone();
        let release = Arc::new(tokio::sync::Notify::new());
        let release_mock = release.clone();
        let mirror_arm = arm.clone();
        let mirror_blocked = blocked.clone();
        let mirror_release = release.clone();
        let upstream = axum::Router::new()
            .route(
                "/sgx/certification/v4/pckcerts",
                axum::routing::post(move |axum::Json(payload): axum::Json<serde_json::Value>| {
                    let arm = armed.clone();
                    let blocked = blocked_mock.clone();
                    let release = release_mock.clone();
                    async move {
                        let manifest = payload["platformManifest"].as_str().unwrap();
                        assert_eq!(payload["pceid"], PCK_PCEID);
                        assert!(["ABCD", "BCDE"].contains(&manifest));
                        let old_pending = manifest == "ABCD" && arm.swap(false, Ordering::Relaxed);
                        if old_pending {
                            blocked.notify_one();
                            release.notified().await;
                        }
                        let (cert, tcbm, chain) = if old_pending {
                            (
                                migration_pck_with_cpu(0x11),
                                format!("{}3333", "11".repeat(16)),
                                "old-M0-chain",
                            )
                        } else if manifest == "BCDE" {
                            (
                                format!("{PCK_PEM}\n"),
                                format!("{PCK_CPUSVN}{PCK_PCESVN}"),
                                "new-M1-chain",
                            )
                        } else {
                            (
                                PCK_PEM.into(),
                                format!("{PCK_CPUSVN}{PCK_PCESVN}"),
                                "initial-M0-chain",
                            )
                        };
                        let mut resp =
                            axum::Json(json!([{"tcbm": tcbm, "cert": cert}])).into_response();
                        resp.headers_mut().insert(headers::SGX_FMSPC, PCK_FMSPC.parse().unwrap());
                        resp.headers_mut().insert(
                            headers::SGX_PCK_CERTIFICATE_CA_TYPE,
                            "platform".parse().unwrap(),
                        );
                        resp.headers_mut().insert(
                            headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
                            chain.parse().unwrap(),
                        );
                        resp
                    }
                }),
            )
            .route(
                "/sgx/certification/v4/pckcert",
                axum::routing::get(
                    move |axum::extract::Query(q): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >| {
                        let arm = mirror_arm.clone();
                        let blocked = mirror_blocked.clone();
                        let release = mirror_release.clone();
                        async move {
                            assert_eq!(q["encrypted_ppid"], "E".repeat(768));
                            let pending = arm.swap(false, Ordering::Relaxed);
                            if pending {
                                blocked.notify_one();
                                release.notified().await;
                            }
                            let (cert, tcbm, chain) = if pending {
                                (
                                    migration_pck_with_cpu(0x11),
                                    format!("{}3333", "11".repeat(16)),
                                    "old-mirror-chain",
                                )
                            } else {
                                (
                                    PCK_PEM.into(),
                                    format!("{PCK_CPUSVN}{PCK_PCESVN}"),
                                    "initial-M0-chain",
                                )
                            };
                            let mut resp = cert.into_response();
                            resp.headers_mut().insert(headers::SGX_TCBM, tcbm.parse().unwrap());
                            resp.headers_mut()
                                .insert(headers::SGX_FMSPC, PCK_FMSPC.parse().unwrap());
                            resp.headers_mut().insert(
                                headers::SGX_PCK_CERTIFICATE_CA_TYPE,
                                "platform".parse().unwrap(),
                            );
                            resp.headers_mut().insert(
                                headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN,
                                chain.parse().unwrap(),
                            );
                            resp
                        }
                    },
                ),
            )
            .route(
                "/sgx/certification/v4/tcb",
                axum::routing::get(
                    |axum::extract::Query(q): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >| async move {
                        migration_tcb_response(&MigrationPool::default(), &q["update"], 0)
                    },
                ),
            )
            .route(
                "/tdx/certification/v4/tcb",
                axum::routing::get(
                    |axum::extract::Query(q): axum::extract::Query<
                        std::collections::HashMap<String, String>,
                    >| async move {
                        migration_tcb_response(&MigrationPool::default(), &q["update"], 1)
                    },
                ),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
        let mut cfg = cfg_empty();
        cfg.uri = format!("http://{addr}/sgx/certification/v4/");
        cfg.cache_mode = mode;
        let router = app_cfg(cfg);
        let registration = |manifest| {
            post_user(
                "/sgx/certification/v4/platforms",
                json!({
                    "qe_id": "AA", "pce_id": PCK_PCEID, "platform_manifest": manifest
                }),
            )
        };
        let initial = if trigger == "mirror_refresh" {
            post_user(
                "/sgx/certification/v4/platforms",
                json!({"qe_id": "AA", "pce_id": PCK_PCEID,
                "cpu_svn": PCK_CPUSVN, "pce_svn": PCK_PCESVN, "enc_ppid": "E".repeat(768)}),
            )
        } else {
            registration("ABCD")
        };
        if !["unknown", "same_manifest_post"].contains(&trigger) {
            let (status, _, _) = send(router.clone(), initial).await;
            assert_eq!(status, StatusCode::OK);
            let (status, _, body) =
                send(router.clone(), get(&migration_pck_path(PCK_CPUSVN))).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
        }
        arm.store(true, Ordering::Relaxed);
        let r = router.clone();
        let pending = tokio::spawn(async move {
            let req = if trigger == "unknown" {
                get(&format!(
                    "{}&encrypted_ppid={}",
                    migration_pck_path(&"11".repeat(16)),
                    "E".repeat(768)
                ))
            } else if trigger == "same_manifest_post" {
                post_user(
                    "/sgx/certification/v4/platforms",
                    json!({"qe_id": "AA", "pce_id": PCK_PCEID, "platform_manifest": "ABCD"}),
                )
            } else {
                get_admin(&format!("/sgx/certification/v4/refresh?type=certs&fmspc={PCK_FMSPC}"))
            };
            send(r, req).await
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), blocked.notified()).await.unwrap();
        if trigger == "raw_addition" {
            // A pool/raw change with identical credentials is NOT a stale
            // fetch. Include the new level by re-reading raws under the lock.
            let added = "33".repeat(16);
            let (status, _, _) = send(router.clone(), get(&migration_pck_path(&added))).await;
            assert_eq!(status, StatusCode::OK);
            release.notify_one();
            let (status, _, body) = pending.await.unwrap();
            assert_eq!(
                status,
                StatusCode::OK,
                "raw additions must not reject refresh: {}",
                String::from_utf8_lossy(&body)
            );
            let rows = migration_platform_rows(&router).await;
            assert_eq!(rows.as_array().unwrap().len(), 2);
            for cpu in [PCK_CPUSVN, &added] {
                let (status, h, body) = send(router.clone(), get(&migration_pck_path(cpu))).await;
                assert_eq!(status, StatusCode::OK);
                assert_eq!(body.as_ref(), migration_pck_with_cpu(0x11).as_bytes());
                assert_eq!(
                    h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
                    "old-M0-chain"
                );
            }
            server.abort();
            continue;
        }
        let next_manifest = if trigger == "same_manifest_post" { "ABCD" } else { "BCDE" };
        let (status, _, body) = send(router.clone(), registration(next_manifest)).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "concurrent M1 registration must succeed: {}",
            String::from_utf8_lossy(&body)
        );
        let rows_m1 = migration_platform_rows(&router).await;
        if ["unknown", "same_manifest_post"].contains(&trigger) {
            assert_eq!(rows_m1, json!([]), "new Manifest registration invents no raw mapping");
        } else {
            assert_eq!(rows_m1.as_array().unwrap().len(), 1);
            assert_eq!(rows_m1[0]["platform_manifest"], "BCDE");
        }
        let (status, _, body) =
            send(router.clone(), get_admin("/sgx/certification/v4/platforms?source=reg")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
            json!([]),
            "successful REQ registration drains NEW"
        );
        release.notify_one();
        let (status, _, body) = pending.await.unwrap();
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "stale {trigger} result must be rejected, not publish M0: {}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(body.as_ref(), b"No cache data for this platform.");
        assert_eq!(
            migration_platform_rows(&router).await,
            rows_m1,
            "M1 credentials and tracked mappings survive stale response"
        );
        let (status, h, body) = send(router.clone(), get(&migration_pck_path(PCK_CPUSVN))).await;
        assert_eq!(status, StatusCode::OK);
        let expected_cert = if trigger == "same_manifest_post" {
            PCK_PEM.to_string()
        } else {
            format!("{PCK_PEM}\n")
        };
        assert_eq!(body.as_ref(), expected_cert.as_bytes());
        assert_eq!(
            h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
            if trigger == "same_manifest_post" { "initial-M0-chain" } else { "new-M1-chain" }
        );
        let (status, _, body) =
            send(router, get_admin("/sgx/certification/v4/platforms?source=reg")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&body).unwrap(), json!([]));
        server.abort();
    }
}

// Intent: regression / invariant. Authenticated Manifest updates stage fetched
// TCB records; document validation or tracked selection failure leaves shared
// TCB bytes, old selections and the old pool unchanged. No GET refill.
#[tokio::test]
async fn migration_failed_registration_does_not_publish_fetched_tcb() {
    let pool = Arc::new(RwLock::new(MigrationPool::default()));
    let (uri, server) = spawn_migration_intel(pool.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    let (status, _, _) = send(
        router.clone(),
        post_user(
            "/sgx/certification/v4/platforms",
            json!({
                "qe_id": "AA", "pce_id": PCK_PCEID, "platform_manifest": "ABCD"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, old_cert) = send(router.clone(), get(&migration_pck_path(PCK_CPUSVN))).await;
    assert_eq!(status, StatusCode::OK);
    let rows = migration_platform_rows(&router).await;
    let tcb_path = format!("/sgx/certification/v4/tcb?fmspc={PCK_FMSPC}");
    let (status, _, old_tcb) = send(router.clone(), get(&tcb_path)).await;
    assert_eq!(status, StatusCode::OK);
    // Request a new Manifest. A bad document fails validation; a valid doc
    // with a cert above the tracked raw TCB fails re-selection before commit.
    for pceid in ["5555", PCK_PCEID] {
        {
            let mut p = pool.write().await;
            p.tcb_pceid = pceid.into();
            p.tcb_signature = "must-not-publish".into();
            p.cert = if pceid == PCK_PCEID {
                migration_pck_with_cpu(0x33)
            } else {
                format!("{PCK_PEM}\n")
            };
        }
        let (status, _, body) = send(
            router.clone(),
            post_user(
                "/sgx/certification/v4/platforms",
                json!({
                    "qe_id": "AA", "pce_id": PCK_PCEID, "platform_manifest": "BCDE"
                }),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body.as_ref(), b"No cache data for this platform.");
        for update in ["standard", "early"] {
            let (status, _, body) =
                send(router.clone(), get(&format!("{tcb_path}&update={update}"))).await;
            assert_eq!(status, StatusCode::OK);
            assert_eq!(body, old_tcb, "failed registration must not publish staged {update} TCB");
        }
        assert_eq!(migration_platform_rows(&router).await, rows);
    }
    pool.write().await.fail = true;
    let unseen = "33".repeat(16);
    for cpu in [PCK_CPUSVN, &unseen] {
        let (status, h, body) = send(router.clone(), get(&migration_pck_path(cpu))).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        assert_eq!(body, old_cert);
        assert_eq!(
            h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
            "migration-pck-chain"
        );
    }
    server.abort();
}

// Intent: regression / invariant, plan invariant 7. Manifest registration with
// unavailable levels invents no raw mapping. A later known-platform GET is
// local selection and MUST track its GET, so cert refresh can update it.
#[tokio::test]
async fn migration_not_available_fill_cannot_leave_stale_untracked_get() {
    let pool = Arc::new(RwLock::new(MigrationPool { not_available: true, ..Default::default() }));
    let (uri, server) = spawn_migration_intel(pool.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    let (status, _, body) = send(
        router.clone(),
        post_user(
            "/sgx/certification/v4/platforms",
            json!({
                "qe_id": "AA", "pce_id": PCK_PCEID, "platform_manifest": "ABCD"
            }),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    assert_eq!(migration_platform_rows(&router).await, json!([]));
    let path = migration_pck_path(PCK_CPUSVN);
    let (status, h, body) = send(router.clone(), get(&path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_ref(), PCK_PEM.as_bytes());
    assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(), "migration-pck-chain");
    assert_eq!(
        migration_platform_rows(&router).await.as_array().unwrap().len(),
        1,
        "local selection tracks the new raw key despite prior unavailable levels"
    );
    let fresh_cert = format!("{PCK_PEM}\n");
    let fresh_tcbm = format!("{}3333", "55".repeat(16));
    {
        let mut p = pool.write().await;
        p.not_available = false;
        p.cert = fresh_cert.clone();
        p.tcbm = fresh_tcbm.clone();
        p.chain = "available-pck-chain".into();
    }
    let refresh = format!("/sgx/certification/v4/refresh?type=certs&fmspc={PCK_FMSPC}");
    let (status, _, body) = send(router.clone(), get_admin(&refresh)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    pool.write().await.fail = true;
    let (status, h, body) = send(router.clone(), get(&path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body.as_ref(),
        fresh_cert.as_bytes(),
        "tracked local GET must update with the refreshed pool"
    );
    assert_eq!(h.get(headers::SGX_TCBM).unwrap(), fresh_tcbm.as_str());
    assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), PCK_FMSPC);
    assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(), "available-pck-chain");
    let rows = migration_platform_rows(&router).await;
    assert_eq!(
        rows.as_array().unwrap().len(),
        1,
        "local selection is tracked for subsequent refreshes"
    );
    assert_eq!(rows[0]["cpu_svn"], PCK_CPUSVN);
    assert_eq!(rows[0]["pce_svn"], PCK_PCESVN);
    server.abort();
}

// Intent: regression / target behavior. Intel refresh probes the v4 identity
// set even when records were absent; a missing identity is tolerated, and v3
// is never fetched. Exact bodies remain cached after the boundary stops serving.
#[tokio::test]
async fn migration_refresh_populates_missing_v4_identities() {
    let fail = Arc::new(AtomicBool::new(false));
    let mut upstream = axum::Router::new();
    for (path, id) in [
        ("/sgx/certification/v4/qe/identity", "QE"),
        ("/sgx/certification/v4/qve/identity", "QVE"),
        ("/tdx/certification/v4/qe/identity", "TD_QE"),
    ] {
        let fail = fail.clone();
        upstream = upstream.route(path, axum::routing::get(move |axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>| {
            let fail = fail.clone();
            async move {
                let update = q.get("update").unwrap();
                if fail.load(Ordering::Relaxed) || (id == "QVE" && update == "early") {
                    return StatusCode::NOT_FOUND.into_response();
                }
                let body = format!("{{\n  \"signature\":\"{update}\",\n  \"enclaveIdentity\":{{\"id\":\"{id}\"}}\n}}\n");
                let mut resp = body.into_response();
                resp.headers_mut().insert(headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN, "refresh-identity-chain".parse().unwrap());
                resp
            }
        }));
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, upstream).await.unwrap() });
    let mut cfg = cfg_empty();
    cfg.uri = format!("http://{addr}/sgx/certification/v4/");
    cfg.cache_mode = CacheMode::Lazy;
    let router = app_cfg(cfg);
    let (status, _, body) = send(router.clone(), get_admin("/sgx/certification/v4/refresh")).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "missing QVE EARLY must not abort refresh: {}",
        String::from_utf8_lossy(&body)
    );
    fail.store(true, Ordering::Relaxed);
    for (path, id) in [
        ("/sgx/certification/v4/qe/identity", "QE"),
        ("/sgx/certification/v4/qve/identity", "QVE"),
        ("/tdx/certification/v4/qe/identity", "TD_QE"),
    ] {
        for update in ["standard", "early"] {
            let (status, h, body) =
                send(router.clone(), get(&format!("{path}?update={update}"))).await;
            if id == "QVE" && update == "early" {
                assert_eq!(status, StatusCode::NOT_FOUND);
                assert_eq!(body.as_ref(), b"No cache data for this platform.");
            } else {
                assert_eq!(
                    status,
                    StatusCode::OK,
                    "{id}/{update}: {}",
                    String::from_utf8_lossy(&body)
                );
                let expected = format!("{{\n  \"signature\":\"{update}\",\n  \"enclaveIdentity\":{{\"id\":\"{id}\"}}\n}}\n");
                assert_eq!(body.as_ref(), expected.as_bytes());
                assert_eq!(
                    h.get(headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN).unwrap(),
                    "refresh-identity-chain"
                );
            }
        }
    }
    let (status, _, _) = send(router, get("/sgx/certification/v3/qe/identity")).await;
    assert_eq!(status, StatusCode::GONE);
    server.abort();
}

// Intent: regression / invariant, plan invariant 8. Production defaults must
// not discover development fixtures; an explicit bad path fails closed, while
// --no-seed overrides even an explicit path.
#[tokio::test]
async fn migration_startup_seeding_is_explicit_and_missing_seed_fails() {
    assert!(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/seed.json").exists(),
        "fixture discovery regression requires the real development fixture to exist"
    );
    let dir = tempfile::tempdir().unwrap();
    let cfg =
        Config { db_path: dir.path().join("default"), uri: String::new(), ..Config::default() };
    assert!(cfg.seed.is_none());
    assert!(!cfg.no_seed);
    let router = app_cfg(cfg);
    let (status, _, body) = send(router, get(TCB)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "normal startup must not implicitly seed fixtures");
    assert_eq!(body.as_ref(), b"No cache data for this platform.");

    let missing = dir.path().join("missing-seed.json");
    let cfg = Config {
        db_path: dir.path().join("missing"),
        uri: String::new(),
        seed: Some(missing.clone()),
        ..Config::default()
    };
    let result = pccs_rs::cache::build_cache(&cfg);
    assert!(result.is_err(), "explicit missing seed must fail, never fall back to fixtures");
    assert!(result.err().unwrap().contains("missing-seed.json"));

    let disabled = Config { db_path: dir.path().join("disabled"), no_seed: true, ..cfg };
    let router = app_cfg(disabled);
    let (status, _, body) = send(router, get(TCB)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body.as_ref(), b"No cache data for this platform.");
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

async fn spawn_amd_kds(calls: Arc<AtomicU64>) -> String {
    let app = axum::Router::new().route(
        "/vcek/v1/Genoa/cert_chain",
        axum::routing::get(move || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                ([("content-type", "application/octet-stream")], "amd-chain")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.ok();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn amd_kds_cert_chain_is_cached_by_its_full_url() {
    let calls = Arc::new(AtomicU64::new(0));
    let upstream = spawn_amd_kds(calls.clone()).await;
    let db_path = std::env::temp_dir().join(format!("pccs-rs-amd-api-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        amd_kds_uri: upstream,
        amd_kds_cache_ttl_secs: 30 * 24 * 60 * 60,
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);

    for _ in 0..2 {
        let (status, headers, body) = send(app.clone(), get("/vcek/v1/Genoa/cert_chain")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "amd-chain");
        assert_eq!(headers.get("content-type").unwrap(), "application/octet-stream");
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn amd_kds_forwards_vcek_vlek_and_crl_paths() {
    let calls = Arc::new(AtomicU64::new(0));
    let mock_calls = calls.clone();
    let upstream_app = axum::Router::new().fallback(move |uri: axum::http::Uri| {
        let calls = mock_calls.clone();
        async move {
            calls.fetch_add(1, Ordering::Relaxed);
            uri.path().to_string()
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });

    let db_path = std::env::temp_dir().join(format!("pccs-rs-amd-prefix-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        amd_kds_uri: format!("http://{addr}/vcek/v1"),
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);

    for path in [
        "/vcek/v1/Genoa/cert_chain",
        "/vcek/v1/Genoa/crl",
        "/vlek/v1/Genoa/cert_chain",
        "/vlek/v1/Milan/abcd",
    ] {
        let (status, _, body) = send(app.clone(), get(path)).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(body, path, "{path}");
    }
    assert_eq!(calls.load(Ordering::Relaxed), 4);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn amd_kds_transport_failure_is_a_bad_gateway() {
    let db_path =
        std::env::temp_dir().join(format!("pccs-rs-amd-transport-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        amd_kds_uri: "http://127.0.0.1:9".into(),
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);

    let (status, _, body) = send(app.clone(), get("/vcek/v1/Genoa/cert_chain")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body, "Unable to retrieve the collateral from the AMD KDS.");

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn concurrent_amd_kds_transport_failures_issue_one_upstream_fetch() {
    let calls = Arc::new(AtomicU64::new(0));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mock_calls = calls.clone();
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            mock_calls.fetch_add(1, Ordering::Relaxed);
            drop(socket);
        }
    });

    let db_path = std::env::temp_dir()
        .join(format!("pccs-rs-amd-failed-concurrent-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        amd_kds_uri: format!("http://{addr}"),
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);
    let path = "/vcek/v1/Genoa/cert_chain";

    let (one, two) = tokio::join!(send(app.clone(), get(path)), send(app.clone(), get(path)));
    assert_eq!(one.0, StatusCode::BAD_GATEWAY);
    assert_eq!(two.0, StatusCode::BAD_GATEWAY);
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn concurrent_amd_kds_misses_issue_one_upstream_fetch() {
    let calls = Arc::new(AtomicU64::new(0));
    let mock_calls = calls.clone();
    let upstream_app = axum::Router::new().route(
        "/vcek/v1/Genoa/cert_chain",
        axum::routing::get(move || {
            let calls = mock_calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                "amd-chain"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });

    let db_path =
        std::env::temp_dir().join(format!("pccs-rs-amd-concurrent-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        amd_kds_uri: format!("http://{addr}"),
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);
    let path = "/vcek/v1/Genoa/cert_chain";

    let (one, two) = tokio::join!(send(app.clone(), get(path)), send(app.clone(), get(path)));
    assert_eq!(one.0, StatusCode::OK);
    assert_eq!(two.0, StatusCode::OK);
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn amd_kds_cache_survives_restart() {
    let calls = Arc::new(AtomicU64::new(0));
    let upstream = spawn_amd_kds(calls.clone()).await;
    let db_path =
        std::env::temp_dir().join(format!("pccs-rs-amd-restart-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        amd_kds_uri: upstream,
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };

    let first = create_app_from_config(cfg.clone());
    let (status, _, _) = send(first.clone(), get("/vcek/v1/Genoa/cert_chain")).await;
    assert_eq!(status, StatusCode::OK);
    drop(first);

    let second = create_app_from_config(cfg);
    let (status, _, body) = send(second.clone(), get("/vcek/v1/Genoa/cert_chain")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "amd-chain");
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    drop(second);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn non_lazy_amd_kds_miss_never_calls_upstream() {
    let calls = Arc::new(AtomicU64::new(0));
    let upstream = spawn_amd_kds(calls.clone()).await;

    for mode in [CacheMode::Req, CacheMode::Offline] {
        let db_path = std::env::temp_dir().join(format!(
            "pccs-rs-amd-no-fill-{}-{}",
            mode.as_str(),
            uuid::Uuid::new_v4()
        ));
        let cfg = Config {
            uri: String::new(),
            amd_kds_uri: upstream.clone(),
            cache_mode: mode,
            db_path: db_path.clone(),
            upstream_max_attempts: 1,
            ..Config::test_default()
        };
        let app = create_app_from_config(cfg);

        let (status, _, _) = send(app.clone(), get("/vcek/v1/Genoa/cert_chain")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{}", mode.as_str());
        drop(app);
        let _ = std::fs::remove_dir_all(db_path);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn amd_kds_error_response_is_relayed_and_not_cached() {
    let calls = Arc::new(AtomicU64::new(0));
    let mock_calls = calls.clone();
    let upstream_app = axum::Router::new().route(
        "/vcek/v1/Genoa/cert_chain",
        axum::routing::get(move || {
            let calls = mock_calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "10")], "slow down")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });

    let db_path = std::env::temp_dir().join(format!("pccs-rs-amd-error-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        amd_kds_uri: format!("http://{addr}"),
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);

    for _ in 0..2 {
        let (status, headers, body) = send(app.clone(), get("/vcek/v1/Genoa/cert_chain")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(headers.get("retry-after").unwrap(), "10");
        assert_eq!(body, "slow down");
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn amd_kds_ttl_starts_after_the_upstream_response() {
    let calls = Arc::new(AtomicU64::new(0));
    let mock_calls = calls.clone();
    let upstream_app = axum::Router::new().route(
        "/vcek/v1/Genoa/cert_chain",
        axum::routing::get(move || {
            let calls = mock_calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
                "amd-chain"
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });

    let db_path =
        std::env::temp_dir().join(format!("pccs-rs-amd-ttl-start-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        amd_kds_uri: format!("http://{addr}"),
        amd_kds_cache_ttl_secs: 1,
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);

    for _ in 0..2 {
        let (status, _, _) = send(app.clone(), get("/vcek/v1/Genoa/cert_chain")).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn expired_amd_kds_entry_is_refetched() {
    let calls = Arc::new(AtomicU64::new(0));
    let upstream = spawn_amd_kds(calls.clone()).await;
    let db_path =
        std::env::temp_dir().join(format!("pccs-rs-amd-expired-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        amd_kds_uri: upstream,
        amd_kds_cache_ttl_secs: 0,
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);

    for _ in 0..2 {
        let (status, _, _) = send(app.clone(), get("/vcek/v1/Genoa/cert_chain")).await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn amd_vcek_cache_key_includes_the_complete_query() {
    let calls = Arc::new(AtomicU64::new(0));
    let mock_calls = calls.clone();
    let upstream_app = axum::Router::new().route(
        "/vcek/v1/Genoa/{hwid}",
        axum::routing::get(move |uri: axum::http::Uri| {
            let calls = mock_calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                uri.query().unwrap_or_default().to_string()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });

    let db_path = std::env::temp_dir().join(format!("pccs-rs-amd-vcek-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        amd_kds_uri: format!("http://{addr}"),
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);
    let hwid = "ab".repeat(64);
    let one = format!("/vcek/v1/Genoa/{hwid}?blSPL=1&teeSPL=2&snpSPL=3&ucodeSPL=4");
    let two = format!("/vcek/v1/Genoa/{hwid}?blSPL=1&teeSPL=2&snpSPL=3&ucodeSPL=5");

    let (_, _, body_one) = send(app.clone(), get(&one)).await;
    let (_, _, body_two) = send(app.clone(), get(&two)).await;
    let (_, _, body_one_cached) = send(app.clone(), get(&one)).await;
    assert_eq!(body_one, "blSPL=1&snpSPL=3&teeSPL=2&ucodeSPL=4");
    assert_eq!(body_two, "blSPL=1&snpSPL=3&teeSPL=2&ucodeSPL=5");
    assert_eq!(body_one_cached, body_one);
    assert_eq!(calls.load(Ordering::Relaxed), 2);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn nvidia_rim_is_cached_by_its_full_url() {
    let calls = Arc::new(AtomicU64::new(0));
    let mock_calls = calls.clone();
    let upstream_app = axum::Router::new().route(
        "/v1/rim/{id}",
        axum::routing::get(move |uri: axum::http::Uri| {
            let calls = mock_calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                ([("content-type", "application/json")], format!("rim {}", uri.path()))
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });

    let db_path = std::env::temp_dir().join(format!("pccs-rs-nvidia-rim-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        nvidia_rim_uri: format!("http://{addr}/v1/rim"),
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);

    for _ in 0..2 {
        let (status, headers, body) = send(app.clone(), get("/v1/rim/some-id")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "rim /v1/rim/some-id");
        assert_eq!(headers.get("content-type").unwrap(), "application/json");
    }
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn nvidia_rim_transport_failure_is_a_bad_gateway() {
    let db_path =
        std::env::temp_dir().join(format!("pccs-rs-nvidia-transport-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        nvidia_rim_uri: "http://127.0.0.1:9".into(),
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);

    let (status, _, body) = send(app.clone(), get("/v1/rim/some-id")).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body, "Unable to retrieve the collateral from the NVIDIA RIM service.");

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn non_lazy_nvidia_rim_miss_never_calls_upstream() {
    let calls = Arc::new(AtomicU64::new(0));
    let mock_calls = calls.clone();
    let upstream_app = axum::Router::new().fallback(move || {
        let calls = mock_calls.clone();
        async move {
            calls.fetch_add(1, Ordering::Relaxed);
            "rim"
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });

    for mode in [CacheMode::Req, CacheMode::Offline] {
        let db_path = std::env::temp_dir().join(format!(
            "pccs-rs-nvidia-no-fill-{}-{}",
            mode.as_str(),
            uuid::Uuid::new_v4()
        ));
        let cfg = Config {
            uri: String::new(),
            nvidia_rim_uri: format!("http://{addr}"),
            cache_mode: mode,
            db_path: db_path.clone(),
            upstream_max_attempts: 1,
            ..Config::test_default()
        };
        let app = create_app_from_config(cfg);
        let (status, _, _) = send(app.clone(), get("/v1/rim/some-id")).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{}", mode.as_str());
        drop(app);
        let _ = std::fs::remove_dir_all(db_path);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn nvidia_rim_error_response_is_relayed_and_not_cached() {
    let calls = Arc::new(AtomicU64::new(0));
    let mock_calls = calls.clone();
    let upstream_app = axum::Router::new().route(
        "/v1/rim/some-id",
        axum::routing::get(move || {
            let calls = mock_calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                (StatusCode::TOO_MANY_REQUESTS, [("retry-after", "10")], "slow down")
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });

    let db_path =
        std::env::temp_dir().join(format!("pccs-rs-nvidia-error-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        nvidia_rim_uri: format!("http://{addr}"),
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);

    for _ in 0..2 {
        let (status, headers, body) = send(app.clone(), get("/v1/rim/some-id")).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(headers.get("retry-after").unwrap(), "10");
        assert_eq!(body, "slow down");
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}


struct UpstreamHit {
    path: String,
    api_key: String,
}

async fn spawn_recording_upstream(
    status: StatusCode,
    extra_headers: &'static [(&'static str, &'static str)],
    body: &'static str,
) -> (String, Arc<Mutex<Vec<UpstreamHit>>>) {
    let seen: Arc<Mutex<Vec<UpstreamHit>>> = Arc::new(Mutex::new(Vec::new()));
    let seen2 = seen.clone();
    let upstream_app =
        axum::Router::new().fallback(move |req: axum::http::Request<axum::body::Body>| {
            let seen = seen2.clone();
            async move {
                let api_key = req
                    .headers()
                    .get("ocp-apim-subscription-key")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let path = req
                    .uri()
                    .path_and_query()
                    .map(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                seen.lock().unwrap().push(UpstreamHit { path, api_key });
                let mut builder = axum::http::Response::builder().status(status);
                for (name, value) in extra_headers {
                    builder = builder.header(*name, *value);
                }
                builder.body(axum::body::Body::from(body)).unwrap()
            }
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });
    (format!("http://{addr}"), seen)
}

fn amd_cfg(upstream: String, db_name: &str) -> (Config, std::path::PathBuf) {
    let db_path = std::env::temp_dir().join(format!("{db_name}-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        amd_kds_uri: upstream,
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    (cfg, db_path)
}

#[tokio::test]
async fn amd_kds_does_not_forward_the_intel_api_key() {
    let (upstream, seen) = spawn_recording_upstream(StatusCode::OK, &[], "ok").await;
    let (mut cfg, db_path) = amd_cfg(upstream, "pccs-rs-amd-no-key");
    cfg.api_key = "secret-key".into();
    let app = create_app_from_config(cfg);

    let (status, _, _) = send(app.clone(), get("/vcek/v1/x/pckcerts")).await;
    assert_eq!(status, StatusCode::OK);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, "/vcek/v1/x/pckcerts");
    assert_eq!(seen[0].api_key, "");

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

fn nras_post(body: impl Into<Body>) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/nvidia/nras/attest/gpu")
        .header("content-type", "application/json")
        .body(body.into())
        .unwrap()
}

fn assert_nras_cors(headers: &axum::http::HeaderMap) {
    assert_eq!(headers.get("access-control-allow-origin").unwrap(), "*");
    let methods = headers.get("access-control-allow-methods").unwrap().to_str().unwrap();
    assert!(methods.contains("POST"), "{methods}");
    assert!(methods.contains("OPTIONS"), "{methods}");
    assert_eq!(headers.get("access-control-allow-headers").unwrap(), "Content-Type");
    assert_eq!(headers.get("access-control-expose-headers").unwrap(), "Retry-After");
    assert_eq!(headers.get("cache-control").unwrap(), "no-store");
}

async fn spawn_nras(
    calls: Arc<AtomicU64>,
    status: StatusCode,
    retry_after: Option<&'static str>,
) -> String {
    let mock_calls = calls.clone();
    let upstream_app = axum::Router::new().route(
        "/v3/attest/gpu",
        axum::routing::post(move |body: bytes::Bytes| {
            let calls = mock_calls.clone();
            async move {
                calls.fetch_add(1, Ordering::Relaxed);
                let mut headers = axum::http::HeaderMap::new();
                headers.insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
                if let Some(retry) = retry_after {
                    headers.insert(
                        axum::http::header::RETRY_AFTER,
                        axum::http::HeaderValue::from_static(retry),
                    );
                }
                (status, headers, body)
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, upstream_app).await.ok();
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn nvidia_nras_proxies_json_and_is_not_cached() {
    let calls = Arc::new(AtomicU64::new(0));
    let upstream = spawn_nras(calls.clone(), StatusCode::OK, None).await;
    let db_path = std::env::temp_dir().join(format!("pccs-rs-nras-proxy-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        nvidia_nras_uri: upstream,
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);
    let payload = json!({"nonce":"aa","evidence_list":[]});

    for _ in 0..2 {
        let (status, headers, body) = send(app.clone(), nras_post(payload.to_string())).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, payload.to_string().as_bytes());
        assert_eq!(headers.get("content-type").unwrap(), "application/json");
        assert_nras_cors(&headers);
    }
    assert_eq!(calls.load(Ordering::Relaxed), 2, "must not persist NRAS results");

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn nvidia_nras_options_preflight_is_cors() {
    let mut ids = Vec::new();
    for _ in 0..2 {
        let req = Request::builder()
            .method("OPTIONS")
            .uri("/nvidia/nras/attest/gpu")
            .header(headers::REQUEST_ID, "client-supplied-id")
            .body(Body::empty())
            .unwrap();
        let (status, h, _) = send(app(), req).await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_nras_cors(&h);
        let id = h.get(headers::REQUEST_ID).unwrap().to_str().unwrap().to_string();
        assert_ne!(id, "client-supplied-id");
        assert!(!id.is_empty());
        ids.push(id);
    }
    assert_ne!(ids[0], ids[1], "each preflight gets a fresh Request-ID");
}

#[tokio::test]
async fn nvidia_nras_prefix_does_not_match_nras_extra() {
    let req =
        Request::builder().method("OPTIONS").uri("/nvidia/nras-extra").body(Body::empty()).unwrap();
    let (status, headers, _) = send(app(), req).await;
    assert_ne!(status, StatusCode::NO_CONTENT);
    assert!(headers.get("access-control-allow-origin").is_none());
}

#[tokio::test]
async fn nvidia_nras_extractor_errors_have_cors() {
    let malformed = Request::builder()
        .method("POST")
        .uri("/nvidia/nras/attest/gpu")
        .header("content-type", "application/json")
        .body(Body::from("{not json"))
        .unwrap();
    let (status, headers, _) = send(app(), malformed).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_nras_cors(&headers);

    let wrong_type = Request::builder()
        .method("POST")
        .uri("/nvidia/nras/attest/gpu")
        .header("content-type", "text/plain")
        .body(Body::from("x"))
        .unwrap();
    let (status, headers, _) = send(app(), wrong_type).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_nras_cors(&headers);
}

#[tokio::test]
async fn nvidia_nras_forwards_retry_after() {
    let calls = Arc::new(AtomicU64::new(0));
    let upstream = spawn_nras(calls.clone(), StatusCode::TOO_MANY_REQUESTS, Some("11")).await;
    let db_path = std::env::temp_dir().join(format!("pccs-rs-nras-429-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        nvidia_nras_uri: upstream,
        db_path: db_path.clone(),
        upstream_max_attempts: 6,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);
    let (status, headers, body) = send(app.clone(), nras_post(json!({}).to_string())).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(headers.get("retry-after").unwrap(), "11");
    assert_eq!(body, "{}");
    assert_nras_cors(&headers);
    assert_eq!(calls.load(Ordering::Relaxed), 1, "NRAS must not inherit Intel 429 retries");

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn nvidia_nras_does_not_retry_upstream_503() {
    let calls = Arc::new(AtomicU64::new(0));
    let upstream = spawn_nras(calls.clone(), StatusCode::SERVICE_UNAVAILABLE, Some("2")).await;
    let db_path = std::env::temp_dir().join(format!("pccs-rs-nras-503-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        nvidia_nras_uri: upstream,
        db_path: db_path.clone(),
        upstream_max_attempts: 6,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);
    let (status, headers, _) = send(app.clone(), nras_post(json!({}).to_string())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(headers.get("retry-after").unwrap(), "2");
    assert_nras_cors(&headers);
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn nvidia_nras_transport_failure_is_a_bad_gateway_with_cors() {
    let db_path =
        std::env::temp_dir().join(format!("pccs-rs-nras-transport-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        nvidia_nras_uri: "http://127.0.0.1:9".into(),
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);
    let (status, headers, body) = send(app.clone(), nras_post(json!({}).to_string())).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(body, "Unable to retrieve the attestation result from the NVIDIA NRAS.");
    assert_nras_cors(&headers);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn nvidia_nras_offline_never_calls_upstream() {
    let calls = Arc::new(AtomicU64::new(0));
    let upstream = spawn_nras(calls.clone(), StatusCode::OK, None).await;
    let db_path =
        std::env::temp_dir().join(format!("pccs-rs-nras-offline-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        nvidia_nras_uri: upstream,
        cache_mode: CacheMode::Offline,
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);
    let (status, headers, _) = send(app.clone(), nras_post(json!({}).to_string())).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_nras_cors(&headers);
    assert_eq!(calls.load(Ordering::Relaxed), 0);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn nvidia_nras_req_mode_still_proxies() {
    let calls = Arc::new(AtomicU64::new(0));
    let upstream = spawn_nras(calls.clone(), StatusCode::OK, None).await;
    let db_path = std::env::temp_dir().join(format!("pccs-rs-nras-req-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        nvidia_nras_uri: upstream,
        cache_mode: CacheMode::Req,
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);
    let (status, _, _) = send(app.clone(), nras_post(json!({}).to_string())).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(calls.load(Ordering::Relaxed), 1);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn amd_kds_unknown_query_is_rejected_and_known_params_are_canonicalised() {
    let (upstream, seen) = spawn_recording_upstream(StatusCode::OK, &[], "ok").await;
    let (cfg, db_path) = amd_cfg(upstream, "pccs-rs-amd-canon");
    let app = create_app_from_config(cfg);
    let hwid = "ab".repeat(64);

    let (status, _, body) = send(
        app.clone(),
        get(&format!("/vcek/v1/Genoa/cert_chain?junk=1")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "Invalid request parameters.");
    assert!(seen.lock().unwrap().is_empty());

    let one = format!("/vcek/v1/Genoa/{hwid}?teeSPL=2&blSPL=1");
    let two = format!("/vcek/v1/Genoa/{hwid}?blSPL=1&teeSPL=2");
    let (status, _, _) = send(app.clone(), get(&one)).await;
    assert_eq!(status, StatusCode::OK);
    let (status, _, _) = send(app.clone(), get(&two)).await;
    assert_eq!(status, StatusCode::OK);
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        seen[0].path,
        format!("/vcek/v1/Genoa/{hwid}?blSPL=1&teeSPL=2")
    );

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn amd_kds_dot_segments_are_rejected_without_touching_upstream() {
    let (upstream, seen) = spawn_recording_upstream(StatusCode::OK, &[], "ok").await;
    let (cfg, db_path) = amd_cfg(upstream, "pccs-rs-amd-dots");
    let app = create_app_from_config(cfg);

    let req = Request::builder()
        .method("GET")
        .uri("/vcek/v1/../../x")
        .body(Body::empty())
        .unwrap();
    let (status, _, body) = send(app.clone(), req).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "Invalid request parameters.");
    assert!(seen.lock().unwrap().is_empty());

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn amd_kds_v3_path_is_rejected_without_touching_upstream() {
    let (upstream, seen) = spawn_recording_upstream(StatusCode::OK, &[], "ok").await;
    let (cfg, db_path) = amd_cfg(upstream, "pccs-rs-amd-v3");
    let app = create_app_from_config(cfg);

    let (status, _, body) = send(app.clone(), get("/vcek/v3/Genoa/cert_chain")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, "Invalid request parameters.");
    assert!(seen.lock().unwrap().is_empty());

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

#[tokio::test]
async fn nvidia_rim_accepts_dotted_driver_ids() {
    let (upstream, seen) = spawn_recording_upstream(StatusCode::OK, &[], "ok").await;
    let db_path =
        std::env::temp_dir().join(format!("pccs-rs-nvidia-dotted-{}", uuid::Uuid::new_v4()));
    let cfg = Config {
        uri: String::new(),
        nvidia_rim_uri: upstream,
        db_path: db_path.clone(),
        upstream_max_attempts: 1,
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);
    let path = "/v1/rim/NV_GPU_DRIVER_GH100_535.129.03";

    for _ in 0..2 {
        let (status, _, body) = send(app.clone(), get(path)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "ok");
    }
    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].path, path);

    drop(app);
    let _ = std::fs::remove_dir_all(db_path);
}

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
        ("GET", "/vcek/v1/Genoa/cert_chain"),
        ("GET", "/vcek/v1/Genoa/crl"),
        ("GET", "/vlek/v1/Genoa/cert_chain"),
        ("GET", "/v1/rim/some-id"),
        ("POST", "/nvidia/nras/attest/gpu"),
    ];

    for (method, path) in routes {
        let req = Request::builder()
            .method(*method)
            .uri(*path)
            .header(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)
            .header(headers::USER_TOKEN, DEFAULT_USER_TOKEN)
            .header("content-type", "application/json")
            .body(if *method == "GET" { Body::empty() } else { Body::from("{}") })
            .unwrap();
        let (status, _, _) = send(app(), req).await;
        assert_ne!(
            status,
            StatusCode::NOT_FOUND,
            "{method} {path} should be registered, got {status}"
        );
        assert_ne!(status, StatusCode::METHOD_NOT_ALLOWED, "{method} {path} method not allowed");
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
    let id = headers.get(headers::REQUEST_ID).unwrap().to_str().unwrap().to_string();
    assert_ne!(id, "abc123clientid");
    assert_eq!(id.len(), 32, "uuid without dashes");
    assert!(id.chars().all(|c| c.is_ascii_hexdigit()));

    let (_, headers2, _) = send(app(), get("/no/such/route")).await;
    assert_ne!(headers2.get(headers::REQUEST_ID).unwrap().to_str().unwrap(), id);
}

#[tokio::test]
async fn admin_auth_missing_and_wrong_are_401() {
    for path in ["/sgx/certification/v4/platforms", "/sgx/certification/v4/refresh"] {
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

    let (status, _, body) =
        send(router.clone(), get_admin("/sgx/certification/v4/platforms?source=reg")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body.as_ref(), b"Authentication failed.");

    let (status, _, _) =
        send(router, post_user("/sgx/certification/v4/platforms", json!({}))).await;
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
    assert_eq!(h.get(axum::http::header::CONTENT_TYPE).unwrap(), "text/html; charset=utf-8");

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
    assert_eq!(status, StatusCode::OK, "pckcert {}", String::from_utf8_lossy(&body));
    assert!(h.get(headers::SGX_TCBM).is_some());
    assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), "ABCDABCDABCD");
    // The seed says "processor" in lowercase; every writer normalises the CA
    // type, so the served header must be the uppercase PROCESSOR / PLATFORM
    // that Intel's clients expect.
    assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).unwrap(), "PROCESSOR");
    assert!(h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).is_some());
    assert_eq!(h.get(axum::http::header::CONTENT_TYPE).unwrap(), headers::CONTENT_TYPE_PEM);
    assert!(h.get(headers::REQUEST_ID).is_some());
    assert!(body.windows(b"BEGIN CERTIFICATE".len()).any(|w| w == b"BEGIN CERTIFICATE"));
    assert!(h.get("x-powered-by").is_none());

    // tcb
    let (status, h, body) = send(app(), get(TCB)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::TCB_INFO_ISSUER_CHAIN).is_some());
    assert_eq!(h.get(axum::http::header::CONTENT_TYPE).unwrap(), headers::CONTENT_TYPE_JSON);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v.get("tcbInfo").is_some());

    // qe identity
    let (status, h, body) = send(app(), get(QE)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::SGX_ENCLAVE_IDENTITY_ISSUER_CHAIN).is_some());
    assert_eq!(h.get(axum::http::header::CONTENT_TYPE).unwrap(), headers::CONTENT_TYPE_JSON);
    let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(v.get("enclaveIdentity").is_some());

    // pckcrl
    let (status, h, _) = send(app(), get(PCKCRL)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(h.get(headers::SGX_PCK_CRL_ISSUER_CHAIN).is_some());
    assert_eq!(h.get(axum::http::header::CONTENT_TYPE).unwrap(), headers::CONTENT_TYPE_PEM);

    // pckcrl DER
    let (status, h, _) =
        send(app(), get("/sgx/certification/v4/pckcrl?ca=platform&encoding=DER")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.get(axum::http::header::CONTENT_TYPE).unwrap(), headers::CONTENT_TYPE_CRL);
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

    let (status, _, body_txt) =
        send(router.clone(), put_admin("/sgx/certification/v4/platformcollateral", body)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body_txt));
    assert_eq!(body_txt.as_ref(), b"Operation successful.");

    let path = format!(
        "/sgx/certification/v4/pckcert?qeid={qeid}&cpusvn={PCK_CPUSVN}&pcesvn={PCK_PCESVN}&pceid={PCK_PCEID}"
    );
    let (status, h, cert) = send(router.clone(), get(&path)).await;
    assert_eq!(status, StatusCode::OK);
    // fmspc and CA come from the certificate, as in Node.
    assert_eq!(h.get(headers::SGX_FMSPC).unwrap(), PCK_FMSPC);
    assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).unwrap(), "PLATFORM");
    assert_eq!(
        h.get(headers::SGX_PCK_CERTIFICATE_ISSUER_CHAIN).unwrap(),
        "put-collateral-issuer-chain"
    );
    assert_eq!(h.get(headers::SGX_TCBM).unwrap(), format!("{PCK_CPUSVN}{PCK_PCESVN}").as_str());
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
    assert_eq!(h.get(headers::SGX_TCBM).unwrap(), format!("{PCK_CPUSVN}{PCK_PCESVN}").as_str());

    // GET /platforms?source=[fmspc] returns only Node's six columns.
    let (status, h, body) = send(
        router,
        get_admin(&format!("/sgx/certification/v4/platforms?source=%5B{PCK_FMSPC}%5D")),
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
        vec!["cpu_svn", "enc_ppid", "pce_id", "pce_svn", "platform_manifest", "qe_id"]
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
    let (status, _, txt) =
        send(router.clone(), put_admin("/sgx/certification/v4/platformcollateral", body)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&txt));

    let (status, h, got) =
        send(router, get(&format!("/sgx/certification/v4/tcb?fmspc={PCK_FMSPC}"))).await;
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
    c["collaterals"].as_object_mut().unwrap().remove("certificates");
    cases.push(("certificates missing", c));
    cases.push(("platforms not an array", json!({ "platforms": {}, "collaterals": {} })));

    for (what, body) in cases {
        let (status, _, txt) =
            send(app(), put_admin("/sgx/certification/v4/platformcollateral", body)).await;
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
    let (status, _, txt) =
        send(router.clone(), post_user("/sgx/certification/v4/platforms", body)).await;
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
        let (status, _, txt) =
            send(router.clone(), post_user("/sgx/certification/v4/platforms", body)).await;
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
    assert_eq!(h.get(axum::http::header::CONTENT_TYPE).unwrap(), headers::CONTENT_TYPE_CRL);

    let (status, h, _) = send(
        app(),
        get("/sgx/certification/v4/crl?uri=https://certificates.trustedservices.intel.com/IntelSGXRootCA.crl"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.get(axum::http::header::CONTENT_TYPE).unwrap(), headers::CONTENT_TYPE_CRL);
}

#[tokio::test]
async fn appraisal_policy_put_get() {
    let router = app();
    let (status, _, body) =
        send(router.clone(), get("/sgx/certification/v4/appraisalpolicy?fmspc=ABCDABCDABCD")).await;
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

    let (status, _, body) =
        send(router.clone(), get("/sgx/certification/v4/appraisalpolicy?fmspc=AAAAAAAAAAAA")).await;
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
    let (status, _, body) =
        send(router.clone(), get("/sgx/certification/v4/appraisalpolicy?fmspc=AAAAAAAAAAAA")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(String::from_utf8_lossy(&body), policy2, "only the newest default is returned");

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
    let (_, _, body) =
        send(router.clone(), get("/sgx/certification/v4/appraisalpolicy?fmspc=AAAAAAAAAAAA")).await;
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
        let (status, _, txt) =
            send(router.clone(), put_admin("/sgx/certification/v4/appraisalpolicy", bad)).await;
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
    let (status, h, _) =
        send(app(), get_admin("/sgx/certification/v4/platforms?source=%5BABCDABCDABCD%5D")).await;
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
    assert_eq!(calls.load(Ordering::Relaxed), 1, "second GET must be RocksDB hit");
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
    assert_eq!(calls.load(Ordering::Relaxed), 1, "second GET must be RocksDB hit");
}

#[tokio::test]
async fn offline_miss_is_404_no_upstream() {
    let sig = Arc::new(RwLock::new("x".into()));
    let calls = Arc::new(AtomicU64::new(0));
    let (uri, _h) = spawn_mock(sig, calls.clone()).await;
    let mut cfg = cfg_empty();
    cfg.uri = uri;
    cfg.cache_mode = CacheMode::Offline;
    let (status, _, body) =
        send(app_cfg(cfg), get("/sgx/certification/v4/tcb?fmspc=00A067110000")).await;
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
    let (status, _, txt) =
        send(router.clone(), put_admin("/sgx/certification/v4/platformcollateral", body)).await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&txt));

    let (status, h, body) =
        send(router.clone(), get(&format!("/sgx/certification/v4/tcb?fmspc={PCK_FMSPC}"))).await;
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
        let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
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
        .args(["--url", &url, "--duration", "1", "--concurrency", "2", "--warmup", "1"])
        .output()
        .expect("run loadgen");
    assert!(out.status.success(), "loadgen failed: {}", String::from_utf8_lossy(&out.stderr));
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
    let (status, _, body) =
        send(router.clone(), get("/sgx/certification/v4/tcb?fmspc=00A067110000")).await;
    assert_eq!(status, StatusCode::OK, "live tcb {}", String::from_utf8_lossy(&body));
    let (status, _, body) = send(router, get("/sgx/certification/v4/qe/identity")).await;
    assert_eq!(status, StatusCode::OK, "live qe {}", String::from_utf8_lossy(&body));
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
            .body(if *method == "GET" { Body::empty() } else { Body::from("{}") })
            .unwrap();
        let (status, _, body) = send(router.clone(), req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} {path} without token must be 401");
        assert_eq!(body.as_ref(), b"Authentication failed.");

        // Normal path WITH valid auth: must NOT be 401 or 404 (auth passed, handler ran)
        let req = Request::builder()
            .method(*method)
            .uri(*path)
            .header(headers::ADMIN_TOKEN, DEFAULT_ADMIN_TOKEN)
            .header("content-type", "application/json")
            .body(if *method == "GET" { Body::empty() } else { Body::from("{}") })
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
            .body(if *method == "GET" { Body::empty() } else { Body::from("{}") })
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
            .body(if *method == "GET" { Body::empty() } else { Body::from("{}") })
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
    assert_eq!(status, StatusCode::NOT_FOUND, "double-slash POST must be 404");
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
    let (status, _, _) =
        send(router.clone(), get("/sgx/certification/v4/tcb?fmspc=00A067110000")).await;
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
    assert_eq!(body.as_ref(), b"Server is currently unable to process the request.");

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

    let (status, _, body) =
        send(router.clone(), get_admin("/sgx/certification/v4/refresh?type=certs&fmspc=nothex"))
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
    let (status, _, _) =
        send(app(), get("/sgx/certification/v4/tcb?fmspc=ABCDABCDABCD&fmspc=nothex")).await;
    assert_eq!(status, StatusCode::OK);

    // ...and junk first is a 400 even when a valid value follows
    let (status, _, _) =
        send(app(), get("/sgx/certification/v4/tcb?fmspc=nothex&fmspc=ABCDABCDABCD")).await;
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
    assert_eq!(h.get(headers::SGX_PCK_CERTIFICATE_CA_TYPE).unwrap(), "PROCESSOR");
    assert_eq!(h.get(headers::SGX_TCBM).unwrap(), "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBCCCC");
    assert!(String::from_utf8_lossy(&body).contains("BEGIN CERTIFICATE"));
    let pck_calls = calls.load(Ordering::Relaxed);

    let (status, _, _) = send(router, get(&path)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(calls.load(Ordering::Relaxed), pck_calls, "second GET is a store hit");
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
        .body(Body::new(StalledBody(Some(bytes::Bytes::from_static(b"{\"qe_id\":")))))
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

#[tokio::test]
async fn nvidia_nras_stalled_body_is_408_with_cors() {
    let mut cfg = Config::test_default();
    cfg.request_timeout_secs = 1;
    let router = app_cfg(cfg);
    let req = Request::builder()
        .method("POST")
        .uri("/nvidia/nras/attest/gpu")
        .header("content-type", "application/json")
        .body(Body::new(StalledBody(Some(bytes::Bytes::from_static(b"{")))))
        .unwrap();
    let (status, headers, _) = send(router, req).await;
    assert_eq!(status, StatusCode::REQUEST_TIMEOUT);
    assert_nras_cors(&headers);
}

#[tokio::test]
async fn nvidia_nras_oversize_body_is_413_with_cors() {
    let mut cfg = Config::test_default();
    cfg.max_body_size = 64;
    let router = app_cfg(cfg);
    let req = Request::builder()
        .method("POST")
        .uri("/nvidia/nras/attest/gpu")
        .header("content-type", "application/json")
        .body(Body::from(format!("{{\"x\":\"{}\"}}", "a".repeat(256))))
        .unwrap();
    let (status, headers, body) = send(router, req).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body.as_ref(), b"Content too large.");
    assert_nras_cors(&headers);
}
