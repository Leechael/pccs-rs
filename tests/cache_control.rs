//! Opt-in `Cache-Control` for Intel collateral (`collateral_cache_max_age_secs`).

use axum::{
    body::Body,
    http::{HeaderMap, Method, Request, StatusCode},
    routing::get,
    Router,
};
use pccs_rs::config::{CacheMode, Config};
use pccs_rs::{create_app_from_config, routes};
use tower::ServiceExt;

const MAX_AGE: u64 = 900;

/// Covered routes with a query the seed fixture answers with 200.
const COVERED_OK: &[&str] = &[
    "/sgx/certification/v4/tcb?fmspc=ABCDABCDABCD",
    "/tdx/certification/v4/tcb?fmspc=ABCDABCDABCD",
    "/sgx/certification/v4/qe/identity",
    "/sgx/certification/v4/qve/identity",
    "/tdx/certification/v4/qe/identity",
    "/sgx/certification/v4/pckcrl?ca=processor",
    "/sgx/certification/v4/rootcacrl",
];

/// Covered routes with a query that must fail validation (400).
const COVERED_BAD_QUERY: &[&str] = &[
    "/sgx/certification/v4/tcb?fmspc=zz",
    "/tdx/certification/v4/tcb?fmspc=zz",
    "/sgx/certification/v4/qe/identity?update=bogus",
    "/sgx/certification/v4/qve/identity?update=bogus",
    "/tdx/certification/v4/qe/identity?update=bogus",
    "/sgx/certification/v4/pckcrl?ca=bogus",
];

fn config(max_age: Option<u64>) -> Config {
    Config { collateral_cache_max_age_secs: max_age, ..Config::test_default() }
}

async fn call(app: &Router, method: Method, path: &str) -> (StatusCode, HeaderMap) {
    let req = Request::builder().method(method).uri(path).body(Body::empty()).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    (resp.status(), resp.headers().clone())
}

fn cache_control(headers: &HeaderMap) -> Vec<&str> {
    headers.get_all("cache-control").iter().map(|v| v.to_str().unwrap()).collect()
}

#[tokio::test]
async fn covered_routes_200_get_public_max_age_for_get_and_head() {
    let app = create_app_from_config(config(Some(MAX_AGE)));
    for path in COVERED_OK {
        for method in [Method::GET, Method::HEAD] {
            let (status, headers) = call(&app, method.clone(), path).await;
            assert_eq!(status, StatusCode::OK, "{method} {path}");
            assert_eq!(cache_control(&headers), ["public, max-age=900"], "{method} {path}");
        }
    }
}

#[tokio::test]
async fn unset_adds_no_cache_control_anywhere() {
    let app = create_app_from_config(config(None));
    for path in COVERED_OK.iter().chain(COVERED_BAD_QUERY) {
        let (_, headers) = call(&app, Method::GET, path).await;
        assert!(cache_control(&headers).is_empty(), "{path}");
    }
}

#[tokio::test]
async fn covered_routes_non_200_get_no_store() {
    let app = create_app_from_config(config(Some(MAX_AGE)));
    for path in COVERED_BAD_QUERY {
        let (status, headers) = call(&app, Method::GET, path).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert_eq!(cache_control(&headers), ["no-store"], "{path}");
    }
}

#[tokio::test]
async fn covered_routes_missing_collateral_get_no_store() {
    // OFFLINE with an empty store: every covered route misses (404).
    let cfg = Config {
        cache_mode: CacheMode::Offline,
        no_seed: true,
        collateral_cache_max_age_secs: Some(MAX_AGE),
        ..Config::test_default()
    };
    let app = create_app_from_config(cfg);
    for path in COVERED_OK {
        for method in [Method::GET, Method::HEAD] {
            let (status, headers) = call(&app, method.clone(), path).await;
            assert_ne!(status, StatusCode::OK, "{method} {path}");
            assert_eq!(cache_control(&headers), ["no-store"], "{method} {path} -> {status}");
        }
    }
    let (status, _) = call(&app, Method::GET, "/sgx/certification/v4/rootcacrl").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn v3_aliases_are_covered() {
    let app = create_app_from_config(config(Some(MAX_AGE)));
    for path in [
        "/sgx/certification/v3/tcb?fmspc=zz",
        "/sgx/certification/v3/qe/identity?update=bogus",
        "/sgx/certification/v3/qve/identity?update=bogus",
        "/sgx/certification/v3/pckcrl?ca=bogus",
    ] {
        let (status, headers) = call(&app, Method::GET, path).await;
        assert_ne!(status, StatusCode::OK, "{path}");
        assert_eq!(cache_control(&headers), ["no-store"], "{path}");
    }
    let (status, headers) = call(&app, Method::GET, "/sgx/certification/v3/rootcacrl").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache_control(&headers), ["public, max-age=900"]);
}

#[tokio::test]
async fn uncovered_routes_never_get_cache_control() {
    let app = create_app_from_config(config(Some(MAX_AGE)));
    for path in [
        "/sgx/certification/v4/pckcert?qeid=00&cpusvn=00&pcesvn=0000&pceid=0000",
        "/sgx/certification/v4/crl?uri=x",
        "/sgx/certification/v4/appraisalpolicy?fmspc=ABCDABCDABCD",
        "/sgx/certification/v4/platforms",
        "/vcek/v1/Milan/0123456789abcdef?blSPL=1",
        "/vlek/v1/Milan/0123456789abcdef",
        "/v1/rim/x",
        "/healthz/live",
        "/healthz/ready",
        "/nonexistent",
    ] {
        let (_, headers) = call(&app, Method::GET, path).await;
        assert!(cache_control(&headers).is_empty(), "{path}: {:?}", cache_control(&headers));
    }
    let req = Request::builder()
        .method(Method::POST)
        .uri("/nvidia/nras/attest/gpu")
        .body(Body::empty())
        .unwrap();
    let resp = Router::clone(&app).oneshot(req).await.unwrap();
    let values: Vec<_> = resp.headers().get_all("cache-control").iter().collect();
    assert_eq!(values.len(), 1, "NRAS keeps exactly its own header");
    assert_eq!(values[0], "no-store");
}

#[tokio::test]
async fn configured_value_replaces_a_relayed_upstream_cache_control() {
    // A handler that relays its own Cache-Control on a covered template.
    let app: Router = Router::new()
        .route(
            "/sgx/certification/v4/tcb",
            get(|| async { ([("cache-control", "max-age=1, private")], "ok") }),
        )
        .route(
            "/sgx/certification/v4/rootcacrl",
            get(|| async {
                (StatusCode::NOT_FOUND, [("cache-control", "max-age=86400")], "missing")
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            MAX_AGE,
            routes::handlers::collateral_cache_control,
        ));
    let (status, headers) = call(&app, Method::GET, "/sgx/certification/v4/tcb").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache_control(&headers), ["public, max-age=900"]);
    let (status, headers) = call(&app, Method::GET, "/sgx/certification/v4/rootcacrl").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(cache_control(&headers), ["no-store"]);
}
