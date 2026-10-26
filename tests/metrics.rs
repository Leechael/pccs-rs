//! Metrics stay outside the PCCS API and never turn request identifiers into labels.
use axum::{
    body::Body,
    http::{HeaderMap, Request, StatusCode},
    Router,
};
use http_body_util::BodyExt;
use pccs_rs::{app_state, config::Config, create_app, headers, store::PckCrlRecord};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tower::ServiceExt;

async fn get(app: &Router, path: &str) -> (StatusCode, HeaderMap, bytes::Bytes) {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body)
}
fn sample(text: &str, name: &str, labels: &str) -> u64 {
    let prefix = format!("{name}{labels} ");
    text.lines().find_map(|line| line.strip_prefix(&prefix)).unwrap_or("0").parse().unwrap()
}
fn config(dir: &tempfile::TempDir) -> Config {
    let mut cfg = Config::test_default();
    cfg.db_path = dir.path().join("db");
    cfg.no_seed = true;
    cfg
}

#[tokio::test]
async fn metrics_cold_then_hit_observes_actual_upstream_and_store() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = calls.clone();
    let mock = Router::new().fallback(axum::routing::get(move || {
        seen.fetch_add(1, Ordering::Relaxed);
        async { ([("content-type", "application/pkix-cert")], "synthetic certificate") }
    }));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let upstream = tokio::spawn(async move { axum::serve(listener, mock).await.unwrap() });
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.amd_kds_uri = format!("http://{addr}");
    let state = app_state(cfg);
    let metrics = state.cache.store.metrics.clone();
    let app = create_app(state);
    let path = "/vcek/v1/Milan/0123456789abcdef?blSPL=1";
    let (status, off_headers, cold) = get(&app, path).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!off_headers.contains_key("server-timing"));
    let first = metrics.render();
    assert_eq!(sample(&first, "pccs_cache_lookups_total", "{kind=\"amd_kds\",result=\"miss\"}"), 1);
    assert_eq!(
        sample(&first, "pccs_upstream_requests_total", "{upstream=\"amd_kds\",status=\"200\"}"),
        1
    );
    assert_eq!(
        sample(&first, "pccs_upstream_attempt_duration_seconds_count", "{upstream=\"amd_kds\"}"),
        1
    );
    assert_eq!(
        sample(&first, "pccs_http_request_duration_seconds_count", "{route=\"/vcek/{*rest}\"}"),
        1
    );
    let (status, _, warm) = get(&app, path).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(cold, warm);
    let second = metrics.render();
    assert_eq!(sample(&second, "pccs_cache_lookups_total", "{kind=\"amd_kds\",result=\"hit\"}"), 1);
    assert_eq!(
        sample(&second, "pccs_upstream_requests_total", "{upstream=\"amd_kds\",status=\"200\"}"),
        1
    );
    assert_eq!(calls.load(Ordering::Relaxed), 1);
    let lookups: u64 = ["hit", "miss", "expired"]
        .into_iter()
        .map(|result| {
            sample(
                &second,
                "pccs_cache_lookups_total",
                &format!("{{kind=\"amd_kds\",result=\"{result}\"}}"),
            )
        })
        .sum();
    assert_eq!(lookups, 2, "one cold and one hot request count as two initial lookups");
    assert!(sample(&second, "pccs_store_read_duration_seconds_count", "{kind=\"amd_kds\"}") >= 2);
    upstream.abort();
}

#[tokio::test]
async fn main_metrics_stays_404_even_with_metrics_configured() {
    let dir = tempfile::tempdir().unwrap();
    let mut cfg = config(&dir);
    cfg.metrics_listen = Some("127.0.0.1:0".parse().unwrap());
    let state = app_state(cfg);
    let metrics = state.cache.store.metrics.clone();
    let app = create_app(state);
    assert_eq!(get(&app, "/metrics").await.0, StatusCode::NOT_FOUND);
    assert_eq!(
        sample(
            &metrics.render(),
            "pccs_http_requests_total",
            "{route=\"unmatched\",status_class=\"4xx\"}"
        ),
        1
    );
    let (status, hdrs, body) = get(&metrics.router(), "/metrics").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(hdrs["content-type"], "text/plain; version=0.0.4; charset=utf-8");
    assert!(std::str::from_utf8(&body)
        .unwrap()
        .contains("# TYPE pccs_http_requests_total counter"));
}

#[tokio::test]
async fn random_paths_create_only_one_unmatched_series() {
    let dir = tempfile::tempdir().unwrap();
    let state = app_state(config(&dir));
    let metrics = state.cache.store.metrics.clone();
    let app = create_app(state);
    let baseline = metrics.render();
    let series = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|line| line.starts_with("pccs_http_requests_total{"))
            .map(|line| line.split_once(' ').unwrap().0.to_string())
            .collect()
    };
    let initial_series = series(&baseline);
    for i in 0..1000 {
        let prefix =
            ["", "/sgx/certification/v3", "/sgx/certification/v4", "/tdx/certification/v4"][i % 4];
        let path = format!("{prefix}/{}", uuid::Uuid::new_v4().simple());
        assert_eq!(get(&app, &path).await.0, StatusCode::NOT_FOUND);
    }
    let text = metrics.render();
    assert_eq!(series(&text), initial_series, "random paths cannot create any new counter series");
    let counters: Vec<_> = text
        .lines()
        .filter(|line| line.starts_with("pccs_http_requests_total{") && !line.ends_with(" 0"))
        .collect();
    assert_eq!(
        counters,
        ["pccs_http_requests_total{route=\"unmatched\",status_class=\"4xx\"} 1000"]
    );
    assert_eq!(
        sample(&text, "pccs_http_request_duration_seconds_count", "{route=\"unmatched\"}"),
        1000
    );
    for class in ["2xx", "3xx", "4xx", "5xx", "other"] {
        assert_eq!(
            sample(
                &text,
                "pccs_http_requests_total",
                &format!("{{route=\"/metrics\",status_class=\"{class}\"}}")
            ),
            0
        );
    }
    assert!(!text.contains("pccs_http_request_duration_seconds_count{route=\"/metrics\"}"));
}

#[tokio::test]
async fn server_timing_opt_in_preserves_response_and_never_contains_keys() {
    async fn response(enabled: bool) -> (StatusCode, HeaderMap, bytes::Bytes) {
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = config(&dir);
        cfg.server_timing = enabled;
        let state = app_state(cfg);
        state
            .cache
            .store
            .put_pckcrl(&PckCrlRecord {
                ca: "processor".into(),
                pckcrl: vec![1, 2, 3],
                issuer_chain: "synthetic-chain".into(),
            })
            .unwrap();
        get(
            &create_app(state),
            "/sgx/certification/v4/pckcrl?ca=processor&encoding=der&unused=0123456789abcdef",
        )
        .await
    }
    let (off_status, mut off_headers, off_body) = response(false).await;
    let (on_status, mut on_headers, on_body) = response(true).await;
    assert_eq!(off_status, StatusCode::OK);
    assert_eq!(off_status, on_status);
    assert_eq!(off_body, on_body);
    assert!(!off_headers.contains_key("server-timing"));
    let timing = on_headers.remove("server-timing").unwrap();
    let timing = timing.to_str().unwrap();
    assert!(timing.contains("cache;desc=hit"), "{timing}");
    for stage in ["store;dur=", "lock;dur=", "upstream;dur=", "app;dur="] {
        assert!(timing.contains(stage), "{timing}");
    }
    assert!(!timing.contains("0123456789abcdef"));
    assert!(!timing.contains("processor"));
    // Request-ID is intentionally generated anew, not a metrics change.
    assert!(off_headers.remove(headers::REQUEST_ID).is_some());
    assert!(on_headers.remove(headers::REQUEST_ID).is_some());
    assert_eq!(off_headers, on_headers);
    assert_eq!(off_headers["content-type"], "application/pkix-crl");
    assert_eq!(off_headers[headers::SGX_PCK_CRL_ISSUER_CHAIN], "synthetic-chain");
}
