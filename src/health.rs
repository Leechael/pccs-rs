//! Health probe endpoints for Kubernetes and similar orchestrators.
//!
//! - `/healthz/live` — liveness: process is alive (never checks the DB).
//! - `/healthz/ready` — readiness: RocksDB is usable.
//! - `/healthz/startup` — startup: boot sequence has completed.

use crate::auth::AppState;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Process-global startup state. Cleared on boot, set once the HTTP server is
/// accepting connections. Must be `Arc` so `mark_started` can own it without
/// the router losing access.
#[derive(Clone)]
pub struct StartupState {
    started: Arc<AtomicBool>,
}

impl StartupState {
    pub fn new() -> Self {
        Self { started: Arc::new(AtomicBool::new(false)) }
    }

    pub fn is_started(&self) -> bool {
        self.started.load(Ordering::Relaxed)
    }

    pub fn mark_started(&self) {
        self.started.store(true, Ordering::Release);
    }
}

impl Default for StartupState {
    fn default() -> Self {
        Self::new()
    }
}

fn json_response(status: StatusCode, value: serde_json::Value) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, HeaderValue::from_static("application/json"));
    (status, headers, serde_json::to_vec(&value).unwrap_or_default()).into_response()
}

fn now_iso8601() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

/// `GET /healthz/live` — liveness probe. Always returns 200 with `{"status":
/// "UP", "timestamp": "<ISO8601>"}`. Must NOT touch the database: a DB outage
/// must not restart the process.
pub async fn liveness() -> Response {
    json_response(StatusCode::OK, json!({ "status": "UP", "timestamp": now_iso8601() }))
}

/// `GET /healthz/ready` — readiness probe. Returns 200 when RocksDB is usable,
/// 503 otherwise. Performs a lightweight DB check (property read + latency
/// measurement), analogous to the JS `sequelize.authenticate()` + `select 1`.
pub async fn readiness(State(state): State<AppState>) -> Response {
    let timestamp = now_iso8601();
    let start = std::time::Instant::now();

    // Cheap RocksDB probe: reading a DB property fails if the DB is closed or
    // unreadable, and succeeds instantly when the DB is healthy. Analogous to
    // JS `select 1 from pcs_version limit 1`.
    let db_ok = state.cache.store.is_healthy();

    let latency_ms = start.elapsed().as_millis();

    if db_ok {
        json_response(
            StatusCode::OK,
            json!({
                "status": "UP",
                "db": "CONNECTED",
                "latency": format!("{latency_ms}ms"),
                "timestamp": timestamp
            }),
        )
    } else {
        json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({
                "status": "DOWN",
                "db": "DISCONNECTED",
                "timestamp": timestamp
            }),
        )
    }
}

/// `GET /healthz/startup` — startup probe. Returns 200 once the HTTP server is
/// accepting connections (after `mark_started()` is called), or 503 while
/// still starting.
pub async fn startup(State(state): State<AppState>) -> Response {
    let timestamp = now_iso8601();
    if state.startup.is_started() {
        json_response(StatusCode::OK, json!({ "status": "STARTED", "timestamp": timestamp }))
    } else {
        json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            json!({ "status": "STARTING", "timestamp": timestamp }),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::build_cache;
    use crate::config::Config;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    #[tokio::test]
    async fn liveness_always_returns_200() {
        let resp = liveness().await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["status"], "UP");
        assert!(body.get("timestamp").is_some());
    }

    #[tokio::test]
    async fn readiness_returns_200_when_db_is_healthy() {
        let cfg = Config::test_default();
        let cache = build_cache(&cfg).unwrap();
        let state = AppState { cache, config: Arc::new(cfg) };

        let resp = readiness(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["status"], "UP");
        assert_eq!(body["db"], "CONNECTED");
        assert!(body["latency"].as_str().unwrap().ends_with("ms"));
        assert!(body.get("timestamp").is_some());
    }

    #[tokio::test]
    async fn startup_returns_503_before_started_and_200_after() {
        let cfg = Config::test_default();
        let cache = build_cache(&cfg).unwrap();
        let startup_state = StartupState::new();
        let state = AppState { cache, config: Arc::new(cfg), startup: startup_state.clone() };

        assert!(!startup_state.is_started());

        let resp = super::startup(State(state.clone())).await;
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["status"], "STARTING");

        startup_state.mark_started();
        assert!(startup_state.is_started());

        let resp = super::startup(State(state)).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(body["status"], "STARTED");
    }

    #[tokio::test]
    async fn health_probes_route_integration() {
        use axum::Router;

        let cfg = Config::test_default();
        let cache = build_cache(&cfg).unwrap();
        let startup_state = StartupState::new();
        let state = AppState { cache, config: Arc::new(cfg), startup: startup_state.clone() };

        let app = Router::new().nest("/healthz", crate::routes::healthz_router()).with_state(state);

        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/healthz/live").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/healthz/ready").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(Request::builder().uri("/healthz/startup").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        startup_state.mark_started();

        let resp = app
            .oneshot(Request::builder().uri("/healthz/startup").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
