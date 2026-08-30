//! pccs-rs — Rust collateral cache for Intel PCS and AMD KDS.
//!
//! The Intel HTTP API is 1:1 with Node PCCS. RocksDB is the source of truth.

#![forbid(unsafe_code)]

pub mod auth;
pub mod cache;
pub mod config;
pub mod error;
pub mod hash;
pub mod headers;
pub mod keys;
pub mod pcs;
pub mod routes;
pub mod selection;
pub mod store;
pub mod validate;

use crate::auth::AppState;
use crate::cache::build_cache;
use crate::config::Config;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::Router;
use std::sync::Arc;

pub fn app_state(cfg: Config) -> AppState {
    // `build_cache` fails for more than a bad DB path (a rejected proxy URL, a
    // seed that will not load), so the message must not claim RocksDB.
    let cache = build_cache(&cfg).unwrap_or_else(|e| {
        panic!("failed to initialise cache: {e}");
    });
    AppState {
        cache,
        config: Arc::new(cfg),
    }
}

pub fn create_app(state: AppState) -> Router {
    let body_limit = state.config.max_body_size;
    let pcs_ver = state.config.pcs_version();

    // Node mounts `v3EolWarning` with `app.use`, so every v3 request carries
    // the header — including ones that match no route. A fallback inside the
    // nested router keeps unmatched v3 paths under the layer.
    let sgx_v3 = routes::sgx_router(state.clone())
        .fallback(routes::handlers::not_found)
        .layer(middleware::from_fn(auth::v3_eol_warning));

    let mut app = Router::new()
        .nest("/sgx/certification/v3", sgx_v3)
        .merge(routes::amd_kds_router())
        .merge(routes::nvidia_rim_router());
    if pcs_ver == 4 {
        app = app
            .nest("/sgx/certification/v4", routes::sgx_router(state.clone()))
            .nest("/tdx/certification/v4", routes::tdx_router());
    }

    app.fallback(routes::handlers::not_found)
        .layer(middleware::from_fn(auth::add_request_id))
        .layer(DefaultBodyLimit::max(body_limit))
        .with_state(state)
}

pub fn create_app_from_config(cfg: Config) -> Router {
    create_app(app_state(cfg))
}
