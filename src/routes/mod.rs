pub mod handlers;

use crate::auth::{self, AppState};
use axum::middleware;
use axum::routing::{get, post, put};
use axum::Router;

pub fn sgx_router(state: AppState) -> Router<AppState> {
    let admin = Router::new()
        .route("/platforms", get(handlers::get_platforms))
        .route(
            "/platformcollateral",
            put(handlers::put_platform_collateral),
        )
        .route("/refresh", get(handlers::refresh).post(handlers::refresh))
        .route("/appraisalpolicy", put(handlers::put_appraisal_policy))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_admin,
        ));

    let user = Router::new()
        .route("/platforms", post(handlers::post_platforms))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_user,
        ));

    Router::new()
        .merge(admin)
        .merge(user)
        .route("/pckcert", get(handlers::get_pckcert))
        .route("/pckcrl", get(handlers::get_pckcrl))
        .route("/tcb", get(handlers::get_sgx_tcb))
        .route("/qe/identity", get(handlers::get_qe_identity))
        .route("/qve/identity", get(handlers::get_qve_identity))
        .route("/rootcacrl", get(handlers::get_rootcacrl))
        .route("/crl", get(handlers::get_crl))
        .route("/appraisalpolicy", get(handlers::get_appraisal_policy))
}

pub fn tdx_router() -> Router<AppState> {
    Router::new()
        .route("/tcb", get(handlers::get_tdx_tcb))
        .route("/qe/identity", get(handlers::get_tdqe_identity))
}

pub fn amd_kds_router() -> Router<AppState> {
    Router::new()
        .route("/vcek/{*rest}", get(handlers::get_amd_kds))
        .route("/vlek/{*rest}", get(handlers::get_amd_kds))
}
