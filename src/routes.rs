//! Router composition. Keeps the mounting table in one place so the service's
//! surface area is obvious.

use axum::Router;
use axum::routing::{get, post};

use crate::handlers::{manage, public};
use crate::state::AppState;

pub fn build(state: AppState) -> Router {
    let decoy_path = state.decoy_path.clone();

    Router::new()
        // apex pages
        .route("/", get(public::index_page))
        .route("/manage", get(manage::manage_page).post(manage::manage_post))
        .route("/admin", get(manage::admin_page))
        // public api
        .route("/register", post(public::register))
        .route("/delete", post(manage::delete_post))
        .route("/.well-known/atproto-did", get(public::well_known))
        // admin api
        .route("/api/admin/list", post(manage::admin_list))
        .route("/api/admin/wipe-did", post(manage::admin_wipe))
        .route("/api/admin/export", post(manage::admin_export))
        // decoy (D6)
        .route(&decoy_path, get(public::decoy_get).post(public::decoy_post))
        .with_state(state)
}
