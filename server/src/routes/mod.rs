pub mod acl;
pub mod envs;
pub mod folders;
pub mod locks;
pub mod proxies;
pub mod users;
pub mod v2;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::auth;
use crate::state::AppState;

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/auth/login", post(auth::login))
        .route("/me", get(auth::me))
        .route("/me/password", post(auth::change_password))
        // users (admin)
        .route("/users", get(users::list).post(users::create))
        .route("/users/:id", delete(users::delete))
        .route("/users/:id/role", patch(users::set_role))
        .route("/users/:id/password", patch(users::reset_password))
        // audit trail (admin)
        .route("/audit", get(crate::audit::list))
        // v2 team/fleet control plane
        .route("/v2/server-identity", get(v2::server_identity))
        .route(
            "/v2/devices/enrollment-challenges",
            post(v2::create_enrollment_challenge),
        )
        .route("/v2/devices/enrollment-proofs", post(v2::enroll_device))
        .route("/v2/device-approvals", post(v2::present_device_approval))
        .route("/v2/capability-grants", post(v2::present_capability_grant))
        .route(
            "/v2/tenant-root-key-grants",
            post(v2::present_tenant_root_key_grant),
        )
        .route("/v2/root-key-generations", post(v2::begin_root_generation))
        .route(
            "/v2/root-key-generations/activate",
            post(v2::activate_root_generation),
        )
        .route(
            "/v2/tenants/:tenant_id/root-key-generation",
            get(v2::get_active_root_generation),
        )
        .route(
            "/v2/tenants/:tenant_id/devices/:device_id/root-key-grants",
            get(v2::list_tenant_root_key_grants),
        )
        .route("/v2/fleet-key-grants", post(v2::present_fleet_key_grant))
        .route(
            "/v2/fleet-key-generations",
            post(v2::begin_fleet_generation),
        )
        .route(
            "/v2/fleet-key-generations/activate",
            post(v2::activate_fleet_generation),
        )
        .route(
            "/v2/tenants/:tenant_id/fleets/:fleet_id/key-generation",
            get(v2::get_active_fleet_generation),
        )
        .route(
            "/v2/tenants/:tenant_id/devices/:device_id/fleet-key-grants",
            get(v2::list_fleet_key_grants),
        )
        .route("/v2/operations", post(v2::begin_idempotent_operation))
        .route(
            "/v2/operations/complete",
            post(v2::complete_idempotent_operation),
        )
        // v2 fleet sync transfer
        .route("/v2/fleet/leases", post(v2::acquire_profile_lease))
        .route("/v2/fleet/leases/release", post(v2::release_profile_lease))
        .route("/v2/fleet/uploads", post(v2::open_snapshot_upload))
        .route(
            "/v2/fleet/uploads/:tenant_id/:session_id/chunk",
            post(v2::append_snapshot_chunk),
        )
        .route("/v2/fleet/uploads/commit", post(v2::commit_snapshot_upload))
        .route("/v2/fleet/uploads/abort", post(v2::abort_snapshot_upload))
        .route(
            "/v2/fleet/snapshots/:tenant_id/:profile_id",
            get(v2::head_snapshot),
        )
        .route(
            "/v2/fleet/snapshots/:tenant_id/:profile_id/range",
            get(v2::download_snapshot_range),
        )
        // folders
        .route("/folders", get(folders::list).post(folders::create))
        .route(
            "/folders/:id",
            patch(folders::update).delete(folders::delete),
        )
        // environments
        .route("/envs", get(envs::list).post(envs::create))
        .route(
            "/envs/:id",
            get(envs::get).patch(envs::update).delete(envs::delete),
        )
        // checkout locks + snapshots
        .route("/envs/:id/checkout", post(locks::checkout))
        .route("/envs/:id/lease", post(locks::lease))
        .route("/envs/:id/release", post(locks::release))
        .route("/envs/:id/force-unlock", post(locks::force_unlock))
        .route("/envs/:id/lock", get(locks::status))
        .route(
            "/envs/:id/checkin",
            post(locks::checkin).layer(DefaultBodyLimit::max(state.cfg.max_snapshot_bytes)),
        )
        .route("/envs/:id/snapshot/:version", get(locks::download))
        // access control (admin)
        .route("/acl", post(acl::grant).delete(acl::revoke))
        // proxies
        .route("/proxies", get(proxies::list).post(proxies::create))
        .route("/proxies/:id", delete(proxies::delete))
        .with_state(state)
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}
