pub mod acl;
pub mod envs;
pub mod folders;
pub mod locks;
pub mod proxies;
pub mod users;
pub mod v2;
pub mod v2_approval;
pub mod v2_auth;
pub mod v2_capability;
pub mod v2_device_revoke;
pub mod v2_fleet;
pub mod v2_profiles;
pub mod v2_restore_epoch;
pub mod v2_root;
pub mod v2_root_grants;
pub mod v2_trust;
pub mod v2_upload_recovery;
pub mod v2_uploads;

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::Method;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, patch, post};
use axum::{Json, Router};
use serde_json::{json, Value};

use crate::auth;
use crate::error::AppError;
use crate::quarantine;
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
        // v2 accounts and proof-bound device sessions (ADR 0001 R2)
        .route("/v2/auth/login", post(v2_auth::login))
        .route(
            "/v2/auth/device-session-challenges",
            post(v2_auth::create_device_session_challenge),
        )
        .route(
            "/v2/auth/device-session-proofs",
            post(v2_auth::prove_device_session),
        )
        .route("/v2/auth/refresh", post(v2_auth::refresh))
        .route("/v2/auth/logout", post(v2_auth::logout))
        .route("/v2/me", get(v2_auth::me))
        .route(
            "/v2/devices/enrollment-challenges",
            post(v2_auth::create_enrollment_challenge),
        )
        .route(
            "/v2/devices/enrollment-proofs",
            post(v2_auth::enroll_device),
        )
        .route(
            "/v2/devices/:device_id/approve",
            post(v2_approval::approve_device)
                .layer(DefaultBodyLimit::max(v2_approval::MAX_APPROVAL_BODY)),
        )
        .route(
            "/v2/tenants/:tenant_id/root-key-generations",
            post(v2_root::create_root_generation)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/tenants/:tenant_id/root-key-generations/:generation/grants",
            post(v2_root_grants::file_root_grant)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/tenants/:tenant_id/root-key-generations/:generation/grants/:replay_id",
            get(v2_root_grants::read_root_grant),
        )
        .route(
            "/v2/tenants/:tenant_id/root-key-generations/:generation/grants/:replay_id/ack",
            post(v2_root_grants::ack_root_grant)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/tenants/:tenant_id/root-key-generations/:generation/grants/:replay_id/revoke",
            post(v2_root_grants::revoke_root_grant)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/tenants/:tenant_id/root-key-generations/:generation/activate",
            post(v2_root_grants::activate_root_generation)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/devices/:device_id/revoke",
            post(v2_device_revoke::revoke_device)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/fleets/:fleet_id/key-generations",
            post(v2_fleet::create_fleet_generation)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/fleets/:fleet_id/key-generations/:generation/grants",
            post(v2_fleet::file_fleet_grant)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/fleets/:fleet_id/key-generations/:generation/grants/:device_id",
            get(v2_fleet::read_fleet_device_grant),
        )
        .route(
            "/v2/fleets/:fleet_id/key-generations/:generation/ack",
            post(v2_fleet::ack_fleet_grant)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/fleets/:fleet_id/key-generations/:generation/activate",
            post(v2_fleet::activate_fleet_generation)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/fleets/:fleet_id/key-generations/:generation/grants/:replay_id/revoke",
            post(v2_fleet::revoke_fleet_grant)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/fleets/:fleet_id/profiles",
            post(v2_profiles::publish_profile)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/profiles/:profile_id/checkout",
            post(v2_profiles::checkout_profile)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/profiles/:profile_id/leases/:lease_id/renew",
            post(v2_profiles::renew_lease)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/profiles/:profile_id/leases/:lease_id/release",
            post(v2_profiles::release_lease)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/profiles/:profile_id/leases/:lease_id/force-expire",
            post(v2_profiles::force_expire_lease),
        )
        .route(
            "/v2/profiles/:profile_id/uploads",
            post(v2_uploads::create_upload)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/uploads/:upload_id",
            patch(v2_uploads::patch_upload)
                .head(v2_uploads::head_upload)
                .delete(v2_uploads::abort_upload)
                .layer(DefaultBodyLimit::max(v2_uploads::MAX_CHUNK_BYTES)),
        )
        .route(
            "/v2/uploads/:upload_id/finalize",
            post(v2_uploads::finalize_upload)
                .layer(DefaultBodyLimit::max(v2_root::MAX_ROOT_REQUEST_BODY)),
        )
        .route(
            "/v2/uploads/:upload_id/commit",
            post(v2_uploads::commit_upload).layer(DefaultBodyLimit::max(
                shared::snapshot_v2::MAX_COMMIT_REQUEST_BYTES,
            )),
        )
        .route(
            "/v2/profiles/:profile_id/snapshots/:version",
            get(v2_uploads::read_snapshot),
        )
        .route(
            "/v2/profiles/:profile_id/snapshots/:version/manifest",
            get(v2_uploads::read_snapshot_manifest),
        )
        .route(
            "/v2/capability-grants",
            post(v2_capability::file_capability_grant).layer(DefaultBodyLimit::max(
                v2_capability::MAX_CAPABILITY_GRANT_BODY,
            )),
        )
        .route(
            "/v2/recovery/restore-epoch-transitions",
            post(v2_restore_epoch::file_restore_epoch_transition)
                .layer(DefaultBodyLimit::max(v2_restore_epoch::MAX_FILING_BODY)),
        )
        .route(
            "/v2/recovery/restore-epoch-transitions/:tenant_id/:previous_epoch/:new_epoch",
            get(v2_restore_epoch::read_restore_epoch_transition),
        )
        .route(
            "/v2/recovery/restore-epoch-transitions/:tenant_id/:previous_epoch/:new_epoch/proofs/:profile_id",
            get(v2_restore_epoch::read_restore_epoch_proof),
        )
        .route(
            "/v2/tenants/:tenant_id/trust-evidence",
            get(v2_trust::trust_evidence),
        )
        .route(
            "/v2/tenants/:tenant_id/root-key-generation",
            get(v2::get_active_root_generation),
        )
        .route(
            "/v2/tenants/:tenant_id/devices/:device_id/root-key-grants",
            get(v2::list_tenant_root_key_grants),
        )
        .route(
            "/v2/tenants/:tenant_id/fleets/:fleet_id/key-generation",
            get(v2::get_active_fleet_generation),
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
        .layer(middleware::from_fn_with_state(state.clone(), v2_write_gate))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            record_quarantine,
        ))
        .with_state(state)
}

/// Records the quarantine a refused request found (plan 5.6.4). The request's
/// transaction rolled back with the refusal, so the mark is written in its
/// own; a write that fails leaves the grant to the next integrity pass.
async fn record_quarantine(State(app): State<AppState>, req: Request, next: Next) -> Response {
    let resp = next.run(req).await;
    if let Some(mark) = resp.extensions().get::<quarantine::Mark>() {
        if let Err(e) = quarantine::record(&app.db, mark).await {
            tracing::error!("could not record a grant quarantine: {e}");
        }
    }
    resp
}

/// Refuse every state-changing v2 request while the identity authority is
/// unverified. Keyed on the path prefix rather than per handler, so a new v2
/// route is gated without anyone remembering to.
async fn v2_write_gate(State(app): State<AppState>, req: Request, next: Next) -> Response {
    let read_only = matches!(*req.method(), Method::GET | Method::HEAD);
    if !read_only && req.uri().path().starts_with("/v2/") {
        if let Err(refusal) = app.authority.as_ref() {
            return AppError::EpochAuthority(refusal.code).into_response();
        }
    }
    next.run(req).await
}

async fn health() -> Json<Value> {
    Json(json!({ "ok": true }))
}
