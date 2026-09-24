//! Replay rejection and idempotent request handling.
//!
//! Two different problems that both look like "we saw this before":
//!
//! * **Replay** — an authorization record may be *used* once. The second
//!   presentation is an attack, and must fail.
//! * **Idempotency** — a client request may be *retried* freely. The second
//!   attempt is normal, and must return the first attempt's exact response
//!   rather than performing the effect twice.
//!
//! Both are enforced by the database rather than by a check-then-act in Rust:
//! two concurrent requests can both pass an application-level "have we seen
//! this?" test before either writes. The primary key is what actually
//! serialises them, so the insert is the decision point.

use crate::authz::VerifiedRecord;
use crate::error::AppError;
use sqlx::{Row, SqlitePool};

/// Outcome of claiming a replay id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayClaim {
    /// First use — the caller may proceed.
    Fresh,
    /// Already consumed. The record must be refused.
    AlreadyUsed,
}

/// Atomically consume a verified record's replay id.
///
/// Correctness rests on the `(tenant_id, payload_domain, replay_id)` primary
/// key: the insert either wins or hits a uniqueness violation, so concurrent
/// callers cannot both observe `Fresh`. No SELECT-then-INSERT, which would be
/// exactly the race this is meant to prevent.
pub async fn consume_replay_id(
    pool: &SqlitePool,
    tenant_id: &[u8; 16],
    table: ReplayTable,
    record: &VerifiedRecord,
    now: &str,
) -> Result<ReplayClaim, AppError> {
    // The ledger is a single table keyed by (tenant, domain, replay_id); the
    // record's own table is recorded as a column rather than selecting the
    // target table, so no identifier is ever interpolated into SQL.
    let sql = "INSERT OR IGNORE INTO v2_replay_ledger (
             tenant_id, payload_domain, replay_id, record_table,
             signed_container_hash, issuer_signing_key_id,
             not_before_ms, not_after_ms, consumed_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";

    // `INSERT OR IGNORE` + `changes()` keeps the claim to a single statement:
    // rows_affected() == 0 means the primary key already held this id.
    let result = sqlx::query(sql)
        .bind(tenant_id.as_slice())
        .bind(&record.domain)
        .bind(record.replay_id.as_slice())
        .bind(table.as_table_name())
        .bind(record.signed_container_hash.as_slice())
        .bind(record.issuer_signing_key_id.as_slice())
        .bind(record.not_before_ms as i64)
        .bind(record.not_after_ms as i64)
        .bind(now)
        .execute(pool)
        .await?;

    if result.rows_affected() == 1 {
        return Ok(ReplayClaim::Fresh);
    }

    // Zero rows means the insert was ignored, but OR IGNORE swallows every
    // constraint failure, not just the duplicate primary key this path is
    // testing for. Reporting "already used" without checking would turn a
    // schema problem into a replay accusation about a record that was never
    // stored -- which is exactly how a missing `record_table` CHECK value once
    // made every root key grant look like a replay. Confirm the row is really
    // there before blaming the caller.
    let present = sqlx::query(
        "SELECT 1 FROM v2_replay_ledger
          WHERE tenant_id = ? AND payload_domain = ? AND replay_id = ? LIMIT 1",
    )
    .bind(tenant_id.as_slice())
    .bind(&record.domain)
    .bind(record.replay_id.as_slice())
    .fetch_optional(pool)
    .await?
    .is_some();

    if present {
        Ok(ReplayClaim::AlreadyUsed)
    } else {
        Err(AppError::Internal(format!(
            "replay ledger rejected a claim for `{}` without recording it",
            table.as_table_name()
        )))
    }
}

/// Which authorization table a replay id belongs to.
///
/// An enum rather than a caller-supplied string: the table name is
/// interpolated into SQL, so it must not be attacker-influenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayTable {
    DeviceApprovals,
    CapabilityGrants,
    TenantRootKeyGrants,
    FleetKeyGrants,
}

impl ReplayTable {
    fn as_table_name(self) -> &'static str {
        match self {
            Self::DeviceApprovals => "v2_device_approvals",
            Self::CapabilityGrants => "v2_capability_grants",
            Self::TenantRootKeyGrants => "v2_tenant_root_key_grants",
            Self::FleetKeyGrants => "v2_fleet_key_grants",
        }
    }
}

/// Result of beginning an idempotent operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationClaim {
    /// This caller owns the operation and must perform the effect.
    Started,
    /// Already completed. Replay the stored response verbatim.
    Completed {
        status_code: u16,
        exact_response_bytes: Vec<u8>,
    },
    /// Another request holds this key and has not finished.
    InFlight,
    /// The key was reused with a different request body.
    ///
    /// Returning the stored response here would answer a question the client
    /// did not ask; performing the new effect would break the idempotency
    /// contract. Both are wrong, so this is a conflict.
    KeyReusedWithDifferentRequest,
}

/// Claim an idempotency key for an operation.
#[allow(clippy::too_many_arguments)]
pub async fn begin_operation(
    pool: &SqlitePool,
    tenant_id: &[u8; 16],
    idempotency_key: &[u8; 16],
    server_instance_id: &[u8; 16],
    restore_epoch: u64,
    account_id: &[u8; 16],
    device_id: &[u8; 16],
    operation_kind: &str,
    request_sha256: &[u8; 32],
    now: &str,
) -> Result<OperationClaim, AppError> {
    // Try to claim first, then read only if the claim lost. Reading first
    // would let two callers both see "absent" and both proceed.
    let inserted = sqlx::query(
        "INSERT OR IGNORE INTO v2_operations (
             tenant_id, idempotency_key, server_instance_id, restore_epoch,
             account_id, device_id, operation_kind, request_sha256,
             status, created_at
         ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'in_flight', ?)",
    )
    .bind(tenant_id.as_slice())
    .bind(idempotency_key.as_slice())
    .bind(server_instance_id.as_slice())
    .bind(restore_epoch as i64)
    .bind(account_id.as_slice())
    .bind(device_id.as_slice())
    .bind(operation_kind)
    .bind(request_sha256.as_slice())
    .bind(now)
    .execute(pool)
    .await?;

    if inserted.rows_affected() == 1 {
        return Ok(OperationClaim::Started);
    }

    let row = sqlx::query(
        "SELECT request_sha256, status, response_status_code, exact_response_bytes
           FROM v2_operations
          WHERE tenant_id = ? AND idempotency_key = ?
            AND server_instance_id = ? AND restore_epoch = ?",
    )
    .bind(tenant_id.as_slice())
    .bind(idempotency_key.as_slice())
    .bind(server_instance_id.as_slice())
    .bind(restore_epoch as i64)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| {
        // The claim was ignored but no row exists, so the insert was dropped
        // for a reason other than a duplicate key -- a constraint violation.
        // Reporting that as a replayed operation would blame the caller for a
        // server-side schema fault, which is how the root key grant ledger bug
        // stayed hidden.
        AppError::Internal(
            "operation ledger: claim was rejected but no row exists (constraint violation?)".into(),
        )
    })?;

    // Same key, different body: the client is misusing the key, and neither
    // answering nor re-executing is safe.
    let stored_request: Vec<u8> = row.get("request_sha256");
    if stored_request != request_sha256.as_slice() {
        return Ok(OperationClaim::KeyReusedWithDifferentRequest);
    }

    let status: String = row.get("status");
    match status.as_str() {
        "succeeded" | "failed" => {
            let code: i64 = row.try_get("response_status_code").unwrap_or(0);
            let body: Vec<u8> = row.try_get("exact_response_bytes").unwrap_or_default();
            Ok(OperationClaim::Completed {
                status_code: code as u16,
                exact_response_bytes: body,
            })
        }
        _ => Ok(OperationClaim::InFlight),
    }
}

/// Record an operation's outcome so retries replay it byte for byte.
#[allow(clippy::too_many_arguments)]
pub async fn complete_operation(
    pool: &SqlitePool,
    tenant_id: &[u8; 16],
    idempotency_key: &[u8; 16],
    server_instance_id: &[u8; 16],
    restore_epoch: u64,
    status_code: u16,
    exact_response_bytes: &[u8],
    now: &str,
) -> Result<(), AppError> {
    let response_sha = shared::canonical::sha256(exact_response_bytes);

    // Guarded by `status = 'in_flight'` so a late writer cannot overwrite a
    // completed operation's stored response.
    sqlx::query(
        "UPDATE v2_operations
            SET status = ?, response_status_code = ?, exact_response_bytes = ?,
                response_sha256 = ?, completed_at = ?
          WHERE tenant_id = ? AND idempotency_key = ?
            AND server_instance_id = ? AND restore_epoch = ?
            AND status = 'in_flight'",
    )
    .bind(if (200..400).contains(&status_code) {
        "succeeded"
    } else {
        "failed"
    })
    .bind(status_code as i64)
    .bind(exact_response_bytes)
    .bind(response_sha.as_slice())
    .bind(now)
    .bind(tenant_id.as_slice())
    .bind(idempotency_key.as_slice())
    .bind(server_instance_id.as_slice())
    .bind(restore_epoch as i64)
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    async fn pool_with_tenant() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO v2_tenants (id, slug, status, active_root_generation, created_at)
             VALUES (?, 'acme', 'active', 1, '2026-01-01T00:00:00+00:00')",
        )
        .bind([1u8; 16].as_slice())
        .execute(&pool)
        .await
        .unwrap();
        pool
    }

    fn record() -> VerifiedRecord {
        VerifiedRecord {
            domain: "shardx.authorization.device-approval.v2".into(),
            replay_id: [7u8; 16],
            issuer_signing_key_id: [8u8; 32],
            signed_container_hash: [9u8; 32],
            signature_bytes: [0u8; 64],
            not_before_ms: 1_000,
            not_after_ms: 2_000,
            exact_bytes_sha256: [10u8; 32],
            fields: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_replay_id_can_only_be_consumed_once() {
        let pool = pool_with_tenant().await;
        let rec = record();
        let t = [1u8; 16];

        assert_eq!(
            consume_replay_id(
                &pool,
                &t,
                ReplayTable::DeviceApprovals,
                &rec,
                "2026-01-01T00:00:00+00:00"
            )
            .await
            .unwrap(),
            ReplayClaim::Fresh
        );
        assert_eq!(
            consume_replay_id(
                &pool,
                &t,
                ReplayTable::DeviceApprovals,
                &rec,
                "2026-01-01T00:00:01+00:00"
            )
            .await
            .unwrap(),
            ReplayClaim::AlreadyUsed
        );
    }

    #[tokio::test]
    async fn concurrent_consumers_of_one_replay_id_yield_exactly_one_winner() {
        // The check that actually matters: a check-then-act implementation
        // passes the sequential test above and fails this one.
        let pool = SqlitePoolOptions::new()
            .max_connections(8)
            .connect("sqlite::memory:?cache=shared")
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        sqlx::query(
            "INSERT INTO v2_tenants (id, slug, status, active_root_generation, created_at)
             VALUES (?, 'acme', 'active', 1, '2026-01-01T00:00:00+00:00')",
        )
        .bind([1u8; 16].as_slice())
        .execute(&pool)
        .await
        .unwrap();

        let mut handles = Vec::new();
        for _ in 0..8 {
            let p = pool.clone();
            handles.push(tokio::spawn(async move {
                consume_replay_id(
                    &p,
                    &[1u8; 16],
                    ReplayTable::DeviceApprovals,
                    &record(),
                    "2026-01-01T00:00:00+00:00",
                )
                .await
                .unwrap()
            }));
        }

        let mut fresh = 0;
        for h in handles {
            if h.await.unwrap() == ReplayClaim::Fresh {
                fresh += 1;
            }
        }
        assert_eq!(fresh, 1, "exactly one caller may consume a replay id");
    }

    #[tokio::test]
    async fn the_same_replay_id_is_independent_across_tenants() {
        // Tenants must not be able to burn each other's replay ids.
        let pool = pool_with_tenant().await;
        sqlx::query(
            "INSERT INTO v2_tenants (id, slug, status, active_root_generation, created_at)
             VALUES (?, 'other', 'active', 1, '2026-01-01T00:00:00+00:00')",
        )
        .bind([2u8; 16].as_slice())
        .execute(&pool)
        .await
        .unwrap();

        let rec = record();
        let now = "2026-01-01T00:00:00+00:00";
        assert_eq!(
            consume_replay_id(&pool, &[1u8; 16], ReplayTable::DeviceApprovals, &rec, now)
                .await
                .unwrap(),
            ReplayClaim::Fresh
        );
        assert_eq!(
            consume_replay_id(&pool, &[2u8; 16], ReplayTable::DeviceApprovals, &rec, now)
                .await
                .unwrap(),
            ReplayClaim::Fresh,
            "another tenant's identical replay id must be unaffected"
        );
    }

    #[tokio::test]
    async fn a_retry_replays_the_exact_stored_response() {
        let pool = pool_with_tenant().await;
        let (t, k, s) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let req = [4u8; 32];
        let now = "2026-01-01T00:00:00+00:00";

        assert_eq!(
            begin_operation(
                &pool,
                &t,
                &k,
                &s,
                0,
                &[5u8; 16],
                &[6u8; 16],
                "profile.commit",
                &req,
                now
            )
            .await
            .unwrap(),
            OperationClaim::Started
        );

        let body = b"{\"snapshot\":42}".to_vec();
        complete_operation(&pool, &t, &k, &s, 0, 201, &body, now)
            .await
            .unwrap();

        assert_eq!(
            begin_operation(
                &pool,
                &t,
                &k,
                &s,
                0,
                &[5u8; 16],
                &[6u8; 16],
                "profile.commit",
                &req,
                now
            )
            .await
            .unwrap(),
            OperationClaim::Completed {
                status_code: 201,
                exact_response_bytes: body
            }
        );
    }

    #[tokio::test]
    async fn reusing_a_key_with_a_different_body_is_a_conflict() {
        let pool = pool_with_tenant().await;
        let (t, k, s) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let now = "2026-01-01T00:00:00+00:00";

        begin_operation(
            &pool,
            &t,
            &k,
            &s,
            0,
            &[5u8; 16],
            &[6u8; 16],
            "profile.commit",
            &[4u8; 32],
            now,
        )
        .await
        .unwrap();

        assert_eq!(
            begin_operation(
                &pool,
                &t,
                &k,
                &s,
                0,
                &[5u8; 16],
                &[6u8; 16],
                "profile.commit",
                &[99u8; 32],
                now
            )
            .await
            .unwrap(),
            OperationClaim::KeyReusedWithDifferentRequest
        );
    }

    #[tokio::test]
    async fn an_unfinished_operation_reports_in_flight() {
        let pool = pool_with_tenant().await;
        let (t, k, s) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let req = [4u8; 32];
        let now = "2026-01-01T00:00:00+00:00";

        begin_operation(
            &pool,
            &t,
            &k,
            &s,
            0,
            &[5u8; 16],
            &[6u8; 16],
            "profile.commit",
            &req,
            now,
        )
        .await
        .unwrap();

        assert_eq!(
            begin_operation(
                &pool,
                &t,
                &k,
                &s,
                0,
                &[5u8; 16],
                &[6u8; 16],
                "profile.commit",
                &req,
                now
            )
            .await
            .unwrap(),
            OperationClaim::InFlight
        );
    }

    #[tokio::test]
    async fn a_restore_frees_the_key_without_serving_the_old_response() {
        // After a restore the epoch advances. The pre-restore response must
        // not be replayed, or a restore would resurrect stale results.
        let pool = pool_with_tenant().await;
        let (t, k, s) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let req = [4u8; 32];
        let now = "2026-01-01T00:00:00+00:00";

        begin_operation(
            &pool,
            &t,
            &k,
            &s,
            0,
            &[5u8; 16],
            &[6u8; 16],
            "profile.commit",
            &req,
            now,
        )
        .await
        .unwrap();
        complete_operation(&pool, &t, &k, &s, 0, 200, b"old", now)
            .await
            .unwrap();

        // Same key, epoch 1: a fresh claim, not the epoch-0 response.
        assert_eq!(
            begin_operation(
                &pool,
                &t,
                &k,
                &s,
                1,
                &[5u8; 16],
                &[6u8; 16],
                "profile.commit",
                &req,
                now
            )
            .await
            .unwrap(),
            OperationClaim::Started
        );
    }

    #[tokio::test]
    async fn a_completed_operation_cannot_be_overwritten() {
        // Guards against a slow duplicate worker clobbering the response a
        // client has already been given.
        let pool = pool_with_tenant().await;
        let (t, k, s) = ([1u8; 16], [2u8; 16], [3u8; 16]);
        let now = "2026-01-01T00:00:00+00:00";

        begin_operation(
            &pool,
            &t,
            &k,
            &s,
            0,
            &[5u8; 16],
            &[6u8; 16],
            "profile.commit",
            &[4u8; 32],
            now,
        )
        .await
        .unwrap();
        complete_operation(&pool, &t, &k, &s, 0, 200, b"first", now)
            .await
            .unwrap();
        complete_operation(&pool, &t, &k, &s, 0, 500, b"second", now)
            .await
            .unwrap();

        let row = sqlx::query(
            "SELECT response_status_code, exact_response_bytes FROM v2_operations
              WHERE tenant_id = ? AND idempotency_key = ?",
        )
        .bind(t.as_slice())
        .bind(k.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();

        let code: i64 = row.get("response_status_code");
        let body: Vec<u8> = row.get("exact_response_bytes");
        assert_eq!(code, 200, "the first response must stand");
        assert_eq!(body, b"first");
    }
}
