//! Startup integrity pass for the v2 control plane (ADR 0001 R1, R4).
//!
//! Runs once the identity authority verifies and before the server accepts
//! requests, under the data-directory lock. It repairs nothing by guessing:
//! a device whose stored key IDs do not match its keys is quarantined, a
//! tenant without a bootstrap guard gets a `recovery_required` one (never
//! `unused`), a guard that disagrees with its confirmation is moved to
//! `recovery_required`, and a broken foreign key turns v2 writes off.

use anyhow::Result;
use shared::grants::HPKE_SUITE_ID_X25519_HKDF_SHA256_CHACHA20POLY1305 as HPKE_SUITE;
use shared::keys::{hpke_key_id, signing_key_id};
use shared::signing::{Ed25519VerifyingKey, SIGNATURE_SUITE_ID_ED25519 as SIGNING_SUITE};
use sqlx::{Row, SqlitePool};

use crate::identity::{ReasonCode, Refusal, Verified};
use crate::util;

/// Why a device's stored keys cannot be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyFault {
    /// A suite other than the pinned one, or a key that is not a usable
    /// Ed25519 point (unparseable or small order).
    InvalidEncoding,
    /// A stored ID that is not the R4 derivation of its key.
    IdMismatch,
}

impl KeyFault {
    fn reason(self) -> &'static str {
        match self {
            Self::InvalidEncoding => "invalid_key_encoding",
            Self::IdMismatch => "key_id_mismatch",
        }
    }
}

/// Checks a device's suites and raw keys and derives both IDs (R4).
///
/// X25519 accepts every 32-byte string as an encoding, so the HPKE key has no
/// encoding check here; a low-order HPKE key fails at encapsulation (R2).
pub fn derive_device_key_ids(
    signing_suite: i64,
    signing_public_key: &[u8; 32],
    hpke_suite: i64,
    hpke_public_key: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), KeyFault> {
    if signing_suite != i64::from(SIGNING_SUITE) || hpke_suite != i64::from(HPKE_SUITE) {
        return Err(KeyFault::InvalidEncoding);
    }
    match Ed25519VerifyingKey::from_bytes(signing_public_key) {
        Ok(vk) if !vk.is_weak() => {}
        _ => return Err(KeyFault::InvalidEncoding),
    }
    Ok((
        signing_key_id(signing_public_key),
        hpke_key_id(hpke_public_key),
    ))
}

/// What the pass did, for the startup log.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub quarantined_devices: usize,
    pub guards_created: usize,
    pub guards_to_recovery: usize,
    pub foreign_key_violations: usize,
}

impl Report {
    /// The refusal that turns v2 writes off, if the pass found one.
    pub fn refusal(&self) -> Option<Refusal> {
        (self.foreign_key_violations > 0).then(|| Refusal {
            code: ReasonCode::ControlPlaneIntegrityUntrusted,
            detail: format!(
                "{} foreign-key violation(s) in the control plane",
                self.foreign_key_violations
            ),
        })
    }
}

pub async fn run(pool: &SqlitePool, identity: &Verified) -> Result<Report> {
    let mut report = Report {
        quarantined_devices: quarantine_bad_keys(pool).await?,
        ..Report::default()
    };
    report.guards_created = create_missing_guards(pool, &identity.server_instance_id).await?;
    report.guards_to_recovery = reconcile_guards(pool).await?;
    report.foreign_key_violations = sqlx::query("SELECT 1 FROM pragma_foreign_key_check")
        .fetch_all(pool)
        .await?
        .len();
    Ok(report)
}

/// Quarantines every device whose suites, keys or stored IDs fail R4 and
/// revokes its sessions, one device per transaction.
async fn quarantine_bad_keys(pool: &SqlitePool) -> Result<usize> {
    let rows = sqlx::query(
        "SELECT tenant_id, id, status, signing_suite, signing_public_key, signing_key_id,
                hpke_suite, hpke_public_key, hpke_key_id
           FROM v2_devices d
          WHERE status <> 'quarantined'
            AND NOT EXISTS (SELECT 1 FROM v2_device_quarantine q
                             WHERE q.tenant_id = d.tenant_id AND q.device_id = d.id)",
    )
    .fetch_all(pool)
    .await?;
    let mut quarantined = 0;
    for row in rows {
        let key = |col: &str| -> Option<[u8; 32]> { row.get::<Vec<u8>, _>(col).try_into().ok() };
        let fault = match (key("signing_public_key"), key("hpke_public_key")) {
            (Some(spk), Some(hpk)) => match derive_device_key_ids(
                row.get("signing_suite"),
                &spk,
                row.get("hpke_suite"),
                &hpk,
            ) {
                Ok((sid, hid))
                    if key("signing_key_id") == Some(sid) && key("hpke_key_id") == Some(hid) =>
                {
                    continue
                }
                Ok(_) => KeyFault::IdMismatch,
                Err(fault) => fault,
            },
            _ => KeyFault::InvalidEncoding,
        };
        let tenant_id: Vec<u8> = row.get("tenant_id");
        let device_id: Vec<u8> = row.get("id");
        let now = util::now_rfc3339();
        let mut tx = pool.begin().await?;
        sqlx::query(
            "INSERT INTO v2_device_quarantine
                 (tenant_id, device_id, reason, prior_status, stored_signing_key_id,
                  stored_hpke_key_id, created_at)
             SELECT tenant_id, id, ?, status, signing_key_id, hpke_key_id, ?
               FROM v2_devices WHERE tenant_id = ? AND id = ?",
        )
        .bind(fault.reason())
        .bind(&now)
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(&mut *tx)
        .await?;
        // A revoked device stays revoked; the record above still says why.
        sqlx::query(
            "UPDATE v2_devices SET status = 'quarantined'
              WHERE tenant_id = ? AND id = ? AND status <> 'revoked'",
        )
        .bind(&tenant_id)
        .bind(&device_id)
        .execute(&mut *tx)
        .await?;
        // R4: a tenant whose device keys fail is in recovery, not bootstrap.
        sqlx::query(
            "UPDATE v2_bootstrap_guards
                SET state = 'recovery_required', recovery_reason = 'integrity_failure',
                    updated_at = ?
              WHERE tenant_id = ? AND state IN ('unused', 'reserved')",
        )
        .bind(&now)
        .bind(&tenant_id)
        .execute(&mut *tx)
        .await?;
        // R2: a status change revokes the device's sessions and open proofs.
        for table in ["v2_sessions", "v2_device_session_challenges"] {
            let extra = if table == "v2_sessions" {
                ""
            } else {
                " AND consumed_at_ms IS NULL"
            };
            sqlx::query(&format!(
                "UPDATE {table} SET revoked_at_ms = ?
                  WHERE tenant_id = ? AND device_id = ? AND revoked_at_ms IS NULL{extra}"
            ))
            .bind(util::now_ms())
            .bind(&tenant_id)
            .bind(&device_id)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        tracing::warn!(
            reason = fault.reason(),
            "quarantined a v2 device whose keys fail the R4 checks"
        );
        quarantined += 1;
    }
    Ok(quarantined)
}

/// Gives every tenant of this instance a guard. A missing guard is not proof
/// of a fresh tenant (R1), so it is created as `recovery_required`.
async fn create_missing_guards(pool: &SqlitePool, instance: &[u8; 16]) -> Result<usize> {
    let created = sqlx::query(
        "INSERT INTO v2_bootstrap_guards
             (server_instance_id, tenant_id, state, recovery_reason, updated_at)
         SELECT ?, t.id, 'recovery_required', 'missing_guard', ?
           FROM v2_tenants t
          WHERE NOT EXISTS (SELECT 1 FROM v2_bootstrap_guards g
                             WHERE g.server_instance_id = ? AND g.tenant_id = t.id)",
    )
    .bind(instance.as_slice())
    .bind(util::now_rfc3339())
    .bind(instance.as_slice())
    .execute(pool)
    .await?
    .rows_affected();
    if created > 0 {
        tracing::warn!(
            created,
            "tenants without a bootstrap guard were set to recovery_required"
        );
    }
    Ok(created as usize)
}

/// Moves a guard to `recovery_required` when its confirmation disagrees with
/// it (R1 transition table). Rows are kept as they are for diagnosis.
async fn reconcile_guards(pool: &SqlitePool) -> Result<usize> {
    let moved = sqlx::query(
        "UPDATE v2_bootstrap_guards
            SET state = 'recovery_required', recovery_reason = 'inconsistent_confirmation',
                updated_at = ?
          WHERE state <> 'recovery_required'
            AND NOT CASE state
                WHEN 'unused' THEN NOT EXISTS (
                    SELECT 1 FROM v2_first_device_confirmations c
                     WHERE c.server_instance_id = v2_bootstrap_guards.server_instance_id
                       AND c.tenant_id = v2_bootstrap_guards.tenant_id)
                -- Reserved: its pending confirmation names a still-pending device.
                WHEN 'reserved' THEN EXISTS (
                    SELECT 1 FROM v2_first_device_confirmations c
                      JOIN v2_devices d ON d.tenant_id = c.tenant_id AND d.id = c.device_id
                     WHERE c.server_instance_id = v2_bootstrap_guards.server_instance_id
                       AND c.tenant_id = v2_bootstrap_guards.tenant_id
                       AND c.state = 'pending' AND d.status = 'pending')
                WHEN 'consumed' THEN EXISTS (
                    SELECT 1 FROM v2_first_device_confirmations c
                     WHERE c.server_instance_id = v2_bootstrap_guards.server_instance_id
                       AND c.tenant_id = v2_bootstrap_guards.tenant_id
                       AND c.state = 'consumed')
                -- Closed: only from a reservation, so its confirmation ended.
                WHEN 'closed' THEN EXISTS (
                    SELECT 1 FROM v2_first_device_confirmations c
                     WHERE c.server_instance_id = v2_bootstrap_guards.server_instance_id
                       AND c.tenant_id = v2_bootstrap_guards.tenant_id
                       AND c.state IN ('cancelled', 'invalidated'))
                END",
    )
    .bind(util::now_rfc3339())
    .execute(pool)
    .await?
    .rows_affected();
    if moved > 0 {
        tracing::warn!(
            moved,
            "bootstrap guards that disagree with their confirmation were set to recovery_required"
        );
    }
    Ok(moved as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::signing::Ed25519SigningKey as SigningKey;
    use sqlx::sqlite::SqlitePoolOptions;

    const INSTANCE: [u8; 16] = [7; 16];

    async fn pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .unwrap();
        shardx_team_server::run_migrations(&pool).await.unwrap();
        sqlx::query("INSERT INTO v2_tenants VALUES (?, 'acme', 'active', NULL, 't')")
            .bind([1u8; 16].as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO v2_accounts VALUES (?, ?, 'owner', 'x', NULL, 0, 'active', 't')")
            .bind([2u8; 16].as_slice())
            .bind([1u8; 16].as_slice())
            .execute(&pool)
            .await
            .unwrap();
        pool
    }

    fn identity() -> Verified {
        Verified {
            server_instance_id: INSTANCE,
            restore_epoch: 0,
            external_record_sha256: [0; 32],
        }
    }

    fn keys(seed: u8) -> ([u8; 32], [u8; 32]) {
        let spk = SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        (spk, [seed.wrapping_add(100); 32])
    }

    async fn insert_device(pool: &SqlitePool, id: u8, seed: u8, status: &str, hpke_id: [u8; 32]) {
        let (spk, hpk) = keys(seed);
        sqlx::query(
            "INSERT INTO v2_devices VALUES (?, ?, ?, x'aa', ?, ?, 1, ?, ?, 1, ?, NULL, 't')",
        )
        .bind([id; 16].as_slice())
        .bind([1u8; 16].as_slice())
        .bind([2u8; 16].as_slice())
        .bind(signing_key_id(&spk).as_slice())
        .bind(spk.as_slice())
        .bind(hpke_id.as_slice())
        .bind(hpk.as_slice())
        .bind(status)
        .execute(pool)
        .await
        .unwrap();
    }

    async fn status(pool: &SqlitePool, id: u8) -> (String, Option<String>) {
        sqlx::query_as(
            "SELECT d.status, q.reason FROM v2_devices d
               LEFT JOIN v2_device_quarantine q ON q.tenant_id = d.tenant_id AND q.device_id = d.id
              WHERE d.id = ?",
        )
        .bind([id; 16].as_slice())
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn insert_guard(pool: &SqlitePool, tenant: u8) {
        sqlx::query("INSERT INTO v2_bootstrap_guards VALUES (?, ?, 'unused', NULL, 't')")
            .bind(INSTANCE.as_slice())
            .bind([tenant; 16].as_slice())
            .execute(pool)
            .await
            .unwrap();
    }

    async fn set_guard(pool: &SqlitePool, tenant: u8, state: &str) {
        sqlx::query("UPDATE v2_bootstrap_guards SET state = ? WHERE tenant_id = ?")
            .bind(state)
            .bind([tenant; 16].as_slice())
            .execute(pool)
            .await
            .unwrap();
    }

    async fn guard(pool: &SqlitePool) -> (String, Option<String>) {
        sqlx::query_as("SELECT state, recovery_reason FROM v2_bootstrap_guards")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[test]
    fn key_checks_follow_r4() {
        let (spk, hpk) = keys(3);
        assert_eq!(
            derive_device_key_ids(1, &spk, 1, &hpk),
            Ok((signing_key_id(&spk), hpke_key_id(&hpk)))
        );
        // The two IDs use different domains even for the same bytes.
        assert_ne!(signing_key_id(&spk), hpke_key_id(&spk));
        for (ss, hs) in [(2, 1), (1, 2), (0, 1)] {
            assert_eq!(
                derive_device_key_ids(ss, &spk, hs, &hpk),
                Err(KeyFault::InvalidEncoding)
            );
        }
        // The identity point is small order.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert_eq!(
            derive_device_key_ids(1, &identity, 1, &hpk),
            Err(KeyFault::InvalidEncoding)
        );
    }

    #[tokio::test]
    async fn wrong_domain_hpke_ids_are_quarantined_once() {
        let pool = pool().await;
        let (_, good_hpk) = keys(4);
        insert_device(&pool, 4, 4, "pending", hpke_key_id(&good_hpk)).await;
        // The historical bug: the HPKE ID derived under the signing domain.
        let (_, bad_hpk) = keys(5);
        insert_device(&pool, 5, 5, "pending", signing_key_id(&bad_hpk)).await;

        let report = run(&pool, &identity()).await.unwrap();
        assert_eq!(report.quarantined_devices, 1);
        assert_eq!(status(&pool, 4).await, ("pending".into(), None));
        assert_eq!(
            status(&pool, 5).await,
            ("quarantined".into(), Some("key_id_mismatch".into()))
        );
        // A second run finds nothing new and rewrites nothing.
        assert_eq!(
            run(&pool, &identity()).await.unwrap().quarantined_devices,
            0
        );
    }

    #[tokio::test]
    async fn quarantine_ends_bootstrap_and_survives_a_later_revocation() {
        let pool = pool().await;
        insert_guard(&pool, 1).await;
        let (_, hpk) = keys(5);
        insert_device(&pool, 5, 5, "pending", signing_key_id(&hpk)).await;
        // A session and an open challenge of that device.
        for sql in [
            "INSERT INTO v2_pre_device_sessions (id, token_hash, server_instance_id, \
             restore_epoch, tenant_id, account_id, account_token_version, created_at_ms, \
             expires_at_ms) VALUES (x'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', randomblob(32), \
             zeroblob(16), 0, ?1, ?2, 0, 1, 600001)",
            "INSERT INTO v2_device_session_challenges (id, pre_device_session_id, tenant_id, \
             account_id, device_id, binding_bytes, secret_hash, created_at_ms, expires_at_ms) \
             VALUES (x'0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b', x'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', \
             ?1, ?2, ?3, x'aa', zeroblob(32), 1, 120001)",
            "INSERT INTO v2_device_session_challenges (id, pre_device_session_id, tenant_id, \
             account_id, device_id, binding_bytes, secret_hash, created_at_ms, expires_at_ms, \
             consumed_at_ms) VALUES (x'0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c', \
             x'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', ?1, ?2, ?3, x'aa', zeroblob(32), 1, 120001, 2)",
            "INSERT INTO v2_sessions (id, tenant_id, account_id, device_id, server_instance_id, \
             restore_epoch, signing_key_id, hpke_key_id, account_token_version, class, \
             pre_device_session_id, device_session_challenge_id, pop_at_ms, access_token_hash, \
             access_expires_at_ms, refresh_token_hash, refresh_expires_at_ms, \
             absolute_expires_at_ms) VALUES (x'0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d0d', ?1, ?2, ?3, \
             zeroblob(16), 0, zeroblob(32), randomblob(32), 0, 'pending_setup', \
             x'0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a', x'0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c', 2, \
             randomblob(32), 300002, randomblob(32), 1800002, 1800002)",
        ] {
            sqlx::query(sql)
                .bind([1u8; 16].as_slice())
                .bind([2u8; 16].as_slice())
                .bind([5u8; 16].as_slice())
                .execute(&pool)
                .await
                .unwrap();
        }
        assert_eq!(
            run(&pool, &identity()).await.unwrap().quarantined_devices,
            1
        );
        assert_eq!(
            guard(&pool).await,
            ("recovery_required".into(), Some("integrity_failure".into()))
        );
        let revoked: (i64, i64) = sqlx::query_as(
            "SELECT (SELECT count(*) FROM v2_sessions WHERE revoked_at_ms IS NOT NULL),
                    (SELECT count(*) FROM v2_device_session_challenges
                      WHERE revoked_at_ms IS NOT NULL)",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        // The open challenge and the session end; the consumed challenge stays.
        assert_eq!(revoked, (1, 1));

        // Revoked later, the device is not quarantined again: that second
        // record would collide and stop the server at startup.
        sqlx::query("UPDATE v2_devices SET status = 'revoked'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            run(&pool, &identity()).await.unwrap().quarantined_devices,
            0
        );
        assert_eq!(
            status(&pool, 5).await,
            ("revoked".into(), Some("key_id_mismatch".into()))
        );
    }

    #[tokio::test]
    async fn a_reserved_guard_whose_device_left_pending_goes_to_recovery() {
        let pool = pool().await;
        let (spk, hpk) = keys(4);
        insert_device(&pool, 4, 4, "pending", hpke_key_id(&hpk)).await;
        insert_guard(&pool, 1).await;
        sqlx::query(
            "INSERT INTO v2_first_device_confirmations
                 (server_instance_id, tenant_id, confirmation_id, account_id, device_id,
                  request_id, restore_epoch, confirmed_at_ms, signing_key_id, hpke_key_id,
                  signing_public_key, hpke_public_key, signing_suite, hpke_suite, state)
             VALUES (?, ?, ?, ?, ?, ?, 0, 1, ?, ?, ?, ?, 1, 1, 'pending')",
        )
        .bind(INSTANCE.as_slice())
        .bind([1u8; 16].as_slice())
        .bind([3u8; 16].as_slice())
        .bind([2u8; 16].as_slice())
        .bind([4u8; 16].as_slice())
        .bind([6u8; 16].as_slice())
        .bind(signing_key_id(&spk).as_slice())
        .bind(hpke_key_id(&hpk).as_slice())
        .bind(spk.as_slice())
        .bind(hpk.as_slice())
        .execute(&pool)
        .await
        .unwrap();
        set_guard(&pool, 1, "reserved").await;
        assert_eq!(run(&pool, &identity()).await.unwrap().guards_to_recovery, 0);

        sqlx::query("UPDATE v2_devices SET status = 'revoked'")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(run(&pool, &identity()).await.unwrap().guards_to_recovery, 1);
        assert_eq!(
            guard(&pool).await,
            (
                "recovery_required".into(),
                Some("inconsistent_confirmation".into())
            )
        );
    }

    #[tokio::test]
    async fn a_tenant_without_a_guard_is_never_unused() {
        let pool = pool().await;
        let report = run(&pool, &identity()).await.unwrap();
        assert_eq!(report.guards_created, 1);
        let state: (String, Option<String>) = sqlx::query_as(
            "SELECT state, recovery_reason FROM v2_bootstrap_guards WHERE server_instance_id = ?",
        )
        .bind(INSTANCE.as_slice())
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(
            state,
            ("recovery_required".into(), Some("missing_guard".into()))
        );
        assert_eq!(run(&pool, &identity()).await.unwrap().guards_created, 0);
    }

    #[tokio::test]
    async fn a_guard_without_its_confirmation_goes_to_recovery() {
        let pool = pool().await;
        for (tenant, slug, states) in [
            (1u8, None, &["reserved"][..]),
            (9, Some("other"), &[][..]),
            (10, Some("closed"), &["reserved", "closed"][..]),
        ] {
            if let Some(slug) = slug {
                sqlx::query("INSERT INTO v2_tenants VALUES (?, ?, 'active', NULL, 't')")
                    .bind([tenant; 16].as_slice())
                    .bind(slug)
                    .execute(&pool)
                    .await
                    .unwrap();
            }
            insert_guard(&pool, tenant).await;
            for state in states {
                set_guard(&pool, tenant, state).await;
            }
        }
        let report = run(&pool, &identity()).await.unwrap();
        assert_eq!(report.guards_to_recovery, 2);
        let states: Vec<(Vec<u8>, String)> =
            sqlx::query_as("SELECT tenant_id, state FROM v2_bootstrap_guards ORDER BY tenant_id")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(
            states,
            vec![
                ([1u8; 16].to_vec(), "recovery_required".into()),
                ([9u8; 16].to_vec(), "unused".into()),
                ([10u8; 16].to_vec(), "recovery_required".into())
            ]
        );
    }

    #[tokio::test]
    async fn a_broken_reference_turns_v2_writes_off() {
        let pool = pool().await;
        sqlx::query("PRAGMA foreign_keys = OFF")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO v2_bootstrap_guards VALUES (?, ?, 'unused', NULL, 't')")
            .bind(INSTANCE.as_slice())
            .bind([8u8; 16].as_slice())
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&pool)
            .await
            .unwrap();
        let report = run(&pool, &identity()).await.unwrap();
        assert_eq!(report.foreign_key_violations, 1);
        assert_eq!(
            report.refusal().map(|r| r.code.as_str()),
            Some("CONTROL_PLANE_INTEGRITY_UNTRUSTED")
        );
    }
}
