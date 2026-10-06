//! Durability of the v2 schema on a real filesystem.
//!
//! In-memory SQLite cannot prove any of this: it never writes a file, never
//! checkpoints, and never reopens. Plan 11.3 therefore requires the workflow
//! probes to close and reopen a real database so the assertions cover what
//! actually survives a process exit — persisted values, constraint definitions,
//! and the extreme ends of the wire-integer domain.

use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Row, SqlitePool};
use std::str::FromStr;

fn id(byte: u8) -> Vec<u8> {
    vec![byte; 16]
}

fn key32(byte: u8) -> Vec<u8> {
    vec![byte; 32]
}

/// Open the same on-disk database the server would, including the pragmas the
/// isolation guarantees depend on. Reopening through this function is what
/// makes the "survives a restart" claim real.
async fn open(path: &std::path::Path) -> SqlitePool {
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
        .unwrap()
        .create_if_missing(true)
        .foreign_keys(true)
        .busy_timeout(std::time::Duration::from_secs(5));
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .unwrap();
    shardx_team_server::run_migrations_fk_safe(&pool)
        .await
        .unwrap();
    pool
}

/// A scratch directory that cleans up after itself.
struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "shardx-v2-durability-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn db(&self) -> std::path::PathBuf {
        self.0.join("server.db")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn seed_profile_chain(pool: &SqlitePool) {
    sqlx::query(
        "INSERT INTO v2_tenants (id, slug, status, active_root_generation, created_at)
         VALUES (?, 'tenant-a', 'active', 1, '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(1))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_fleets (id, tenant_id, name, status, created_at)
         VALUES (?, ?, 'fleet-a', 'active', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(10))
    .bind(id(1))
    .execute(pool)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, current_version, status, created_at, updated_at)
         VALUES (?, ?, ?, 'profile-a', 0, 'active', '2026-09-02T00:00:00+00:00', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(20))
    .bind(id(1))
    .bind(id(10))
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn max_i64_wire_values_survive_close_and_reopen() {
    // The top of the wire-integer domain is exactly where a silent truncation
    // or float round-trip would show up, and only a real file can prove the
    // value came back off disk rather than out of a cache.
    let tmp = TempDir::new("maxint");
    let db = tmp.db();

    {
        let pool = open(&db).await;
        seed_profile_chain(&pool).await;
        sqlx::query(
            "INSERT INTO v2_leases (id, tenant_id, profile_id, holder_account_id, holder_device_id,
                fencing_token, base_version, server_instance_id, restore_epoch, acquired_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '2026-09-02T00:00:00+00:00', '2026-09-02T01:00:00+00:00')",
        )
        .bind(id(30))
        .bind(id(1))
        .bind(id(20))
        .bind(id(40))
        .bind(id(50))
        .bind(i64::MAX)
        .bind(i64::MAX)
        .bind(id(60))
        .bind(i64::MAX)
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }

    let pool = open(&db).await;
    let row = sqlx::query(
        "SELECT fencing_token, base_version, restore_epoch FROM v2_leases WHERE id = ?",
    )
    .bind(id(30))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.get::<i64, _>("fencing_token"), i64::MAX);
    assert_eq!(row.get::<i64, _>("base_version"), i64::MAX);
    assert_eq!(row.get::<i64, _>("restore_epoch"), i64::MAX);
    pool.close().await;
}

#[tokio::test]
async fn exact_signed_bytes_round_trip_byte_for_byte() {
    // Signature verification runs against the stored bytes. If storage mutated
    // them at all — encoding, padding, truncation — every later verification
    // would fail in a way that looks like a bad signature.
    let tmp = TempDir::new("bytes");
    let db = tmp.db();

    // Deliberately nasty payload: embedded NULs and high bytes, which a TEXT
    // column or a naive encoder would corrupt.
    let payload: Vec<u8> = (0..=255u8).chain(0..=255u8).collect();

    {
        let pool = open(&db).await;
        seed_profile_chain(&pool).await;
        sqlx::query(
            "INSERT INTO v2_snapshot_manifests (tenant_id, profile_id, version, snapshot_id, fleet_id,
                base_version, key_generation, restore_epoch, server_instance_id, fencing_token,
                intent_hash, container_sha256, container_size, blob_path, author_account_id,
                author_device_id, signature_bytes, issuer_signing_key_id, signed_container_hash,
                exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at)
             VALUES (?, ?, 1, ?, ?, 0, 1, 1, ?, 1, ?, ?, 512, 'blob', ?, ?, ?, ?, ?, ?, ?,
                     '2026-09-02T00:00:00+00:00')",
        )
        .bind(id(1))
        .bind(id(20))
        .bind(id(70))
        .bind(id(10))
        .bind(id(60))
        .bind(key32(1))
        .bind(key32(2))
        .bind(id(40))
        .bind(id(50))
        .bind(vec![0xABu8; 64])
        .bind(key32(3))
        .bind(key32(4))
        .bind(payload.clone())
        .bind(key32(5))
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }

    let pool = open(&db).await;
    let row = sqlx::query(
        "SELECT exact_signed_container_bytes, signature_bytes FROM v2_snapshot_manifests
         WHERE tenant_id = ? AND profile_id = ? AND version = 1",
    )
    .bind(id(1))
    .bind(id(20))
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        row.get::<Vec<u8>, _>("exact_signed_container_bytes"),
        payload,
        "stored container bytes must return byte-identical"
    );
    assert_eq!(row.get::<Vec<u8>, _>("signature_bytes"), vec![0xABu8; 64]);
    pool.close().await;
}

#[tokio::test]
async fn constraints_still_bind_after_reopen() {
    // A constraint that only holds in the session that created the schema
    // would be worthless. Re-check the isolation FK against a reopened file.
    let tmp = TempDir::new("constraints");
    let db = tmp.db();

    {
        let pool = open(&db).await;
        seed_profile_chain(&pool).await;
        pool.close().await;
    }

    let pool = open(&db).await;
    sqlx::query(
        "INSERT INTO v2_tenants (id, slug, status, active_root_generation, created_at)
         VALUES (?, 'tenant-b', 'active', 1, '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(2))
    .execute(&pool)
    .await
    .unwrap();

    // Tenant B pointing at tenant A's fleet, on a database that was written by
    // an earlier process.
    let err = sqlx::query(
        "INSERT INTO v2_profiles (id, tenant_id, fleet_id, name, current_version, status, created_at, updated_at)
         VALUES (?, ?, ?, 'x', 0, 'active', '2026-09-02T00:00:00+00:00', '2026-09-02T00:00:00+00:00')",
    )
    .bind(id(21))
    .bind(id(2))
    .bind(id(10))
    .execute(&pool)
    .await
    .unwrap_err();
    let code = match err {
        sqlx::Error::Database(d) => d.code().map(|c| c.to_string()).unwrap_or_default(),
        other => panic!("expected database error, got {other:?}"),
    };
    assert_eq!(code, "787", "composite FK must survive a reopen");
    pool.close().await;
}

#[tokio::test]
async fn a_live_lease_still_blocks_a_second_checkout_after_reopen() {
    // The partial unique index is the anti-double-checkout guarantee; prove it
    // is persisted in the schema rather than being a session-local artifact.
    let tmp = TempDir::new("lease");
    let db = tmp.db();

    {
        let pool = open(&db).await;
        seed_profile_chain(&pool).await;
        sqlx::query(
            "INSERT INTO v2_leases (id, tenant_id, profile_id, holder_account_id, holder_device_id,
                fencing_token, base_version, server_instance_id, restore_epoch, acquired_at, expires_at)
             VALUES (?, ?, ?, ?, ?, 1, 0, ?, 1, '2026-09-02T00:00:00+00:00', '2026-09-02T01:00:00+00:00')",
        )
        .bind(id(30))
        .bind(id(1))
        .bind(id(20))
        .bind(id(40))
        .bind(id(50))
        .bind(id(60))
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;
    }

    let pool = open(&db).await;
    let err = sqlx::query(
        "INSERT INTO v2_leases (id, tenant_id, profile_id, holder_account_id, holder_device_id,
            fencing_token, base_version, server_instance_id, restore_epoch, acquired_at, expires_at)
         VALUES (?, ?, ?, ?, ?, 2, 0, ?, 1, '2026-09-02T00:00:00+00:00', '2026-09-02T01:00:00+00:00')",
    )
    .bind(id(31))
    .bind(id(1))
    .bind(id(20))
    .bind(id(41))
    .bind(id(51))
    .bind(id(60))
    .execute(&pool)
    .await
    .unwrap_err();
    let code = match err {
        sqlx::Error::Database(d) => d.code().map(|c| c.to_string()).unwrap_or_default(),
        other => panic!("expected database error, got {other:?}"),
    };
    assert_eq!(code, "2067", "one-live-lease index must survive a reopen");
    pool.close().await;
}

#[tokio::test]
async fn an_uncommitted_transaction_leaves_nothing_behind() {
    // Stands in for an unclean close: work that never committed must not be
    // visible to the next process to open the file.
    let tmp = TempDir::new("rollback");
    let db = tmp.db();

    {
        let pool = open(&db).await;
        seed_profile_chain(&pool).await;

        let mut tx = pool.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO v2_snapshot_manifests (tenant_id, profile_id, version, snapshot_id, fleet_id,
                base_version, key_generation, restore_epoch, server_instance_id, fencing_token,
                intent_hash, container_sha256, container_size, blob_path, author_account_id,
                author_device_id, signature_bytes, issuer_signing_key_id, signed_container_hash,
                exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at)
             VALUES (?, ?, 7, ?, ?, 0, 1, 1, ?, 1, ?, ?, 1, 'b', ?, ?, ?, ?, ?, X'00', ?,
                     '2026-09-02T00:00:00+00:00')",
        )
        .bind(id(1))
        .bind(id(20))
        .bind(id(70))
        .bind(id(10))
        .bind(id(60))
        .bind(key32(1))
        .bind(key32(2))
        .bind(id(40))
        .bind(id(50))
        .bind(vec![0u8; 64])
        .bind(key32(3))
        .bind(key32(4))
        .bind(key32(5))
        .execute(&mut *tx)
        .await
        .unwrap();
        // Drop without commit — the transaction rolls back.
        drop(tx);
        pool.close().await;
    }

    let pool = open(&db).await;
    let count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM v2_snapshot_manifests WHERE version = 7")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0, "rolled-back manifest must not be durable");
    pool.close().await;
}

#[tokio::test]
async fn migrations_are_idempotent_across_reopens() {
    // Every server start runs the migrator. Reopening repeatedly must not
    // re-apply, duplicate, or fail.
    let tmp = TempDir::new("idempotent");
    let db = tmp.db();

    for _ in 0..3 {
        let pool = open(&db).await;
        pool.close().await;
    }

    let pool = open(&db).await;
    let applied: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&pool)
        .await
        .unwrap();
    let files = std::fs::read_dir("./migrations")
        .unwrap()
        .filter(|e| {
            e.as_ref()
                .map(|e| e.path().extension().is_some_and(|x| x == "sql"))
                .unwrap_or(false)
        })
        .count() as i64;
    assert_eq!(
        applied, files,
        "each migration file should be applied exactly once"
    );
    pool.close().await;
}
