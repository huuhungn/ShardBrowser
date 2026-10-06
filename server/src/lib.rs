use sha2::{Digest, Sha384};
use sqlx::migrate::Migrator;
use sqlx::{Connection, SqliteConnection, SqlitePool};

/// Apply migrations on a dedicated connection with foreign-key enforcement
/// disabled before SQLx opens each migration transaction.
///
/// SQLite ignores `PRAGMA foreign_keys = OFF` once a transaction is active,
/// while sqlx-sqlite 0.8.x always starts one for a migration. Migration 0009
/// contains a fail-closed guard; this runner is the only path that disables
/// enforcement before the rebuild begins, then restores the connection's
/// previous setting even if the migration fails, so a pooled connection is
/// never handed back with enforcement silently changed.
pub async fn run_migrations_fk_safe(pool: &SqlitePool) -> anyhow::Result<()> {
    run_migrations_fk_safe_with(pool, &sqlx::migrate!("./migrations")).await
}

/// Testable form of [`run_migrations_fk_safe`] for a staged migration set.
pub async fn run_migrations_fk_safe_with(
    pool: &SqlitePool,
    migrator: &Migrator,
) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    adopt_line_ending_checksums(&mut conn, migrator).await?;

    let previous: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&mut *conn)
        .await?;
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await?;

    let migration_result = migrator.run_direct(&mut *conn).await;
    let restore = if previous == 0 {
        "PRAGMA foreign_keys = OFF"
    } else {
        "PRAGMA foreign_keys = ON"
    };
    let restore_result = sqlx::query(restore).execute(&mut *conn).await;

    migration_result?;
    restore_result?;
    Ok(())
}

/// SQLx checksums the raw migration text. Before `.gitattributes` pinned the
/// migrations to LF, a Windows checkout with `core.autocrlf` embedded them
/// with CRLF, so a database migrated by that build stored CRLF checksums and
/// an LF build would refuse it as modified. Re-record a stored checksum only
/// when it equals this migration's text with the other line ending; any other
/// difference is left for SQLx to refuse.
async fn adopt_line_ending_checksums(
    conn: &mut SqliteConnection,
    migrator: &Migrator,
) -> anyhow::Result<()> {
    let has_table: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master \
         WHERE type = 'table' AND name = '_sqlx_migrations')",
    )
    .fetch_one(&mut *conn)
    .await?;
    if !has_table {
        return Ok(());
    }

    let mut tx = conn.begin().await?;
    for migration in migrator.iter() {
        let lf = migration.sql.replace("\r\n", "\n");
        let crlf = lf.replace('\n', "\r\n");
        for variant in [lf, crlf] {
            let alternate = Sha384::digest(variant.as_bytes()).to_vec();
            if alternate.as_slice() == migration.checksum.as_ref() {
                continue;
            }
            let adopted = sqlx::query(
                "UPDATE _sqlx_migrations SET checksum = ? WHERE version = ? AND checksum = ?",
            )
            .bind(migration.checksum.as_ref())
            .bind(migration.version)
            .bind(&alternate)
            .execute(&mut *tx)
            .await?
            .rows_affected();
            if adopted > 0 {
                tracing::warn!(
                    version = migration.version,
                    "re-recorded a migration checksum that differed only in line endings"
                );
            }
        }
    }
    tx.commit().await?;
    Ok(())
}
