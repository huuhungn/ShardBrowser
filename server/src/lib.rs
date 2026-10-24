use std::borrow::Cow;
use std::collections::HashMap;

use sha2::{Digest, Sha384};
use sqlx::migrate::{Migration, Migrator};
use sqlx::{SqliteConnection, SqlitePool};

pub mod identity_record;

/// Apply the embedded migrations, accepting a database whose applied
/// migrations were checksummed with the other line ending.
pub async fn run_migrations(pool: &SqlitePool) -> anyhow::Result<()> {
    run_migrations_with(pool, &sqlx::migrate!("./migrations")).await
}

/// Testable form of [`run_migrations`] for a staged migration set.
///
/// SQLx checksums the raw migration text. Before `.gitattributes` pinned the
/// migrations to LF, a Windows checkout with `core.autocrlf` embedded them with
/// CRLF (the published Windows server did), so its databases hold CRLF
/// checksums that an LF build refuses as modified. For each applied migration
/// whose stored checksum matches this migration's text with the other line
/// ending, run with that variant instead. The database is never rewritten, so
/// the build that created it can still open it. Any other difference is left
/// for SQLx to refuse.
///
/// Migrations run on one connection with foreign-key enforcement disabled
/// before SQLx opens each migration transaction: SQLite ignores
/// `PRAGMA foreign_keys = OFF` once a transaction is active, and 0009 rebuilds
/// `v2_tenants` behind a fail-closed guard. The connection's previous setting
/// is restored even if a migration fails, so a pooled connection is never
/// handed back with enforcement silently changed.
pub async fn run_migrations_with(pool: &SqlitePool, migrator: &Migrator) -> anyhow::Result<()> {
    let mut conn = pool.acquire().await?;
    let stored = stored_checksums(&mut conn).await?;
    let migrations = migrator
        .iter()
        .map(|m| match stored.get(&m.version) {
            Some(checksum) if checksum.as_slice() != m.checksum.as_ref() => {
                line_ending_variant(m, checksum).unwrap_or_else(|| m.clone())
            }
            _ => m.clone(),
        })
        .collect::<Vec<_>>();
    let adapted = Migrator {
        migrations: Cow::Owned(migrations),
        ignore_missing: migrator.ignore_missing,
        locking: migrator.locking,
        no_tx: migrator.no_tx,
    };

    let previous: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&mut *conn)
        .await?;
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&mut *conn)
        .await?;
    let migration_result = adapted.run_direct(&mut *conn).await;
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

async fn stored_checksums(conn: &mut SqliteConnection) -> anyhow::Result<HashMap<i64, Vec<u8>>> {
    let has_table: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM sqlite_master \
         WHERE type = 'table' AND name = '_sqlx_migrations')",
    )
    .fetch_one(&mut *conn)
    .await?;
    if !has_table {
        return Ok(HashMap::new());
    }
    let rows: Vec<(i64, Vec<u8>)> =
        sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations")
            .fetch_all(&mut *conn)
            .await?;
    Ok(rows.into_iter().collect())
}

fn line_ending_variant(m: &Migration, stored: &[u8]) -> Option<Migration> {
    let lf = m.sql.replace("\r\n", "\n");
    let crlf = lf.replace('\n', "\r\n");
    let sql = [lf, crlf]
        .into_iter()
        .find(|variant| Sha384::digest(variant.as_bytes()).as_slice() == stored)?;
    tracing::debug!(
        version = m.version,
        "running a migration with the line endings its stored checksum was recorded with"
    );
    Some(Migration::new(
        m.version,
        m.description.clone(),
        m.migration_type,
        Cow::Owned(sql),
        m.no_tx,
    ))
}
