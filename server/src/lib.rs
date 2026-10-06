use sqlx::migrate::Migrator;
use sqlx::SqlitePool;

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
