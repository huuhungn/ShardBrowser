//! A database migrated by a build whose checkout had CRLF migration files must
//! keep working after the files are pinned to LF, and nothing else may pass.
use shardx_team_server::run_migrations_fk_safe_with;
use sqlx::migrate::{Migration, Migrator};
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;
use std::borrow::Cow;

fn with_sql(edit: impl Fn(&str) -> String) -> Migrator {
    let migrations = sqlx::migrate!("./migrations")
        .iter()
        .map(|m| {
            Migration::new(
                m.version,
                m.description.clone(),
                m.migration_type,
                Cow::Owned(edit(&m.sql.replace("\r\n", "\n"))),
                m.no_tx,
            )
        })
        .collect::<Vec<_>>();
    Migrator {
        migrations: Cow::Owned(migrations),
        ..Migrator::DEFAULT
    }
}

fn lf() -> Migrator {
    with_sql(|sql| sql.to_string())
}

fn crlf() -> Migrator {
    with_sql(|sql| sql.replace('\n', "\r\n"))
}

async fn pool() -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

async fn stored_checksums(pool: &SqlitePool) -> Vec<(i64, Vec<u8>)> {
    sqlx::query_as("SELECT version, checksum FROM _sqlx_migrations ORDER BY version")
        .fetch_all(pool)
        .await
        .unwrap()
}

fn expected_checksums(migrator: &Migrator) -> Vec<(i64, Vec<u8>)> {
    migrator
        .iter()
        .map(|m| (m.version, m.checksum.to_vec()))
        .collect()
}

#[tokio::test]
async fn lf_build_accepts_a_database_migrated_by_a_crlf_build() {
    let pool = pool().await;
    run_migrations_fk_safe_with(&pool, &crlf()).await.unwrap();
    assert_eq!(stored_checksums(&pool).await, expected_checksums(&crlf()));

    run_migrations_fk_safe_with(&pool, &lf()).await.unwrap();

    assert_eq!(stored_checksums(&pool).await, expected_checksums(&lf()));
    // A second start with the same build is a no-op.
    run_migrations_fk_safe_with(&pool, &lf()).await.unwrap();
}

#[tokio::test]
async fn an_edited_migration_is_still_refused() {
    let pool = pool().await;
    run_migrations_fk_safe_with(&pool, &crlf()).await.unwrap();
    let before = stored_checksums(&pool).await;
    let edited = with_sql(|sql| format!("{sql}\n-- edited after it was applied\n"));

    let error = run_migrations_fk_safe_with(&pool, &edited)
        .await
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("was previously applied but has been modified"),
        "{error}"
    );
    assert_eq!(stored_checksums(&pool).await, before);
}
