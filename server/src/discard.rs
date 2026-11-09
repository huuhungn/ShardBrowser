//! `fleet discard-preparing` and `root discard-preparing` (ADR 0002 Q-60):
//! offline, an operator removes a stuck PREPARING generation N+1 so the
//! number can be created again. Every removed row is archived first in
//! `v2_discarded_records`; the delete triggers allow it only under the
//! marker row this command writes inside its one transaction. Idempotency and
//! replay rows stay: a replayed create gets its stored reply, and the
//! launcher's next step finds no such generation.

use anyhow::{bail, ensure, Context, Result};
use sqlx::SqliteConnection;

use crate::config::Config;
use crate::identity::hex;
use crate::{audit, bootstrap, db, restore, util};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Fleet,
    Root,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Fleet => "fleet",
            Kind::Root => "root",
        }
    }
}

/// One table's rows to archive and delete, in delete order.
struct Rows {
    table: &'static str,
    /// SQL condition on the table's own columns, its values inlined: every
    /// one is an integer or a blob this command read or parsed.
    filter: String,
}

/// The quarantine marks of the `grants` rows `scope` names, of `kind`.
fn quarantined(instance: &[u8], tenant: &[u8], kind: &str, grants: &str, scope: &str) -> Rows {
    Rows {
        table: "v2_grant_quarantine",
        filter: format!(
            "kind = '{kind}' AND server_instance_id = x'{}' AND tenant_id = x'{}' \
             AND replay_id IN (SELECT replay_id FROM {grants} WHERE {scope})",
            hex(instance),
            hex(tenant)
        ),
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Copies every row `rows` names into the archive as JSON (blobs as hex),
/// then deletes them. Returns how many rows went.
async fn archive_and_delete(
    conn: &mut SqliteConnection,
    tenant: &[u8],
    kind: Kind,
    generation: i64,
    rows: &Rows,
    at: &str,
) -> Result<u64> {
    let columns: Vec<String> = sqlx::query_scalar("SELECT name FROM pragma_table_info(?)")
        .bind(rows.table)
        .fetch_all(&mut *conn)
        .await?;
    ensure!(!columns.is_empty(), "no table {}", rows.table);
    let pairs: Vec<String> = columns
        .iter()
        .map(|c| {
            format!("'{c}', CASE typeof(\"{c}\") WHEN 'blob' THEN hex(\"{c}\") ELSE \"{c}\" END")
        })
        .collect();
    let copied = sqlx::query(&format!(
        "INSERT INTO v2_discarded_records
             (tenant_id, kind, generation, source_table, row_json, discarded_at)
         SELECT ?, ?, ?, ?, json_object({}), ? FROM {} WHERE {}",
        pairs.join(", "),
        rows.table,
        rows.filter
    ))
    .bind(tenant)
    .bind(kind.as_str())
    .bind(generation)
    .bind(rows.table)
    .bind(at)
    .execute(&mut *conn)
    .await?
    .rows_affected();
    let deleted = sqlx::query(&format!("DELETE FROM {} WHERE {}", rows.table, rows.filter))
        .execute(&mut *conn)
        .await
        .with_context(|| format!("deleting from {}", rows.table))?
        .rows_affected();
    ensure!(
        copied == deleted,
        "{} changed during the discard",
        rows.table
    );
    Ok(deleted)
}

/// Archives and deletes PREPARING generation `generation` of the tenant
/// `slug`'s fleet (`fleet` names it when several fleets have that
/// generation) or root, with its grants. The caller holds the lock.
pub async fn discard_preparing(
    cfg: &Config,
    kind: Kind,
    slug: &str,
    generation: u64,
    fleet: Option<[u8; 16]>,
    force: bool,
) -> Result<()> {
    restore::require_clean(cfg).await?;
    let verified = bootstrap::verified_identity(cfg).await?;
    let instance = verified.server_instance_id.to_vec();
    let n = i64::try_from(generation).context("--generation is out of range")?;
    let pool = db::init_pool(cfg).await?;
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let tenant = bootstrap::tenant_id(&mut tx, slug).await?;
    let own = format!(
        "server_instance_id = x'{}' AND tenant_id = x'{}'",
        hex(&instance),
        hex(&tenant)
    );

    // The target: PREPARING, one above the ACTIVE generation.
    let (key_id, rows) = match kind {
        Kind::Fleet => {
            let found: Vec<(Vec<u8>, String, Vec<u8>)> = sqlx::query_as(
                "SELECT fleet_id, state, fkek_key_id FROM v2_fleet_key_generations
                  WHERE server_instance_id = ? AND tenant_id = ? AND generation = ?
                    AND (? IS NULL OR fleet_id = ?)",
            )
            .bind(&instance)
            .bind(&tenant)
            .bind(n)
            .bind(fleet.map(|f| f.to_vec()))
            .bind(fleet.map(|f| f.to_vec()))
            .fetch_all(&mut *tx)
            .await?;
            let (fleet_id, state, key_id) = match found.as_slice() {
                [] => bail!("refusing: no fleet key generation {generation} in this tenant"),
                [one] => one.clone(),
                _ => bail!(
                    "refusing: several fleets have a generation {generation}; name one with --fleet"
                ),
            };
            ensure!(
                state == "PREPARING",
                "refusing: fleet key generation {generation} is {state}, not PREPARING"
            );
            let active: Option<i64> = sqlx::query_scalar(
                "SELECT generation FROM v2_fleet_key_generations
                  WHERE server_instance_id = ? AND tenant_id = ? AND fleet_id = ?
                    AND state = 'ACTIVE'",
            )
            .bind(&instance)
            .bind(&tenant)
            .bind(&fleet_id)
            .fetch_optional(&mut *tx)
            .await?;
            ensure!(
                active.is_some_and(|a| a.checked_add(1) == Some(n)),
                "refusing: fleet key generation {generation} is not the ACTIVE generation + 1"
            );
            // A launcher whose rotation is still inside its window may still
            // finish it; past the window it has stopped with rotationStuck.
            let open_until: Option<i64> = sqlx::query_scalar(
                "SELECT max(not_after_ms) FROM v2_fleet_rotation_grants
                  WHERE server_instance_id = ? AND tenant_id = ? AND fleet_id = ?
                    AND generation = ?",
            )
            .bind(&instance)
            .bind(&tenant)
            .bind(&fleet_id)
            .bind(n)
            .fetch_one(&mut *tx)
            .await?;
            // With no rotation grant filed yet, the launcher may still be
            // preparing its run: its window has not even started.
            let open = match open_until {
                None => Some("no rotation grant is filed yet".to_string()),
                Some(until) if until > now_ms() => Some(format!("until {until} (ms)")),
                Some(_) => None,
            };
            if let Some(why) = open {
                ensure!(
                    force,
                    "refusing: the rotation's grant window is open ({why}); \
                     wait for it to end or pass --force"
                );
            }
            let scope = format!(
                "{own} AND fleet_id = x'{}' AND generation = {n}",
                hex(&fleet_id)
            );
            let mut rows = Vec::new();
            for (table, quarantine) in [
                ("v2_fleet_device_hpke_grants", "fleet_device_hpke_grant"),
                ("v2_fleet_recovery_grants", "fleet_recovery_grant"),
                ("v2_fleet_rotation_grants", "fleet_rotation_grant"),
            ] {
                rows.push(quarantined(&instance, &tenant, quarantine, table, &scope));
                rows.push(Rows {
                    table,
                    filter: scope.clone(),
                });
            }
            rows.push(Rows {
                table: "v2_fleet_key_generations",
                filter: scope,
            });
            (key_id, rows)
        }
        Kind::Root => {
            let (state, key_id): (String, Vec<u8>) = sqlx::query_as(
                "SELECT state, root_key_id FROM v2_root_key_generations
                  WHERE server_instance_id = ? AND tenant_id = ? AND generation = ?",
            )
            .bind(&instance)
            .bind(&tenant)
            .bind(n)
            .fetch_optional(&mut *tx)
            .await?
            .with_context(|| {
                format!("refusing: no root key generation {generation} in this tenant")
            })?;
            ensure!(
                state == "PREPARING",
                "refusing: root key generation {generation} is {state}, not PREPARING"
            );
            let active: Option<i64> = sqlx::query_scalar(
                "SELECT generation FROM v2_root_key_generations
                  WHERE server_instance_id = ? AND tenant_id = ? AND state = 'ACTIVE'",
            )
            .bind(&instance)
            .bind(&tenant)
            .fetch_optional(&mut *tx)
            .await?;
            ensure!(
                active.is_some_and(|a| a.checked_add(1) == Some(n)),
                "refusing: root key generation {generation} is not the ACTIVE generation + 1"
            );
            // The fleet recovery grants wrapped under N+1 name it (FK 0020).
            let wrapped = format!(
                "{own} AND recipient_root_generation = {n} AND recipient_root_key_id = x'{}'",
                hex(&key_id)
            );
            let grants = format!("{own} AND root_generation = {n}");
            let rows = vec![
                quarantined(
                    &instance,
                    &tenant,
                    "fleet_recovery_grant",
                    "v2_fleet_recovery_grants",
                    &wrapped,
                ),
                Rows {
                    table: "v2_fleet_recovery_grants",
                    filter: wrapped.clone(),
                },
                quarantined(
                    &instance,
                    &tenant,
                    "root_grant",
                    "v2_tenant_root_key_grants",
                    &grants,
                ),
                Rows {
                    table: "v2_tenant_root_key_grants",
                    filter: grants,
                },
                Rows {
                    table: "v2_root_key_generations",
                    filter: format!("{own} AND generation = {n}"),
                },
            ];
            (key_id, rows)
        }
    };

    sqlx::query("INSERT INTO v2_offline_discard (tenant_id, kind, generation) VALUES (?, ?, ?)")
        .bind(&tenant)
        .bind(kind.as_str())
        .bind(n)
        .execute(&mut *tx)
        .await?;
    let at = util::now_rfc3339();
    let mut counts = Vec::new();
    for r in &rows {
        let gone = archive_and_delete(&mut tx, &tenant, kind, n, r, &at).await?;
        counts.push(format!("{}={gone}", r.table));
    }
    let broken = sqlx::query("PRAGMA foreign_key_check")
        .fetch_all(&mut *tx)
        .await?;
    ensure!(
        broken.is_empty(),
        "refusing: the discard would leave {} rows naming what it removed; nothing was changed",
        broken.len()
    );
    sqlx::query(
        "DELETE FROM v2_offline_discard WHERE tenant_id = ? AND kind = ? AND generation = ?",
    )
    .bind(&tenant)
    .bind(kind.as_str())
    .bind(n)
    .execute(&mut *tx)
    .await?;
    let (action, target) = match kind {
        Kind::Fleet => ("fleet.generation_discarded", "fleet_key_generation"),
        Kind::Root => ("root.generation_discarded", "root_key_generation"),
    };
    audit::insert_offline(
        &mut tx,
        &tenant,
        action,
        target,
        &key_id,
        &uuid::Uuid::new_v4().into_bytes(),
    )
    .await?;
    tx.commit().await?;
    pool.close().await;
    println!("discarded={} generation={generation}", kind.as_str());
    println!("key_id_prefix={}", &hex(&key_id)[..16]);
    for c in counts {
        println!("archived {c}");
    }
    Ok(())
}
