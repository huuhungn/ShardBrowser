//! Offline first-device commands (ADR 0001 D1 step 2, R1).
//!
//! `tenant confirm-first-device` records that the operator compared the
//! pending device's two key IDs with the client screen. It is the only way a
//! bootstrap guard leaves `unused` for `reserved`, and it writes the
//! confirmation, the guard move and the audit row in one transaction or not
//! at all. `tenant cancel-first-device` closes the attempt for good;
//! `tenant first-device-status` reads the result back after a lost response
//! and never writes.

use anyhow::{bail, ensure, Context, Result};
use sqlx::{Row, SqliteConnection};

use crate::config::Config;
use crate::identity::{self, hex, Verified};
use crate::{audit, db, integrity};

/// The pending device the operator is asked to confirm.
struct Candidate {
    tenant_id: Vec<u8>,
    account_id: Vec<u8>,
    signing_key_id: [u8; 32],
    hpke_key_id: [u8; 32],
    signing_public_key: Vec<u8>,
    hpke_public_key: Vec<u8>,
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// A device ID as typed: 32 hex digits.
pub fn parse_device_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

async fn verified_identity(cfg: &Config) -> Result<Verified> {
    let mirror = identity::read_mirror_read_only(cfg).await?;
    identity::authority(cfg, mirror.as_ref()).map_err(|r| {
        anyhow::anyhow!(
            "refusing: the server identity does not verify ({}: {}); run `identity show`",
            r.code.as_str(),
            r.detail
        )
    })
}

async fn tenant_id(conn: &mut SqliteConnection, slug: &str) -> Result<Vec<u8>> {
    sqlx::query_scalar("SELECT id FROM v2_tenants WHERE slug = ?")
        .bind(slug)
        .fetch_optional(&mut *conn)
        .await?
        .with_context(|| format!("no tenant with slug {slug}"))
}

async fn guard_state(
    conn: &mut SqliteConnection,
    instance: &[u8; 16],
    tenant_id: &[u8],
) -> Result<Option<(String, Option<String>)>> {
    Ok(sqlx::query_as(
        "SELECT state, recovery_reason FROM v2_bootstrap_guards
          WHERE server_instance_id = ? AND tenant_id = ?",
    )
    .bind(instance.as_slice())
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await?)
}

/// Every R1 precondition for a new confirmation. Run once before the prompt
/// and again inside the write transaction, so nothing checked here can change
/// between the check and the write.
async fn candidate(
    conn: &mut SqliteConnection,
    instance: &[u8; 16],
    slug: &str,
    device_id: &[u8; 16],
) -> Result<Candidate> {
    let tenant_id = tenant_id(conn, slug).await?;
    let tenant_status: String = sqlx::query_scalar("SELECT status FROM v2_tenants WHERE id = ?")
        .bind(&tenant_id)
        .fetch_one(&mut *conn)
        .await?;
    ensure!(
        tenant_status == "active",
        "refusing: the tenant is {tenant_status}"
    );
    match guard_state(conn, instance, &tenant_id).await? {
        Some((state, _)) if state == "unused" => {}
        Some((state, reason)) => bail!(
            "refusing: this tenant's first-device opportunity is {state}{}; \
             it never reopens",
            reason.map(|r| format!(" ({r})")).unwrap_or_default()
        ),
        None => bail!("refusing: this tenant has no bootstrap guard for this server instance"),
    }

    // History counts too, revoked rows included (R1 transition table).
    for (table, what) in [
        ("v2_device_approvals", "a device approval"),
        ("v2_capability_grants", "a capability grant"),
        ("v2_root_key_generations", "a root key generation"),
        ("v2_tenant_root_key_grants", "a root key grant"),
        (
            "v2_first_device_confirmations",
            "a first-device confirmation",
        ),
    ] {
        let any: bool = sqlx::query_scalar(&format!(
            "SELECT EXISTS (SELECT 1 FROM {table} WHERE tenant_id = ?)"
        ))
        .bind(&tenant_id)
        .fetch_one(&mut *conn)
        .await?;
        ensure!(!any, "refusing: the tenant already has {what}");
    }

    let owners: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT m.account_id FROM v2_tenant_memberships m
           JOIN v2_accounts a ON a.tenant_id = m.tenant_id AND a.id = m.account_id
          WHERE m.tenant_id = ? AND m.role = 'owner' AND m.status = 'active'
            AND a.status = 'active'",
    )
    .bind(&tenant_id)
    .fetch_all(&mut *conn)
    .await?;
    let [owner] = owners.as_slice() else {
        bail!(
            "refusing: the tenant must have exactly one active owner, it has {}",
            owners.len()
        );
    };

    let row = sqlx::query(
        "SELECT account_id, status, signing_suite, signing_public_key, signing_key_id,
                hpke_suite, hpke_public_key, hpke_key_id
           FROM v2_devices WHERE tenant_id = ? AND id = ?",
    )
    .bind(&tenant_id)
    .bind(device_id.as_slice())
    .fetch_optional(&mut *conn)
    .await?
    .context("refusing: no such device in this tenant")?;
    let status: String = row.get("status");
    ensure!(
        status == "pending",
        "refusing: the device is {status}, not pending"
    );
    let account_id: Vec<u8> = row.get("account_id");
    ensure!(
        &account_id == owner,
        "refusing: the device was not enrolled by the tenant's owner"
    );

    // R4: show only IDs that are the derivation of the stored keys.
    let key = |col: &str| -> Option<[u8; 32]> { row.get::<Vec<u8>, _>(col).try_into().ok() };
    let (signing_public_key, hpke_public_key) =
        match (key("signing_public_key"), key("hpke_public_key")) {
            (Some(s), Some(h)) => (s, h),
            _ => bail!("refusing: the device keys need reconciliation"),
        };
    let derived = integrity::derive_device_key_ids(
        row.get("signing_suite"),
        &signing_public_key,
        row.get("hpke_suite"),
        &hpke_public_key,
    );
    let (signing_key_id, hpke_key_id) = match derived {
        Ok(ids) if Some(ids.0) == key("signing_key_id") && Some(ids.1) == key("hpke_key_id") => ids,
        _ => bail!(
            "refusing: the stored key IDs are not the derivation of the device keys; \
             the device needs reconciliation, not confirmation"
        ),
    };
    Ok(Candidate {
        tenant_id,
        account_id,
        signing_key_id,
        hpke_key_id,
        signing_public_key: signing_public_key.to_vec(),
        hpke_public_key: hpke_public_key.to_vec(),
    })
}

/// Reads one key ID as the operator typed it.
fn typed_key_id(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_ascii_lowercase())
}

/// `tenant confirm-first-device --tenant <slug> --device <id>`. The caller
/// holds the data directory lock.
pub async fn confirm(cfg: &Config, slug: &str, device_id: &[u8; 16]) -> Result<()> {
    let verified = verified_identity(cfg).await?;
    let pool = db::init_pool(cfg).await?;
    let instance = verified.server_instance_id;

    let shown = {
        let mut conn = pool.acquire().await?;
        candidate(&mut conn, &instance, slug, device_id).await?
    };
    println!("tenant={slug}");
    println!("device_id={}", hex(device_id));
    println!("signing_key_id={}", hex(&shown.signing_key_id));
    println!("hpke_key_id={}", hex(&shown.hpke_key_id));
    let signing = typed_key_id("Signing key ID as shown on the client: ")?;
    let hpke = typed_key_id("HPKE key ID as shown on the client: ")?;
    ensure!(
        signing == hex(&shown.signing_key_id) && hpke == hex(&shown.hpke_key_id),
        "the key IDs entered do not match the device; nothing was written"
    );

    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let c = candidate(&mut tx, &instance, slug, device_id).await?;
    ensure!(
        c.signing_key_id == shown.signing_key_id && c.hpke_key_id == shown.hpke_key_id,
        "the device changed while waiting for input; nothing was written"
    );
    let confirmation_id = uuid::Uuid::new_v4().into_bytes();
    let request_id = uuid::Uuid::new_v4().into_bytes();
    let epoch = i64::try_from(verified.restore_epoch).context("restore epoch out of range")?;
    sqlx::query(
        "INSERT INTO v2_first_device_confirmations
             (server_instance_id, tenant_id, confirmation_id, account_id, device_id, request_id,
              restore_epoch, confirmed_at_ms, signing_key_id, hpke_key_id, signing_public_key,
              hpke_public_key, signing_suite, hpke_suite, state)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 1, 'pending')",
    )
    .bind(instance.as_slice())
    .bind(&c.tenant_id)
    .bind(confirmation_id.as_slice())
    .bind(&c.account_id)
    .bind(device_id.as_slice())
    .bind(request_id.as_slice())
    .bind(epoch)
    .bind(now_ms())
    .bind(c.signing_key_id.as_slice())
    .bind(c.hpke_key_id.as_slice())
    .bind(&c.signing_public_key)
    .bind(&c.hpke_public_key)
    .execute(&mut *tx)
    .await
    .context("inserting the confirmation")?;
    let moved = sqlx::query(
        "UPDATE v2_bootstrap_guards SET state = 'reserved', updated_at = ?
          WHERE server_instance_id = ? AND tenant_id = ? AND state = 'unused'",
    )
    .bind(crate::util::now_rfc3339())
    .bind(instance.as_slice())
    .bind(&c.tenant_id)
    .execute(&mut *tx)
    .await?;
    ensure!(moved.rows_affected() == 1, "the bootstrap guard moved");
    audit::insert_offline(
        &mut tx,
        &c.tenant_id,
        "tenant.first_device_confirm",
        "device",
        device_id,
        &request_id,
    )
    .await?;
    tx.commit().await?;
    pool.close().await;

    println!("confirmation_id={}", hex(&confirmation_id));
    Ok(())
}

/// `tenant cancel-first-device --tenant <slug>`: closes a reserved attempt.
/// No replacement confirmation is possible afterwards (R1).
pub async fn cancel(cfg: &Config, slug: &str) -> Result<()> {
    let verified = verified_identity(cfg).await?;
    let pool = db::init_pool(cfg).await?;
    let instance = verified.server_instance_id;
    let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
    let tenant_id = tenant_id(&mut tx, slug).await?;
    match guard_state(&mut tx, &instance, &tenant_id).await? {
        Some((state, _)) if state == "reserved" => {}
        Some((state, _)) => {
            bail!("refusing: there is no reserved first device to cancel ({state})")
        }
        None => bail!("refusing: this tenant has no bootstrap guard for this server instance"),
    }
    let (device_id, epoch, device_status): (Vec<u8>, i64, Option<String>) = sqlx::query_as(
        "SELECT c.device_id, c.restore_epoch, d.status
           FROM v2_first_device_confirmations c
           LEFT JOIN v2_devices d ON d.tenant_id = c.tenant_id AND d.id = c.device_id
          WHERE c.server_instance_id = ? AND c.tenant_id = ? AND c.state = 'pending'",
    )
    .bind(instance.as_slice())
    .bind(&tenant_id)
    .fetch_optional(&mut *tx)
    .await?
    .context("refusing: the guard is reserved but no pending confirmation exists")?;
    // A cancel records an operator decision. A confirmation that is already
    // inconsistent belongs to the startup integrity pass (R1), not to a cancel.
    ensure!(
        device_status.as_deref() == Some("pending")
            && u64::try_from(epoch).ok() == Some(verified.restore_epoch),
        "refusing: the confirmation no longer matches its device or this restore epoch; \
         restart the server so the integrity pass moves it to recovery"
    );
    let cancelled = sqlx::query(
        "UPDATE v2_first_device_confirmations
            SET state = 'cancelled', terminal_at_ms = ?, terminal_reason = 'operator_cancelled'
          WHERE server_instance_id = ? AND tenant_id = ? AND state = 'pending'",
    )
    .bind(now_ms())
    .bind(instance.as_slice())
    .bind(&tenant_id)
    .execute(&mut *tx)
    .await?;
    ensure!(cancelled.rows_affected() == 1, "the confirmation moved");
    let closed = sqlx::query(
        "UPDATE v2_bootstrap_guards SET state = 'closed', updated_at = ?
          WHERE server_instance_id = ? AND tenant_id = ? AND state = 'reserved'",
    )
    .bind(crate::util::now_rfc3339())
    .bind(instance.as_slice())
    .bind(&tenant_id)
    .execute(&mut *tx)
    .await?;
    ensure!(closed.rows_affected() == 1, "the bootstrap guard moved");
    let request_id = uuid::Uuid::new_v4().into_bytes();
    audit::insert_offline(
        &mut tx,
        &tenant_id,
        "tenant.first_device_cancel",
        "device",
        &device_id,
        &request_id,
    )
    .await?;
    tx.commit().await?;
    pool.close().await;
    println!("state=closed");
    Ok(())
}

/// `tenant first-device-status --tenant <slug>`: read-only.
pub async fn status(cfg: &Config, slug: &str) -> Result<()> {
    let verified = verified_identity(cfg).await?;
    let pool = identity::open_read_only(cfg)
        .await?
        .context("there is no database yet")?;
    let mut conn = pool.acquire().await?;
    let tenant_id = tenant_id(&mut conn, slug).await?;
    let instance = verified.server_instance_id;
    match guard_state(&mut conn, &instance, &tenant_id).await? {
        Some((state, reason)) => {
            println!("guard={state}");
            if let Some(reason) = reason {
                println!("recovery_reason={reason}");
            }
        }
        None => println!("guard=missing"),
    }
    let row = sqlx::query(
        "SELECT * FROM v2_first_device_confirmations
          WHERE server_instance_id = ? AND tenant_id = ?",
    )
    .bind(instance.as_slice())
    .bind(&tenant_id)
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        println!("confirmation=none");
        return Ok(());
    };
    let blob = |col: &str| row.get::<Option<Vec<u8>>, _>(col).map(|b| hex(&b));
    for col in [
        "confirmation_id",
        "account_id",
        "device_id",
        "signing_key_id",
        "hpke_key_id",
        "approval_replay_id",
        "approval_payload_sha256",
        "approval_signed_container_hash",
        "approval_outer_sha256",
    ] {
        if let Some(v) = blob(col) {
            println!("{col}={v}");
        }
    }
    println!("state={}", row.get::<String, _>("state"));
    println!("restore_epoch={}", row.get::<i64, _>("restore_epoch"));
    println!("restore_epoch_current={}", verified.restore_epoch);
    let device_status: Option<String> =
        sqlx::query_scalar("SELECT status FROM v2_devices WHERE tenant_id = ? AND id = ?")
            .bind(&tenant_id)
            .bind(row.get::<Vec<u8>, _>("device_id"))
            .fetch_optional(&mut *conn)
            .await?;
    println!(
        "device_status={}",
        device_status.as_deref().unwrap_or("missing")
    );
    if let Some(reason) = row.get::<Option<String>, _>("terminal_reason") {
        println!("terminal_reason={reason}");
    }
    // R4: the stored IDs must still be the derivation of the stored keys.
    let key = |col: &str| -> Option<[u8; 32]> { row.get::<Vec<u8>, _>(col).try_into().ok() };
    let verified_keys = match (key("signing_public_key"), key("hpke_public_key")) {
        (Some(s), Some(h)) => integrity::derive_device_key_ids(
            row.get("signing_suite"),
            &s,
            row.get("hpke_suite"),
            &h,
        )
        .is_ok_and(|ids| Some(ids.0) == key("signing_key_id") && Some(ids.1) == key("hpke_key_id")),
        _ => false,
    };
    println!("key_ids_verified={verified_keys}");
    drop(conn);
    pool.close().await;
    ensure!(
        verified_keys,
        "the stored key IDs are not the derivation of the stored keys"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_ids_are_32_hex_digits() {
        assert_eq!(
            parse_device_id("000102030405060708090a0b0c0d0e0f"),
            Some([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
        );
        assert_eq!(
            parse_device_id("000102030405060708090A0B0C0D0E0F").map(|d| d[15]),
            Some(15)
        );
        for bad in [
            "",
            "00",
            "000102030405060708090a0b0c0d0e0",
            "+00102030405060708090a0b0c0d0e0f",
            "g00102030405060708090a0b0c0d0e0f",
        ] {
            assert_eq!(parse_device_id(bad), None, "{bad:?}");
        }
    }
}
