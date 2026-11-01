//! The exact signed authorization records and root grants this device keeps
//! (plan L1510-L1744, L2032, L2056; probe 3, L2038).
//!
//! The five records of 5.6.1 go to `signed_authorization_records`, the
//! `TenantRootKeyGrantV2` to `tenant_root_key_grants`. Every column the
//! container decides is derived from its exact bytes, by the payload's own
//! field names, and [`load`] rederives them all on every read: a row whose
//! columns differ from its bytes in any way is refused, never repaired. Only
//! `server_id` and the local times and references (`LOCAL`) are this
//! device's own. Keeping a record grants nothing: before a key is used, its
//! container is still reverified against the trust evidence.

use std::collections::BTreeMap;

use anyhow::{anyhow, Result};
use rusqlite::types::Value as Sql;
use rusqlite::{params, params_from_iter, Connection, OptionalExtension};
use shardx_core::authz_record::{self as az, AuthorizationRecord};
use shardx_core::canonical::{decode, Value};

use crate::fleet_client::hex;

pub const SIGNED: &str = "signed_authorization_records";
pub const ROOT_GRANTS: &str = "tenant_root_key_grants";

/// The columns this device sets itself: no byte of the record decides them.
const LOCAL: [&str; 5] = [
    "server_id",
    "verified_at_ms",
    "revoked_at_ms",
    "trk_credential_ref",
    "acknowledged_at_ms",
];

fn unreadable() -> anyhow::Error {
    anyhow!(crate::errcode::code("team.trustLedgerUnreadable"))
}

/// The table, and the `record_kind`, of a payload domain.
fn kind(domain: &str) -> Option<(&'static str, Option<&'static str>)> {
    Some(match domain {
        az::DOMAIN_DEVICE_APPROVAL => (SIGNED, Some("DeviceApprovalV2")),
        az::DOMAIN_TENANT_CAPABILITY_GRANT => (SIGNED, Some("TenantCapabilityGrantV2")),
        az::DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE => {
            (SIGNED, Some("FleetKeyGrantV2::DeviceHpkeGrant"))
        }
        az::DOMAIN_FLEET_KEY_GRANT_RECOVERY => (SIGNED, Some("FleetKeyGrantV2::RecoveryGrant")),
        az::DOMAIN_FLEET_KEY_GRANT_ROTATION => (SIGNED, Some("FleetKeyGrantV2::RotationGrant")),
        az::DOMAIN_TENANT_ROOT_KEY_GRANT => (ROOT_GRANTS, None),
        _ => return None,
    })
}

/// Byte fields kept as BLOB; every other byte field is an ID, kept as
/// lowercase hex like the rest of the team database.
fn blob(name: &str) -> bool {
    name.ends_with("_bytes") || name.ends_with("_hash") || name.ends_with("replay_id")
}

/// The table `exact` belongs in and every column its bytes decide.
fn columns(exact: &[u8]) -> Result<(&'static str, BTreeMap<String, Sql>)> {
    let r = AuthorizationRecord::parse(exact).map_err(|_| unreadable())?;
    let (table, kind) = kind(r.payload_domain()).ok_or_else(unreadable)?;
    let Ok(Value::Map(fields)) = decode(r.canonical_payload_bytes()) else {
        return Err(unreadable());
    };
    let mut cols = BTreeMap::new();
    for (name, v) in fields {
        let v = match v {
            // The codec refuses an integer past i64::MAX (`WIRE_INTEGER_OUT_OF_RANGE`).
            Value::Uint(u) => Sql::Integer(i64::try_from(u).map_err(|_| unreadable())?),
            Value::Text(t) => Sql::Text(t),
            Value::Bytes(b) if blob(&name) => Sql::Blob(b),
            Value::Bytes(b) => Sql::Text(hex(&b)),
            _ => return Err(unreadable()),
        };
        // `parse` checked the payload's own domain and version are the
        // container's.
        let name = match name.as_str() {
            "domain" => "payload_domain".to_string(),
            "version" => "payload_version".to_string(),
            _ => name,
        };
        cols.insert(name, v);
    }
    let (suite, version) = r.signature_suite();
    let container = [
        ("container_domain", Sql::Text(az::CONTAINER_DOMAIN.into())),
        (
            "container_version",
            Sql::Integer(az::CONTAINER_VERSION.into()),
        ),
        (
            "canonical_payload_bytes",
            Sql::Blob(r.canonical_payload_bytes().to_vec()),
        ),
        ("payload_sha256", Sql::Blob(r.payload_sha256().to_vec())),
        ("signature_suite_id", Sql::Integer(suite.into())),
        ("signature_version", Sql::Integer(version.into())),
        (
            "issuer_signing_key_id",
            Sql::Text(hex(r.issuer_signing_key_id())),
        ),
        ("signature_bytes", Sql::Blob(r.signature_bytes().to_vec())),
        (
            "signed_container_hash",
            Sql::Blob(r.signed_container_hash().to_vec()),
        ),
        ("exact_signed_container_bytes", Sql::Blob(exact.to_vec())),
        (
            "exact_signed_container_bytes_sha256",
            Sql::Blob(r.exact_signed_container_bytes_sha256().to_vec()),
        ),
    ];
    let record = kind.map(|kind| {
        [
            ("record_id", Sql::Text(hex(r.signed_container_hash()))),
            ("record_kind", Sql::Text(kind.into())),
        ]
    });
    let fixed = container.into_iter().chain(record.into_iter().flatten());
    cols.extend(fixed.map(|(name, v)| (name.to_string(), v)));
    Ok((table, cols))
}

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    Ok(conn
        .prepare("SELECT name FROM pragma_table_info(?1)")?
        .query_map([table], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?)
}

/// Every column of `table` but the local ones, as `cols` decides it: NULL
/// for a field the record lacks. The payload schemas are closed, so every
/// field has its column.
fn row(
    conn: &Connection,
    table: &str,
    mut cols: BTreeMap<String, Sql>,
) -> Result<Vec<(String, Sql)>> {
    Ok(table_columns(conn, table)?
        .into_iter()
        .filter(|name| !LOCAL.contains(&name.as_str()))
        .map(|name| {
            let v = cols.remove(&name).unwrap_or(Sql::Null);
            (name, v)
        })
        .collect())
}

/// The `server_origins` row of `server_url`, from the URL parser (L2032),
/// filed on first use for `instance` at `epoch`. An origin filed for another
/// instance is refused: what was kept under the old one never moves.
/// Its `last_restore_epoch` starts at the epoch of the first record kept
/// here and moves with each accepted restore epoch transition.
pub(crate) fn origin(
    conn: &Connection,
    server_url: &str,
    instance: &str,
    epoch: i64,
) -> Result<String> {
    let url = url::Url::parse(server_url).map_err(|_| unreadable())?;
    let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
        return Err(unreadable());
    };
    let found: Option<(String, String)> = conn
        .query_row(
            "SELECT server_id, server_instance_id FROM server_origins WHERE origin = ?1",
            [format!("{}://{host}:{port}", url.scheme())],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match found {
        Some((id, filed)) if filed == instance => Ok(id),
        Some(_) => Err(unreadable()),
        None => {
            let mut id = [0u8; 16];
            shardx_core::keys::fill_random(&mut id).map_err(|e| anyhow!("{e}"))?;
            let id = hex(&id);
            conn.execute(
                "INSERT INTO server_origins(server_id, scheme, host, port, tls_policy,
                   server_instance_id, last_restore_epoch, status)
                 VALUES (?1, ?2, ?3, ?4, 'SYSTEM', ?5, ?6, 'ACTIVE')",
                params![id, url.scheme(), host, port, instance, epoch],
            )?;
            Ok(id)
        }
    }
}

/// Keeps the exact container `exact`, from the server at `server_url` and
/// verified at `now`, unless it is kept already; either way it must then
/// [`load`] back. A record of the same replay ID with
/// other bytes is refused (L1580, L1725), and a root grant needs its
/// generation filed first, on the same instance (L1728).
pub fn keep(conn: &Connection, server_url: &str, exact: &[u8], now: u64) -> Result<()> {
    let (table, cols) = columns(exact)?;
    let (Some(Sql::Text(instance)), Some(Sql::Integer(epoch)), Some(Sql::Blob(hash))) = (
        cols.get("server_instance_id"),
        cols.get("restore_epoch"),
        cols.get("signed_container_hash"),
    ) else {
        return Err(unreadable());
    };
    let server = origin(conn, server_url, instance, *epoch)?;
    let hash: [u8; 32] = hash.as_slice().try_into().map_err(|_| unreadable())?;
    let mut names = vec!["server_id".to_string()];
    let mut values = vec![Sql::Text(server)];
    if table == SIGNED {
        names.push("verified_at_ms".into());
        values.push(Sql::Integer(
            i64::try_from(now).map_err(|_| anyhow!("WIRE_INTEGER_OUT_OF_RANGE"))?,
        ));
    }
    for (name, v) in row(conn, table, cols)? {
        names.push(name);
        values.push(v);
    }
    let marks = vec!["?"; names.len()].join(", ");
    conn.execute(
        &format!(
            "INSERT INTO {table}({}) VALUES ({marks}) ON CONFLICT DO NOTHING",
            names.join(", ")
        ),
        params_from_iter(values),
    )?;
    load(conn, table, &hash).map(drop)
}

/// Files root generation 0 that the first root self-grant `self_grant`
/// names, ACTIVE with that grant as its one custodian (L1656-L1678), then
/// the grant itself and the device's approval `approval`. Run once the
/// bootstrap activated the generation; running it again changes nothing.
pub fn keep_root_bootstrap(
    conn: &Connection,
    server_url: &str,
    approval: &[u8],
    self_grant: &[u8],
    recovery_bundle_sha256: &[u8; 32],
    now: u64,
) -> Result<()> {
    let (_, cols) = columns(self_grant)?;
    let text = |name: &str| match cols.get(name) {
        Some(Sql::Text(t)) => Ok(t.as_str()),
        _ => Err(unreadable()),
    };
    // Parsing holds a self-grant to generation 0.
    if text("grant_variant")? != "FirstRootSelfGrant" {
        return Err(unreadable());
    }
    let Some(Sql::Integer(epoch)) = cols.get("restore_epoch") else {
        return Err(unreadable());
    };
    let instance = text("server_instance_id")?;
    let server = origin(conn, server_url, instance, *epoch)?;
    let hash = AuthorizationRecord::parse(self_grant)
        .map_err(|_| unreadable())?
        .signed_container_hash()
        .to_owned();
    let set_hash =
        shardx_core::mutation::root_custodian_grant_set_hash(&[hash]).ok_or_else(unreadable)?;
    conn.execute(
        "INSERT INTO tenant_root_key_generations(server_id, server_instance_id, tenant_id,
           root_generation, root_key_id, state, recovery_bundle_sha256,
           required_custodian_grant_count, required_custodian_grant_set_hash,
           created_at, activated_at)
         VALUES (?1, ?2, ?3, 0, ?4, 'ACTIVE', ?5, 1, ?6,
           strftime('%Y-%m-%dT%H:%M:%SZ', 'now'), strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
         ON CONFLICT DO NOTHING",
        params![
            server,
            instance,
            text("tenant_id")?,
            text("root_key_id")?,
            &recovery_bundle_sha256[..],
            &set_hash[..]
        ],
    )?;
    keep(conn, server_url, self_grant, now)?;
    keep(conn, server_url, approval, now)
}

/// The exact container kept in `table` whose signed container hash is
/// `hash`, once every column its bytes decide equals what they say, its
/// origin is the instance it names and it is not revoked. Anything else
/// refuses it: no column is trusted on its own (L2032, L2056).
pub fn load(conn: &Connection, table: &str, hash: &[u8; 32]) -> Result<Vec<u8>> {
    let names = table_columns(conn, table)?;
    let sql = format!(
        "SELECT {} FROM {table} WHERE signed_container_hash = ?1",
        names.join(", ")
    );
    let mut rows = conn
        .prepare(&sql)?
        .query_map([&hash[..]], |r| {
            (0..names.len()).map(|i| r.get::<_, Sql>(i)).collect()
        })?
        .collect::<rusqlite::Result<Vec<Vec<Sql>>>>()?;
    let (Some(stored), None) = (rows.pop(), rows.pop()) else {
        return Err(unreadable());
    };
    let stored: BTreeMap<&str, Sql> = names.iter().map(String::as_str).zip(stored).collect();
    let Some(Sql::Blob(exact)) = stored.get("exact_signed_container_bytes") else {
        return Err(unreadable());
    };
    let (_, cols) = columns(exact)?;
    let want = row(conn, table, cols)?;
    if want
        .iter()
        .any(|(name, v)| stored.get(name.as_str()) != Some(v))
    {
        return Err(unreadable());
    }
    let instance_of_server: Option<String> = conn
        .query_row(
            "SELECT server_instance_id FROM server_origins WHERE server_id = ?1",
            [stored.get("server_id")],
            |r| r.get(0),
        )
        .optional()?;
    if instance_of_server.map(Sql::Text).as_ref() != stored.get("server_instance_id")
        || stored.get("revoked_at_ms") != Some(&Sql::Null)
    {
        return Err(unreadable());
    }
    Ok(exact.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::team::db::Db;
    use shardx_core::authz_record::{
        build_record, ApprovalScopeKind, Capability, CapabilityScopeKind, CommonFields,
        DeviceApprovalV2, DeviceHpkeGrantV2, GrantSubject, RecoveryGrantV2, RootGrantVariant,
        RotationGrantV2, TenantCapabilityGrantV2, TenantRootKeyGrantV2,
    };
    use shardx_core::fleet_grants::fkek_key_id;
    use shardx_core::keys::{hpke_key_id, signing_key_id};
    use shardx_core::signing::Ed25519SigningKey;

    const URL: &str = "https://Fleet.Test/";
    const OTHER_URL: &str = "https://other.test";

    fn common(replay: u8, instance: [u8; 16]) -> CommonFields {
        CommonFields {
            replay_id: [replay; 16],
            tenant_id: [0x22; 16],
            issued_at_ms: 10,
            not_before_ms: 10,
            not_after_ms: 1_000,
            server_instance_id: instance,
            restore_epoch: 0,
        }
    }

    fn root_grant(replay: u8, instance: [u8; 16], variant: RootGrantVariant) -> Vec<u8> {
        let sk = Ed25519SigningKey::from_bytes(&[7; 32]);
        let me = signing_key_id(sk.verifying_key().as_bytes());
        let (_, hpke_pk) = shardx_core::grants::derive_keypair(&[8; 32]);
        let g = TenantRootKeyGrantV2 {
            common: common(replay, instance),
            variant,
            root_key_id: [6; 32],
            root_generation: 0,
            subject_account_id: [3; 16],
            subject_device_id: [4; 16],
            subject_signing_key_id: me,
            recipient_hpke_key_id: hpke_key_id(&hpke_pk),
            subject_device_approval_replay_id: [1; 16],
            hpke_encapped_key_bytes: [5; 32],
            hpke_wrapped_trk_bytes: [6; 48],
        };
        build_record(&sk, az::DOMAIN_TENANT_ROOT_KEY_GRANT, &g.encode())
    }

    /// The six records of probe 3: the five of 5.6.1, then the root grant.
    fn six() -> Vec<Vec<u8>> {
        let sk = Ed25519SigningKey::from_bytes(&[7; 32]);
        let me = signing_key_id(sk.verifying_key().as_bytes());
        let (_, hpke_pk) = shardx_core::grants::derive_keypair(&[8; 32]);
        let hpke = hpke_key_id(&hpke_pk);
        let i = [0x11; 16];
        let approval = DeviceApprovalV2 {
            common: common(1, i),
            subject_account_id: [3; 16],
            subject_device_id: [4; 16],
            subject_signing_key_id: me,
            subject_hpke_key_id: hpke,
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: [0x22; 16],
        };
        let capability = TenantCapabilityGrantV2 {
            common: common(2, i),
            subject: GrantSubject::Device {
                account_id: [3; 16],
                device_id: [4; 16],
                signing_key_id: me,
                hpke_key_id: hpke,
            },
            scope_kind: CapabilityScopeKind::Tenant,
            scope_id: [0x22; 16],
            capability: Capability::TenantManage,
        };
        let mut device = DeviceHpkeGrantV2 {
            common: common(3, i),
            fleet_id: [5; 16],
            fkek_key_id: fkek_key_id(&[9; 32]),
            generation: 1,
            subject_account_id: [3; 16],
            subject_device_id: [4; 16],
            subject_signing_key_id: me,
            recipient_hpke_key_id: hpke,
            hpke_encapped_key_bytes: Vec::new(),
            hpke_wrapped_fleet_key_bytes: Vec::new(),
        };
        shardx_core::grants::seal_device_fkek(&hpke_pk, &mut device, &[9; 32]).unwrap();
        let recovery = RecoveryGrantV2 {
            common: common(4, i),
            fleet_id: [5; 16],
            fkek_key_id: fkek_key_id(&[9; 32]),
            generation: 1,
            recipient_root_key_id: [6; 32],
            recipient_root_generation: 0,
            root_wrap_nonce_bytes: [1; 12],
            wrapped_fleet_key_bytes: [2; 48],
        };
        let rotation = RotationGrantV2 {
            common: common(5, i),
            fleet_id: [5; 16],
            fkek_key_id: fkek_key_id(&[10; 32]),
            generation: 2,
            previous_fkek_key_id: fkek_key_id(&[9; 32]),
            previous_generation: 1,
            required_device_grant_count: 1,
            required_device_grant_set_hash: [3; 32],
            recovery_grant_signed_container_hash: [4; 32],
            activation_not_before_ms: 10,
        };
        vec![
            build_record(&sk, az::DOMAIN_DEVICE_APPROVAL, &approval.encode()),
            build_record(
                &sk,
                az::DOMAIN_TENANT_CAPABILITY_GRANT,
                &capability.encode(),
            ),
            build_record(
                &sk,
                az::DOMAIN_FLEET_KEY_GRANT_DEVICE_HPKE,
                &device.encode(),
            ),
            build_record(&sk, az::DOMAIN_FLEET_KEY_GRANT_RECOVERY, &recovery.encode()),
            build_record(&sk, az::DOMAIN_FLEET_KEY_GRANT_ROTATION, &rotation.encode()),
            root_grant(6, i, RootGrantVariant::FirstRootSelfGrant),
        ]
    }

    fn hash(exact: &[u8]) -> [u8; 32] {
        *AuthorizationRecord::parse(exact)
            .unwrap()
            .signed_container_hash()
    }

    fn table(exact: &[u8]) -> &'static str {
        columns(exact).unwrap().0
    }

    /// A fresh database holding all six records, closed.
    fn kept() -> (tempfile::TempDir, std::path::PathBuf, Vec<Vec<u8>>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        let six = six();
        let db = Db::open_at(&path).unwrap();
        keep_root_bootstrap(&db.conn, URL, &six[0], &six[5], &[7; 32], 100).unwrap();
        for exact in &six[1..5] {
            keep(&db.conn, URL, exact, 100).unwrap();
        }
        (dir, path, six)
    }

    /// Probe 3 (L2038, G2-35): each of the six records reopens byte-identical,
    /// and keeping it again changes nothing. Then, on a reopened database,
    /// every column of its row is changed in turn, with the DDL's CHECKs and
    /// foreign keys off as a corrupt file would have them: each change the
    /// bytes decide refuses the record. Only the local columns may change.
    #[test]
    fn six_records_reopen_exactly_and_refuse_every_changed_column() {
        let (_dir, path, six) = kept();
        let db = Db::open_at(&path).unwrap();
        for exact in &six {
            assert_eq!(&load(&db.conn, table(exact), &hash(exact)).unwrap(), exact);
            keep(&db.conn, URL, exact, 200).unwrap();
            let reparsed = AuthorizationRecord::parse(exact).unwrap();
            assert_eq!(reparsed.exact_signed_container_bytes(), &exact[..]);
        }
        let count = |t: &str| -> i64 {
            db.conn
                .query_row(&format!("SELECT count(*) FROM {t}"), [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!((count(SIGNED), count(ROOT_GRANTS)), (5, 1));
        db.conn
            .execute_batch("PRAGMA foreign_keys = OFF; PRAGMA ignore_check_constraints = ON;")
            .unwrap();
        let mut refused = 0;
        for exact in &six {
            let t = table(exact);
            let types: Vec<(String, String)> = db
                .conn
                .prepare("SELECT name, type FROM pragma_table_info(?1)")
                .unwrap()
                .query_map([t], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap();
            for (col, ty) in types {
                let set = match ty.as_str() {
                    "INTEGER" => "1",
                    "TEXT" => "'x'",
                    _ => "x'00'",
                };
                let sql = format!(
                    "SAVEPOINT m; UPDATE {t} SET {col} = CASE
                       WHEN {col} IS NULL THEN {set}
                       WHEN typeof({col}) = 'integer' THEN {col} + 1
                       WHEN typeof({col}) = 'text' THEN {col} || '0'
                       ELSE CAST(x'00' || {col} AS BLOB) END
                     WHERE signed_container_hash = x'{}'",
                    hex(&hash(exact))
                );
                db.conn.execute_batch(&sql).unwrap();
                assert_eq!(db.conn.changes(), 1, "{t}.{col}");
                let loaded = load(&db.conn, t, &hash(exact));
                let local = ["verified_at_ms", "trk_credential_ref", "acknowledged_at_ms"];
                if local.contains(&col.as_str()) {
                    assert_eq!(&loaded.unwrap(), exact, "{t}.{col} is local");
                } else {
                    let err = loaded.err().unwrap_or_else(|| panic!("{t}.{col}"));
                    assert!(
                        crate::errcode::has_code(&err.to_string(), "team.trustLedgerUnreadable"),
                        "{t}.{col}: {err}"
                    );
                    refused += 1;
                }
                db.conn.execute_batch("ROLLBACK TO m; RELEASE m;").unwrap();
                assert_eq!(&load(&db.conn, t, &hash(exact)).unwrap(), exact);
            }
        }
        // 58 columns of each of five records but `verified_at_ms`, and 43 of
        // the root grant but `trk_credential_ref` and `acknowledged_at_ms`.
        assert_eq!(refused, 5 * 57 + 41);
    }

    /// Probe 3's root grant rules (L1742, L1728): a second
    /// `FirstRootSelfGrant` of the tenant is refused, and a grant naming a
    /// generation of another server instance has no generation to refer to.
    /// The same holds for rows written by hand, with the DDL on.
    #[test]
    fn a_second_self_grant_and_a_cross_instance_generation_are_refused() {
        let (_dir, path, _) = kept();
        let db = Db::open_at(&path).unwrap();
        let unreadable = |r: Result<()>| {
            let err = r.expect_err("refused").to_string();
            assert!(
                crate::errcode::has_code(&err, "team.trustLedgerUnreadable"),
                "{err}"
            );
        };
        // Another self-grant of the same tenant, generation and root key.
        let second = root_grant(7, [0x11; 16], RootGrantVariant::FirstRootSelfGrant);
        unreadable(keep(&db.conn, URL, &second, 200));
        // A self-grant on another instance, whose generation 0 was never filed.
        let elsewhere = root_grant(8, [0x33; 16], RootGrantVariant::FirstRootSelfGrant);
        assert!(keep(&db.conn, OTHER_URL, &elsewhere, 200).is_err());
        // The first server's records never move to another instance.
        unreadable(keep(&db.conn, URL, &elsewhere, 200));
        let grants: i64 = db
            .conn
            .query_row("SELECT count(*) FROM tenant_root_key_grants", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(grants, 1);

        let other: String = db
            .conn
            .query_row(
                "SELECT server_id FROM server_origins WHERE origin = 'https://other.test:443'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        for (sql, refusal) in [
            (
                "UPDATE c SET replay_id = randomblob(16)".to_string(),
                "UNIQUE constraint failed",
            ),
            (
                format!(
                    "UPDATE c SET replay_id = randomblob(16),
                       grant_variant = 'ExistingRootGrant', server_id = '{other}',
                       server_instance_id = '{}'",
                    "33".repeat(16)
                ),
                "FOREIGN KEY constraint failed",
            ),
        ] {
            let err = db
                .conn
                .execute_batch(&format!(
                    "SAVEPOINT r;
                     CREATE TEMP TABLE c AS SELECT * FROM tenant_root_key_grants;
                     {sql};
                     INSERT INTO tenant_root_key_grants SELECT * FROM c;"
                ))
                .unwrap_err()
                .to_string();
            assert!(err.contains(refusal), "{sql}: {err}");
            db.conn.execute_batch("ROLLBACK TO r; RELEASE r;").unwrap();
        }
    }

    /// The bootstrap files a generation only from a first root self-grant,
    /// once per origin however the URL is spelled; and a second row claiming
    /// a kept record's hash, as a corrupt file could hold, refuses it.
    #[test]
    fn only_a_self_grant_files_a_generation_and_a_duplicate_row_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let db = Db::open_at(&dir.path().join("team-sync.db")).unwrap();
        let six = six();
        let existing = root_grant(9, [0x11; 16], RootGrantVariant::ExistingRootGrant);
        for grant in [&existing, &six[2]] {
            assert!(keep_root_bootstrap(&db.conn, URL, &six[0], grant, &[7; 32], 100).is_err());
        }
        let count = |sql: &str| -> i64 { db.conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert_eq!(count("SELECT count(*) FROM tenant_root_key_generations"), 0);
        for url in [URL, "https://fleet.test:443"] {
            keep_root_bootstrap(&db.conn, url, &six[0], &six[5], &[7; 32], 100).unwrap();
        }
        assert_eq!(count("SELECT count(*) FROM server_origins"), 1);
        assert_eq!(count("SELECT count(*) FROM tenant_root_key_generations"), 1);

        // The copy goes first, so the true row is the one a scan ends on.
        let approval = hash(&six[0]);
        db.conn
            .execute_batch(
                "CREATE TEMP TABLE o AS SELECT * FROM signed_authorization_records;
                 CREATE TEMP TABLE c AS SELECT * FROM o;
                 UPDATE c SET record_id = 'copy', replay_id = randomblob(16);
                 DELETE FROM signed_authorization_records;
                 INSERT INTO signed_authorization_records SELECT * FROM c;
                 INSERT INTO signed_authorization_records SELECT * FROM o;",
            )
            .unwrap();
        assert!(load(&db.conn, SIGNED, &approval).is_err());
        db.conn
            .execute(
                "DELETE FROM signed_authorization_records WHERE record_id = 'copy'",
                [],
            )
            .unwrap();
        assert_eq!(load(&db.conn, SIGNED, &approval).unwrap(), six[0]);
    }

    /// Probe 10 (L2045, G2-42) on every table version 4 adds, per wire
    /// integer class: both bounds are kept exactly across a reopen; one past
    /// either bound, 2^63 and 2^64 - 1, a fraction, and text or bytes that
    /// name no integer are refused with the value left as it was. SQLite
    /// STRICT converts text or a real naming an in-range integer losslessly,
    /// so that is stored as that exact INTEGER, never as text (ADR 0002
    /// Q-43: probe 10 refuses the coercions that would change the value). A record
    /// whose bytes carry an integer past i64::MAX is refused by the codec
    /// with `WIRE_INTEGER_OUT_OF_RANGE`, before any row is written.
    #[test]
    fn every_integer_class_keeps_its_range_across_a_reopen() {
        let (_dir, path, six) = kept();
        let i = "11".repeat(16);
        let h = format!("x'{}'", "22".repeat(32));
        let n = format!("x'{}'", "33".repeat(16));
        let db = Db::open_at(&path).unwrap();
        let server: String = db
            .conn
            .query_row("SELECT server_id FROM server_origins", [], |r| r.get(0))
            .unwrap();
        let device = hex(&hash(&six[2]));
        let second = hex(&hash(&six[3]));
        db.conn
            .execute_batch(&format!(
                "INSERT INTO accounts VALUES ('{server}', '{i}', 'a', 'd', 'owner', 'ACTIVE');
                 INSERT INTO device_state VALUES ('{server}', '{i}', 'a', 'd', 'sk', 'hk',
                   'cred:sign', 'cred:hpke', 0);
                 INSERT INTO fleet_key_state VALUES ('{server}', '{i}', '{i}', '{i}', 1, 'k', 'd',
                   '{device}', 'cred:fkek', 'ACTIVE', NULL, 't');
                 INSERT INTO fleet_key_state VALUES ('{server}', '{i}', '{i}', '{i}', 2, 'k2', 'd',
                   '{second}', 'cred:fkek2', 'RETIRED', NULL, 't');
                 INSERT INTO profile_bindings(local_profile_id, server_id, server_instance_id,
                   tenant_id, account_id, device_id, fleet_id, remote_profile_id, remote_version,
                   base_version, accepted_restore_epoch, fkek_key_id, key_generation, sync_state,
                   dirty)
                 VALUES ('p', '{server}', '{i}', '{i}', 'a', 'd', '{i}', '{i}', 0, 0, 0, 'k', 1,
                   'AVAILABLE', 0);
                 INSERT INTO restore_journals VALUES ('p', 'j', 'CREATED', 's', 'b', '{{}}', 0,
                   {h}, 't', 't');
                 INSERT INTO restore_epoch_transitions VALUES ('{server}', '{i}', '{i}', {n}, 0, 1,
                   'PROFILE_HEAD_SET_MERKLE_V2', 1, {h}, 'operator_restore', 'a', 'd', 'k', 0, {n},
                   x'01', {h}, 1, 1, x'01', {h}, x'01', {h}, 't');
                 INSERT INTO restore_epoch_binding_proofs VALUES ('{server}', '{i}', '{i}', 0, 1,
                   '{i}', {h}, {h}, 0, 1000000, x'01', {h}, {h}, x'01', {h}, 't');"
            ))
            .unwrap();
        // The ranges are probed by rewriting rows that are write-once in use;
        // `db` tests those triggers.
        db.conn
            .execute_batch(
                "DROP TRIGGER restore_epoch_transitions_fixed;
                 DROP TRIGGER restore_epoch_binding_proofs_fixed;",
            )
            .unwrap();
        let max = i64::MAX;
        let u32_max = i64::from(u32::MAX);
        let kind = |k: &str| format!("record_kind = '{k}'");
        // (table, column, row, lowest, highest)
        let probes = [
            ("server_origins", "last_restore_epoch", "1".into(), 0, max),
            ("server_origins", "port", "1".into(), 1, 65535),
            ("device_state", "recovery_ready", "1".into(), 0, 1),
            (SIGNED, "verified_at_ms", kind("DeviceApprovalV2"), 0, max),
            (SIGNED, "restore_epoch", kind("DeviceApprovalV2"), 0, max),
            (
                SIGNED,
                "signature_suite_id",
                kind("DeviceApprovalV2"),
                0,
                65535,
            ),
            (
                SIGNED,
                "generation",
                kind("FleetKeyGrantV2::DeviceHpkeGrant"),
                0,
                max,
            ),
            (
                SIGNED,
                "hpke_suite_id",
                kind("FleetKeyGrantV2::DeviceHpkeGrant"),
                0,
                65535,
            ),
            (
                SIGNED,
                "recipient_root_generation",
                kind("FleetKeyGrantV2::RecoveryGrant"),
                0,
                max,
            ),
            (
                SIGNED,
                "required_device_grant_count",
                kind("FleetKeyGrantV2::RotationGrant"),
                0,
                u32_max,
            ),
            (
                "tenant_root_key_generations",
                "required_custodian_grant_count",
                "1".into(),
                1,
                u32_max,
            ),
            (ROOT_GRANTS, "acknowledged_at_ms", "1".into(), 0, max),
            (ROOT_GRANTS, "revoked_at_ms", "1".into(), 0, max),
            (ROOT_GRANTS, "restore_epoch", "1".into(), 0, max),
            (
                "fleet_key_state",
                "generation",
                "fkek_key_id = 'k2'".into(),
                0,
                max,
            ),
            ("restore_journals", "target_version", "1".into(), 0, max),
            (
                "restore_epoch_transitions",
                "issued_at_ms",
                "1".into(),
                0,
                max,
            ),
            (
                "restore_epoch_transitions",
                "mapping_count",
                "1".into(),
                1,
                1_000_000,
            ),
            (
                "restore_epoch_binding_proofs",
                "leaf_index",
                "1".into(),
                0,
                999_999,
            ),
            (
                "profile_bindings",
                "accepted_restore_epoch",
                "1".into(),
                0,
                max,
            ),
        ];
        let set = |table: &str, col: &str, row: &str, v: Sql| {
            db.conn
                .execute(&format!("UPDATE {table} SET {col} = ?1 WHERE {row}"), [v])
        };
        let get = |db: &Db, table: &str, col: &str, row: &str| -> (Sql, String) {
            db.conn
                .query_row(
                    &format!("SELECT {col}, typeof({col}) FROM {table} WHERE {row}"),
                    [],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        };
        for (table, col, row, lo, hi) in &probes {
            let at = format!("{table}.{col}");
            for v in [*lo, *hi] {
                assert_eq!(
                    set(table, col, row, Sql::Integer(v)).unwrap(),
                    1,
                    "{at} = {v}"
                );
            }
            let mut bad = vec![
                Sql::Integer(lo - 1),
                Sql::Real(2f64.powi(63)),
                Sql::Real(u64::MAX as f64),
                Sql::Real(0.5),
                Sql::Text("zero".into()),
                Sql::Text("9223372036854775808".into()),
                Sql::Text("-1".into()),
                Sql::Blob(vec![1]),
            ];
            if *hi < max {
                bad.push(Sql::Integer(hi + 1));
            }
            for v in bad {
                assert!(set(table, col, row, v.clone()).is_err(), "{at} = {v:?}");
                assert_eq!(get(&db, table, col, row).0, Sql::Integer(*hi), "{at}");
            }
            // Lossless conversions land as the exact integer.
            for v in [Sql::Text(hi.to_string()), Sql::Real(*lo as f64)] {
                set(table, col, row, v).unwrap();
            }
            assert_eq!(
                get(&db, table, col, row),
                (Sql::Integer(*lo), "integer".into())
            );
            set(table, col, row, Sql::Integer(*hi)).unwrap();
        }
        drop(db);
        let db = Db::open_at(&path).unwrap();
        for (table, col, row, _, hi) in &probes {
            assert_eq!(
                get(&db, table, col, row),
                (Sql::Integer(*hi), "integer".into()),
                "{table}.{col}"
            );
        }

        // A record carrying not_after_ms = 2^64 - 1 never becomes a row.
        let sk = Ed25519SigningKey::from_bytes(&[7; 32]);
        let me = signing_key_id(sk.verifying_key().as_bytes());
        let mut c = common(9, [0x11; 16]);
        c.not_after_ms = u64::MAX;
        let wide = DeviceApprovalV2 {
            common: c,
            subject_account_id: [3; 16],
            subject_device_id: [4; 16],
            subject_signing_key_id: me,
            subject_hpke_key_id: [9; 32],
            approval_scope_kind: ApprovalScopeKind::Tenant,
            approval_scope_id: [0x22; 16],
        };
        let wide = build_record(&sk, az::DOMAIN_DEVICE_APPROVAL, &wide.encode());
        let code = AuthorizationRecord::parse(&wide).unwrap_err().code();
        assert_eq!(code, "WIRE_INTEGER_OUT_OF_RANGE");
        assert!(keep(&db.conn, URL, &wide, 100).is_err());
        let rows: i64 = db
            .conn
            .query_row(&format!("SELECT count(*) FROM {SIGNED}"), [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 5);
    }
}
