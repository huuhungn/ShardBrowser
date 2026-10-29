//! Plan L401, L2471, L2768: every unsigned wire integer persisted in SQLite
//! lives in `0..=i64::MAX` (narrower where its class is bounded). Per class,
//! the request decoder and the SQL CHECK accept the domain's ends and refuse
//! -1, 2^63, u64::MAX, a float, text and an overlong form; and every INTEGER
//! column of every v2 table carries such an upper-bound CHECK and refuses any
//! value that is not an integer (plan L2045: no REAL/TEXT coercion).
use shardx_team_server::run_migrations;
use shared::envelope_v2::MAX_OBJECT_SIZE;
use shared::fleet_lifecycle::{
    FleetGenerationRef, FleetGenerationTerms, FleetKeyGenerationCreateV2,
};
use shared::profile_lease::{CreateUploadV2, LeaseRef, ProfileRef};
use shared::snapshot_v2::SnapshotManifestV2;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::SqlitePool;

const MAX: u64 = i64::MAX as u64;

// --------------------------------------------------------- the decoder ---

/// A carrier puts `n` into one field of a request and reads it back from
/// the decoded request.
struct Carrier {
    class: &'static str,
    encode: fn(u64) -> Vec<u8>,
    decode: fn(&[u8]) -> Result<u64, String>,
    lo: u64,
    hi: u64,
}

fn upload(edit: fn(&mut CreateUploadV2, u64), n: u64) -> Vec<u8> {
    let mut u = CreateUploadV2 {
        profile: ProfileRef {
            tenant_id: [1; 16],
            fleet_id: [2; 16],
            profile_id: [3; 16],
        },
        snapshot_id: [4; 16],
        manifest_replay_id: [5; 16],
        lease: LeaseRef {
            lease_id: [6; 16],
            fencing_token: 1,
            base_version: 0,
        },
        intent_hash: [7; 32],
        preamble_sha256: [8; 32],
        dek_slot_sha256: [9; 32],
        fkek_key_id: [10; 32],
        key_generation: 0,
        expected_ciphertext_size: 1,
        expected_ciphertext_sha256: [11; 32],
    };
    edit(&mut u, n);
    u.encode()
}

fn manifest(edit: fn(&mut SnapshotManifestV2, u64), n: u64) -> Vec<u8> {
    let mut m = SnapshotManifestV2 {
        snapshot_id: [1; 16],
        tenant_id: [2; 16],
        fleet_id: [3; 16],
        profile_id: [4; 16],
        lease_id: [5; 16],
        target_version: 1,
        base_version: 0,
        fencing_token: 1,
        key_generation: 0,
        fkek_key_id: [6; 32],
        preamble_sha256: [7; 32],
        intent_hash: [8; 32],
        dek_slot_sha256: [9; 32],
        ciphertext_sha256: [10; 32],
        ciphertext_size: 1,
        previous_signed_head_hash: None,
        signer_signing_key_id: [11; 32],
        server_instance_id: [12; 16],
        restore_epoch: 0,
        manifest_replay_id: [13; 16],
        created_at_ms: 0,
    };
    edit(&mut m, n);
    m.encode()
}

fn generation_create(n: u64) -> Vec<u8> {
    FleetKeyGenerationCreateV2 {
        terms: FleetGenerationTerms {
            generation: FleetGenerationRef {
                tenant_id: [1; 16],
                server_instance_id: [2; 16],
                restore_epoch: 0,
                fleet_id: [3; 16],
                generation: 0,
                fkek_key_id: [4; 32],
            },
            required_device_grant_count: u32::try_from(n).unwrap(),
            required_device_grant_set_hash: [5; 32],
            recovery_grant_signed_container_hash: [6; 32],
            rotation: None,
        },
        root_generation: 0,
    }
    .encode()
}

fn carriers() -> Vec<Carrier> {
    vec![
        Carrier {
            class: "version",
            encode: |n| upload(|u, n| u.lease.base_version = n, n),
            decode: |b| {
                CreateUploadV2::parse(b)
                    .map(|u| u.lease.base_version)
                    .map_err(|e| format!("{e:?}"))
            },
            lo: 0,
            hi: MAX,
        },
        Carrier {
            class: "generation",
            encode: |n| upload(|u, n| u.key_generation = n, n),
            decode: |b| {
                CreateUploadV2::parse(b)
                    .map(|u| u.key_generation)
                    .map_err(|e| format!("{e:?}"))
            },
            lo: 0,
            hi: MAX,
        },
        Carrier {
            class: "fence",
            encode: |n| upload(|u, n| u.lease.fencing_token = n, n),
            decode: |b| {
                CreateUploadV2::parse(b)
                    .map(|u| u.lease.fencing_token)
                    .map_err(|e| format!("{e:?}"))
            },
            lo: 0,
            hi: MAX,
        },
        Carrier {
            class: "size",
            encode: |n| upload(|u, n| u.expected_ciphertext_size = n, n),
            decode: |b| {
                CreateUploadV2::parse(b)
                    .map(|u| u.expected_ciphertext_size)
                    .map_err(|e| format!("{e:?}"))
            },
            lo: 1,
            hi: MAX_OBJECT_SIZE,
        },
        Carrier {
            class: "epoch",
            encode: |n| manifest(|m, n| m.restore_epoch = n, n),
            decode: |b| {
                SnapshotManifestV2::parse(b)
                    .map(|m| m.restore_epoch)
                    .map_err(|e| format!("{e:?}"))
            },
            lo: 0,
            hi: MAX,
        },
        Carrier {
            class: "ms timestamp",
            encode: |n| manifest(|m, n| m.created_at_ms = n, n),
            decode: |b| {
                SnapshotManifestV2::parse(b)
                    .map(|m| m.created_at_ms)
                    .map_err(|e| format!("{e:?}"))
            },
            lo: 0,
            hi: MAX,
        },
        Carrier {
            class: "count",
            encode: generation_create,
            decode: |b| {
                FleetKeyGenerationCreateV2::parse(b)
                    .map(|g| g.terms.required_device_grant_count.into())
                    .map_err(|e| format!("{e:?}"))
            },
            lo: 1,
            hi: 65535,
        },
    ]
}

/// The canonical CBOR head of unsigned `n`.
fn uint(n: u64) -> Vec<u8> {
    match n {
        0..=23 => vec![n as u8],
        24..=0xff => vec![0x18, n as u8],
        0x100..=0xffff => [&[0x19][..], &(n as u16).to_be_bytes()].concat(),
        0x1_0000..=0xffff_ffff => [&[0x1a][..], &(n as u32).to_be_bytes()].concat(),
        _ => [&[0x1b][..], &n.to_be_bytes()].concat(),
    }
}

/// `bytes` with the one occurrence of `from` replaced by `to`.
fn splice(bytes: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let at: Vec<usize> = (0..=bytes.len() - from.len())
        .filter(|&i| bytes[i..].starts_with(from))
        .collect();
    assert_eq!(at.len(), 1, "the sentinel is not unique");
    [&bytes[..at[0]], to, &bytes[at[0] + from.len()..]].concat()
}

#[test]
fn every_class_decodes_its_domain_ends_and_refuses_everything_else() {
    for c in carriers() {
        // A value of the domain whose encoding occurs once in the request.
        let sentinel = c.lo + (c.hi - c.lo) / 3 + 0x1234;
        let honest = (c.encode)(sentinel);
        assert_eq!((c.decode)(&honest), Ok(sentinel), "{}", c.class);
        let with = |item: &[u8]| splice(&honest, &uint(sentinel), item);

        for n in [c.lo, c.hi] {
            assert_eq!(
                (c.decode)(&with(&uint(n))),
                Ok(n),
                "{} accepts {n}",
                c.class
            );
        }
        let mut refused = vec![
            ("-1", vec![0x20]),
            ("2^63", uint(MAX + 1)),
            ("u64::MAX", uint(u64::MAX)),
            ("REAL 1.0", [&[0xfb][..], &1.0f64.to_be_bytes()].concat()),
            ("REAL half 0.0", vec![0xf9, 0x00, 0x00]),
            ("TEXT \"1\"", vec![0x61, b'1']),
            ("overlong 1", vec![0x18, 0x01]),
        ];
        if c.hi < MAX {
            refused.push(("hi + 1", uint(c.hi + 1)));
        }
        if c.lo > 0 {
            refused.push(("lo - 1", uint(c.lo - 1)));
        }
        for (name, item) in refused {
            let got = (c.decode)(&with(&item));
            assert!(got.is_err(), "{} accepted {name}: {got:?}", c.class);
        }
    }
}

// ----------------------------------------------------------- the schema ---

async fn pool() -> SqlitePool {
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect("sqlite::memory:")
        .await
        .unwrap();
    run_migrations(&pool).await.unwrap();
    // Only the column's own CHECK is under test; its parents are not.
    sqlx::query("PRAGMA foreign_keys = OFF")
        .execute(&pool)
        .await
        .unwrap();
    pool
}

/// A persisted column of a class, and a row of its table with `{v}` there.
struct Column {
    class: &'static str,
    column: &'static str,
    row: &'static str,
    lo: u64,
    hi: u64,
}

const UPLOAD_ROW: &str = "INSERT INTO v2_uploads (server_instance_id, tenant_id, upload_id,
  fleet_id, profile_id, snapshot_id, manifest_replay_id, lease_id, fencing_token, base_version,
  restore_epoch, operation_scope, idempotency_key, canonical_request_hash, intent_hash,
  preamble_sha256, dek_slot_sha256, fkek_key_id, key_generation, expected_ciphertext_size,
  expected_ciphertext_sha256, committed_offset, staging_path, state, expires_at_ms, created_at_ms)
  VALUES (randomblob(16), randomblob(16), randomblob(16), randomblob(16), randomblob(16),
  randomblob(16), randomblob(16), randomblob(16), {fence}, {version}, {epoch},
  'profile.create-upload.v2', randomblob(16), zeroblob(32), zeroblob(32), zeroblob(32),
  zeroblob(32), zeroblob(32), {generation}, {size}, zeroblob(32), {offset}, 'staging', 'OPEN',
  {ms}, 0)";

fn columns() -> Vec<Column> {
    vec![
        Column {
            class: "version",
            column: "v2_uploads.base_version",
            row: "version",
            lo: 0,
            hi: MAX,
        },
        Column {
            class: "generation",
            column: "v2_uploads.key_generation",
            row: "generation",
            lo: 0,
            hi: MAX,
        },
        Column {
            class: "fence",
            column: "v2_uploads.fencing_token",
            row: "fence",
            lo: 1,
            hi: MAX,
        },
        Column {
            class: "epoch",
            column: "v2_uploads.restore_epoch",
            row: "epoch",
            lo: 0,
            hi: MAX,
        },
        Column {
            class: "ms timestamp",
            column: "v2_uploads.expires_at_ms",
            row: "ms",
            lo: 0,
            hi: MAX,
        },
        Column {
            class: "size",
            column: "v2_uploads.expected_ciphertext_size",
            row: "size",
            lo: 1,
            hi: MAX_OBJECT_SIZE,
        },
        // The committed offset of an upload of the largest size.
        Column {
            class: "offset",
            column: "v2_uploads.committed_offset",
            row: "offset",
            lo: 0,
            hi: MAX_OBJECT_SIZE,
        },
    ]
}

/// The upload row with `v` in the `slot` column and honest values elsewhere.
fn upload_row(slot: &str, v: &str) -> String {
    let mut sql = UPLOAD_ROW.to_string();
    for (name, honest) in [
        ("fence", "1"),
        ("version", "0"),
        ("epoch", "0"),
        ("generation", "0"),
        ("size", "536870912"),
        ("offset", "0"),
        ("ms", "0"),
    ] {
        let value = if name == slot { v } else { honest };
        sql = sql.replace(&format!("{{{name}}}"), value);
    }
    sql
}

/// The SQLite extended result code of a refused statement, or `None`.
async fn refusal(pool: &SqlitePool, sql: &str) -> Option<String> {
    match sqlx::query(sql).execute(pool).await {
        Ok(_) => None,
        Err(e) => Some(e.as_database_error().unwrap().code().unwrap().into_owned()),
    }
}

const CHECK: Option<&str> = Some("275");
/// `SQLITE_CONSTRAINT_TRIGGER`: an integer column's type trigger refused it.
const NOT_INTEGER: Option<&str> = Some("1811");

#[tokio::test]
async fn every_class_column_stores_its_domain_ends_and_its_check_refuses_the_rest() {
    let pool = pool().await;
    for c in columns() {
        let (table, column) = c.column.split_once('.').unwrap();
        for n in [c.lo, c.hi] {
            assert_eq!(
                refusal(&pool, &upload_row(c.row, &n.to_string())).await,
                None,
                "{} {} accepts {n}",
                c.class,
                c.column
            );
            let stored: (i64, String) = sqlx::query_as(&format!(
                "SELECT {column}, typeof({column}) FROM {table} WHERE rowid = last_insert_rowid()"
            ))
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(stored, (n as i64, "integer".into()), "{}", c.column);
        }
        let mut refused = vec![
            "-1".to_string(),
            "9223372036854775808".into(),
            "18446744073709551615".into(),
            // Out-of-domain floats, as REAL and as numeric TEXT.
            "9.3e18".into(),
            "-0.5".into(),
            "'9223372036854775808'".into(),
            // In-range values that are not integers, as REAL and as the
            // numeric TEXT that INTEGER affinity turns into a REAL.
            format!("{}.5", c.lo),
            format!("'{}.5'", c.lo),
            "'one'".into(),
            "x'01'".into(),
            (c.hi + 1).to_string(),
        ];
        if c.lo > 0 {
            refused.push((c.lo - 1).to_string());
        }
        for v in refused {
            // A literal past i64 is a REAL to SQLite, so its type refuses it.
            let want = if v.parse::<i64>().is_ok() {
                CHECK
            } else {
                NOT_INTEGER
            };
            assert_eq!(
                refusal(&pool, &upload_row(c.row, &v)).await.as_deref(),
                want,
                "{} {} refuses {v}",
                c.class,
                c.column
            );
        }
        // An update to a non-integer is refused as well, by the type trigger
        // and not by another of the table's triggers.
        for v in [format!("{}.5", c.lo), format!("'{}.5'", c.lo)] {
            let e = sqlx::query(&format!(
                "UPDATE {table} SET {column} = {v} WHERE rowid = (SELECT max(rowid) FROM {table})"
            ))
            .execute(&pool)
            .await
            .unwrap_err()
            .to_string();
            assert!(
                e.contains("an integer column holds only integers"),
                "{} {} update refuses {v}: {e}",
                c.class,
                c.column
            );
        }
    }
}

/// Whether `col` of the table `sql` creates has a CHECK bounding it inside
/// `0..=i64::MAX`: `col BETWEEN lo AND hi`, by a literal or by another bounded
/// column, or `col = n` / `col IN (n, ...)`.
fn bounded(sql: &str, col: &str, cols: &[String], depth: u8) -> bool {
    let sql = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut at = 0;
    while let Some(i) = sql[at..].find(col).map(|i| i + at) {
        at = i + col.len();
        if sql[..i].chars().next_back().is_some_and(word)
            || sql[at..].chars().next().is_some_and(word)
        {
            continue;
        }
        let rest: Vec<&str> = sql[at..].split(' ').take(5).collect();
        let tok = |k: usize| rest.get(k).map_or("", |t| t.trim_end_matches([')', ',']));
        match (tok(1), tok(3)) {
            ("BETWEEN", "AND") => {
                let (lo, hi) = (tok(2), tok(4));
                if lo.parse::<u64>().is_err() {
                    continue;
                }
                match hi.parse::<u64>() {
                    Ok(hi) if hi <= MAX => return true,
                    Ok(_) => {}
                    Err(_) if depth == 0 && cols.iter().any(|c| c == hi) => {
                        if bounded(&sql, hi, cols, 1) {
                            return true;
                        }
                    }
                    Err(_) => {}
                }
            }
            ("=", _) if tok(2).parse::<u64>().is_ok_and(|n| n <= MAX) => return true,
            ("IN", _)
                if rest.get(2).is_some_and(|t| {
                    t.starts_with("(") && t[1..].starts_with(|c: char| c.is_ascii_digit())
                }) =>
            {
                return true
            }
            _ => {}
        }
    }
    false
}

#[tokio::test]
async fn every_integer_column_of_every_v2_table_has_an_upper_bound_check() {
    let pool = pool().await;
    let tables: Vec<(String, String)> = sqlx::query_as(
        "SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name LIKE 'v2\\_%' ESCAPE '\\'
          ORDER BY name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut checked = 0;
    let mut unbounded = Vec::new();
    for (table, sql) in &tables {
        let cols: Vec<(String, String)> =
            sqlx::query_as("SELECT name, type FROM pragma_table_info(?) ORDER BY cid")
                .bind(table)
                .fetch_all(&pool)
                .await
                .unwrap();
        let names: Vec<String> = cols.iter().map(|(n, _)| n.clone()).collect();
        for (name, ty) in &cols {
            if !ty.eq_ignore_ascii_case("INTEGER") {
                continue;
            }
            checked += 1;
            if !bounded(sql, name, &names, 0) {
                unbounded.push(format!("{table}.{name}"));
            }
        }
    }
    assert!(checked > 150, "only {checked} integer columns found");
    assert!(unbounded.is_empty(), "{unbounded:?}");
}

#[tokio::test]
async fn every_integer_column_of_every_v2_table_refuses_a_value_that_is_no_integer() {
    let pool = pool().await;
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'v2\\_%' ESCAPE '\\'
          ORDER BY name",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    let mut guarded = 0;
    let mut unguarded = Vec::new();
    for table in &tables {
        let cols: Vec<String> = sqlx::query_scalar(
            "SELECT name FROM pragma_table_info(?) WHERE type = 'INTEGER' COLLATE NOCASE
              ORDER BY cid",
        )
        .bind(table)
        .fetch_all(&pool)
        .await
        .unwrap();
        if cols.is_empty() {
            continue;
        }
        let trigger = |event: &'static str| {
            let pool = &pool;
            async move {
                let sql: Option<String> = sqlx::query_scalar(
                    "SELECT sql FROM sqlite_master WHERE type = 'trigger' AND name = ? AND tbl_name = ?",
                )
                .bind(format!("{table}_integers_on_{event}"))
                .bind(table)
                .fetch_optional(pool)
                .await
                .unwrap();
                sql.unwrap_or_default()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
            }
        };
        let (insert, update) = (trigger("insert").await, trigger("update").await);
        let of = update
            .split_once("BEFORE UPDATE OF ")
            .and_then(|(_, rest)| rest.split_once(" ON "))
            .map_or(Vec::new(), |(list, _)| list.split(", ").collect::<Vec<_>>());
        for col in &cols {
            let guard = format!("typeof(NEW.{col}) NOT IN ('integer', 'null')");
            if insert.contains(&guard) && update.contains(&guard) && of.contains(&col.as_str()) {
                guarded += 1;
            } else {
                unguarded.push(format!("{table}.{col}"));
            }
        }
    }
    assert!(unguarded.is_empty(), "{unguarded:?}");
    assert_eq!(guarded, 180);
}

#[test]
fn the_bound_scan_tells_bounded_from_unbounded_columns() {
    let cols = ["a", "b", "size"].map(String::from);
    let ddl = |check: &str| format!("CREATE TABLE t (a INTEGER NOT NULL CHECK ({check}))");
    assert!(bounded(
        &ddl("a BETWEEN 0 AND 9223372036854775807"),
        "a",
        &cols,
        0
    ));
    assert!(bounded(
        &ddl("a IS NULL OR a BETWEEN 1 AND 65535"),
        "a",
        &cols,
        0
    ));
    assert!(bounded(&ddl("a = 2"), "a", &cols, 0));
    assert!(bounded(&ddl("a IN (0, 1)"), "a", &cols, 0));
    assert!(bounded(
        &format!(
            "{}, size INTEGER CHECK (size BETWEEN 1 AND 10)",
            ddl("a BETWEEN 0 AND size")
        ),
        "a",
        &cols,
        0
    ));
    assert!(!bounded(
        &ddl("a BETWEEN 0 AND 9223372036854775808"),
        "a",
        &cols,
        0
    ));
    assert!(!bounded(&ddl("a >= 0"), "a", &cols, 0));
    assert!(!bounded(&ddl("a BETWEEN -1 AND 5"), "a", &cols, 0));
    assert!(!bounded(&ddl("a BETWEEN 0 AND b"), "a", &cols, 0));
    assert!(!bounded(&ddl("ab BETWEEN 0 AND 5"), "a", &cols, 0));
}
