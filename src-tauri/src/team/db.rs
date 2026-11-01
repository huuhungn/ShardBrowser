//! `team-sync.db`, the launcher's local team database (plan 11.1).
//!
//! Every reader goes through [`Db::open`], which creates the schema on an
//! empty file and otherwise runs the plan's startup compatibility query
//! (L2032): exactly one `schema_meta` row, `migration_state = 'CLEAN'`, a
//! `schema_version` this binary reads and a `min_reader_version` it meets.
//! Anything else is refused before any row is read, and the file is left as
//! it was (probe 8, L2043).
//!
//! The journal stays in rollback mode with `synchronous = FULL`: the plan
//! enables WAL only once the Windows crash, checkpoint and busy tests pass
//! (11.3, L2061).
//!
//! The tables so far are `schema_meta`, exactly as the plan's reference DDL
//! (L1450-L1458), and the W6 trust ledger (ADR 0002 D-6, Q-12, Q-13), which
//! the plan's DDL leaves to W6. The ledger keeps hashes, key IDs and times,
//! the exact bytes of counted revocations, and the exact grant behind each
//! collected fleet key with its evidence (G2-35), never a key (L2048).
//! Version 3 adds the plan's `profile_bindings`, `operations` and
//! `upload_sessions` for published-profile sync (`team::sync`), and version
//! 4 the rest of the plan's tables: the kept authorization records and root
//! grants (`team::records`), and the schema of the tables later packages
//! fill. Version 5 lets a restore epoch binding proof outlive its binding.
//! Version 6 brings the three sync tables to the plan's columns and foreign
//! keys: each names its `server_origins` row, a binding its account and its
//! fleet key.

use anyhow::{bail, Context, Result};
use rusqlite::{Connection, TransactionBehavior};
use std::path::Path;

/// The schema this binary writes, and the newest one it reads.
pub const SCHEMA_VERSION: i64 = 7;

/// Version 1, as #188 shipped it.
const SCHEMA_V1: &str = r#"
CREATE TABLE schema_meta (
  singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
  schema_version      INTEGER NOT NULL CHECK (schema_version BETWEEN 1 AND 9223372036854775807),
  min_reader_version  INTEGER NOT NULL CHECK (min_reader_version BETWEEN 1 AND 9223372036854775807),
  migration_state     TEXT NOT NULL CHECK (migration_state IN ('CLEAN','MIGRATING','RECOVERY_REQUIRED')),
  applied_at          TEXT NOT NULL
) STRICT;
INSERT INTO schema_meta(singleton, schema_version, min_reader_version, migration_state, applied_at)
VALUES (1, 1, 1, 'CLEAN', '1970-01-01T00:00:00Z');

-- The anchor A0 pinned per (instance, tenant). BOOTSTRAP: the device that
-- bootstrapped custody. JOIN: the Q-12 join ceremony, which has not shipped.
-- A pin never changes: a server-supplied new anchor is never accepted.
CREATE TABLE trust_anchors (
  server_instance_id TEXT NOT NULL CHECK (length(server_instance_id) = 32 AND server_instance_id NOT GLOB '*[^0-9a-f]*'),
  tenant_id          TEXT NOT NULL CHECK (length(tenant_id) = 32 AND tenant_id NOT GLOB '*[^0-9a-f]*'),
  anchor_key_id      TEXT NOT NULL CHECK (length(anchor_key_id) = 64 AND anchor_key_id NOT GLOB '*[^0-9a-f]*'),
  source             TEXT NOT NULL CHECK (source IN ('BOOTSTRAP','JOIN')),
  pinned_at_ms       INTEGER NOT NULL CHECK (pinned_at_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id)
) STRICT;

-- One row per trust-evidence evaluation; its ID orders first sightings
-- against counted revocations (ADR 0002 rule 1, "Order").
CREATE TABLE trust_evaluations (
  evaluation_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  server_instance_id TEXT NOT NULL,
  tenant_id          TEXT NOT NULL,
  evaluated_at_ms    INTEGER NOT NULL CHECK (evaluated_at_ms BETWEEN 0 AND 9223372036854775807),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

-- The first local sighting of each container (D-6 (d), (e)).
CREATE TABLE trust_sightings (
  server_instance_id    TEXT NOT NULL,
  tenant_id             TEXT NOT NULL,
  signed_container_hash TEXT NOT NULL CHECK (length(signed_container_hash) = 64 AND signed_container_hash NOT GLOB '*[^0-9a-f]*'),
  issuer_signing_key_id TEXT NOT NULL CHECK (length(issuer_signing_key_id) = 64 AND issuer_signing_key_id NOT GLOB '*[^0-9a-f]*'),
  first_seen_evaluation INTEGER NOT NULL REFERENCES trust_evaluations(evaluation_id) ON DELETE RESTRICT,
  first_seen_ms         INTEGER NOT NULL CHECK (first_seen_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id, signed_container_hash),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

-- Server revocation reports, kept at their earliest time: they only tighten.
CREATE TABLE trust_reported_revocations (
  server_instance_id TEXT NOT NULL,
  tenant_id          TEXT NOT NULL,
  payload_domain     TEXT NOT NULL,
  replay_id          TEXT NOT NULL CHECK (length(replay_id) = 32 AND replay_id NOT GLOB '*[^0-9a-f]*'),
  revoked_at_ms      INTEGER NOT NULL CHECK (revoked_at_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id, payload_domain, replay_id),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE trust_reported_device_revocations (
  server_instance_id TEXT NOT NULL,
  tenant_id          TEXT NOT NULL,
  device_id          TEXT NOT NULL CHECK (length(device_id) = 32 AND device_id NOT GLOB '*[^0-9a-f]*'),
  revoked_at_ms      INTEGER NOT NULL CHECK (revoked_at_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id, device_id),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

-- Keys this device holds as proven revoked: a counted DeviceRevocationV2
-- (Q-13, with its exact container) or local distrust (D-6 (d)). Records by
-- the key first seen after `counted_evaluation` are unusable.
CREATE TABLE trust_proven_revocations (
  server_instance_id           TEXT NOT NULL,
  tenant_id                    TEXT NOT NULL,
  signing_key_id               TEXT NOT NULL CHECK (length(signing_key_id) = 64 AND signing_key_id NOT GLOB '*[^0-9a-f]*'),
  source                       TEXT NOT NULL CHECK (source IN ('DEVICE_REVOCATION','LOCAL_DISTRUST')),
  counted_evaluation           INTEGER NOT NULL CHECK (counted_evaluation BETWEEN 0 AND 9223372036854775807),
  counted_at_ms                INTEGER NOT NULL CHECK (counted_at_ms BETWEEN 0 AND 9223372036854775807),
  exact_signed_container_bytes BLOB,
  PRIMARY KEY(server_instance_id, tenant_id, signing_key_id, source),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT,
  CHECK ((source = 'DEVICE_REVOCATION') = (exact_signed_container_bytes IS NOT NULL))
) STRICT;

-- ADR 0002 "Fleet generation freshness": the highest generation verified
-- per fleet.
CREATE TABLE trust_fleet_generations (
  server_instance_id          TEXT NOT NULL,
  tenant_id                   TEXT NOT NULL,
  fleet_id                    TEXT NOT NULL CHECK (length(fleet_id) = 32 AND fleet_id NOT GLOB '*[^0-9a-f]*'),
  highest_verified_generation INTEGER NOT NULL CHECK (highest_verified_generation BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id, fleet_id),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

-- What the ledger learns is never taken back.
CREATE TRIGGER trust_anchors_fixed BEFORE UPDATE ON trust_anchors
BEGIN SELECT RAISE(ABORT, 'a pinned anchor never changes'); END;
CREATE TRIGGER trust_anchors_kept BEFORE DELETE ON trust_anchors
BEGIN SELECT RAISE(ABORT, 'a pinned anchor is never forgotten'); END;
CREATE TRIGGER trust_evaluations_kept BEFORE DELETE ON trust_evaluations
BEGIN SELECT RAISE(ABORT, 'an evaluation is never forgotten'); END;
CREATE TRIGGER trust_sightings_kept BEFORE DELETE ON trust_sightings
BEGIN SELECT RAISE(ABORT, 'a first sighting is never forgotten'); END;
CREATE TRIGGER trust_fleet_generations_kept BEFORE DELETE ON trust_fleet_generations
BEGIN SELECT RAISE(ABORT, 'a verified generation is never forgotten'); END;
CREATE TRIGGER trust_proven_revocations_fixed BEFORE UPDATE ON trust_proven_revocations
BEGIN SELECT RAISE(ABORT, 'a proven revocation never changes'); END;
CREATE TRIGGER trust_proven_revocations_kept BEFORE DELETE ON trust_proven_revocations
BEGIN SELECT RAISE(ABORT, 'a proven revocation is never forgotten'); END;
CREATE TRIGGER trust_reported_revocations_kept BEFORE DELETE ON trust_reported_revocations
BEGIN SELECT RAISE(ABORT, 'a reported revocation is never forgotten'); END;
CREATE TRIGGER trust_reported_revocations_earlier BEFORE UPDATE ON trust_reported_revocations
WHEN NEW.revoked_at_ms > OLD.revoked_at_ms
BEGIN SELECT RAISE(ABORT, 'a reported revocation only moves earlier'); END;
CREATE TRIGGER trust_reported_device_revocations_kept BEFORE DELETE ON trust_reported_device_revocations
BEGIN SELECT RAISE(ABORT, 'a reported revocation is never forgotten'); END;
CREATE TRIGGER trust_reported_device_revocations_earlier BEFORE UPDATE ON trust_reported_device_revocations
WHEN NEW.revoked_at_ms > OLD.revoked_at_ms
BEGIN SELECT RAISE(ABORT, 'a reported revocation only moves earlier'); END;
CREATE TRIGGER trust_fleet_generations_forward BEFORE UPDATE ON trust_fleet_generations
WHEN NEW.highest_verified_generation < OLD.highest_verified_generation
BEGIN SELECT RAISE(ABORT, 'a verified generation never goes backwards'); END;
"#;

/// Version 1 to 2: the custodian keys of D-6 (a)-(c) and the fleet key
/// grants of G2-35. A version 1 reader would skip them, so 2 is also the
/// minimum reader.
const MIGRATE_V2: &str = r#"
-- D-6 (a)-(c): each key a counted root grant made a custodian. The earliest
-- not_before and latest end of its counted root grants: the first starts the
-- 1095-day clip and only moves earlier, the second only moves later. The
-- first evaluation that found that known custody ended, and its local time,
-- is the key's sticky lapse.
CREATE TABLE trust_custodian_keys (
  server_instance_id    TEXT NOT NULL,
  tenant_id             TEXT NOT NULL,
  signing_key_id        TEXT NOT NULL CHECK (length(signing_key_id) = 64 AND signing_key_id NOT GLOB '*[^0-9a-f]*'),
  first_seen_evaluation INTEGER NOT NULL REFERENCES trust_evaluations(evaluation_id) ON DELETE RESTRICT,
  first_not_before_ms   INTEGER NOT NULL CHECK (first_not_before_ms BETWEEN 0 AND 9223372036854775807),
  latest_not_after_ms   INTEGER NOT NULL CHECK (latest_not_after_ms BETWEEN 0 AND 9223372036854775807),
  lapsed_evaluation     INTEGER REFERENCES trust_evaluations(evaluation_id) ON DELETE RESTRICT,
  observed_lapsed_at_ms INTEGER CHECK (observed_lapsed_at_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_instance_id, tenant_id, signing_key_id),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT,
  CHECK ((lapsed_evaluation IS NULL) = (observed_lapsed_at_ms IS NULL))
) STRICT;

-- G2-35 (plan L2056): the exact DeviceHpkeGrant behind each fleet key this
-- device collected, and the pages it verified against, so sync can reverify
-- it before using the key; the key itself is never here.
CREATE TABLE trust_fleet_key_grants (
  server_instance_id           TEXT NOT NULL,
  tenant_id                    TEXT NOT NULL,
  fleet_id                     TEXT NOT NULL CHECK (length(fleet_id) = 32 AND fleet_id NOT GLOB '*[^0-9a-f]*'),
  generation                   INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
  fkek_key_id                  TEXT NOT NULL CHECK (length(fkek_key_id) = 64 AND fkek_key_id NOT GLOB '*[^0-9a-f]*'),
  verified_evaluation          INTEGER NOT NULL REFERENCES trust_evaluations(evaluation_id) ON DELETE RESTRICT,
  exact_signed_container_bytes BLOB NOT NULL,
  evidence_pages               BLOB NOT NULL,
  PRIMARY KEY(server_instance_id, tenant_id, fleet_id, generation),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER trust_custodian_keys_kept BEFORE DELETE ON trust_custodian_keys
BEGIN SELECT RAISE(ABORT, 'a custodian key is never forgotten'); END;
CREATE TRIGGER trust_custodian_keys_earlier BEFORE UPDATE ON trust_custodian_keys
WHEN NEW.first_not_before_ms > OLD.first_not_before_ms
  OR NEW.first_seen_evaluation IS NOT OLD.first_seen_evaluation
BEGIN SELECT RAISE(ABORT, 'a cached first_not_before only moves earlier'); END;
CREATE TRIGGER trust_custodian_keys_later BEFORE UPDATE ON trust_custodian_keys
WHEN NEW.latest_not_after_ms < OLD.latest_not_after_ms
BEGIN SELECT RAISE(ABORT, 'a known custody end only moves later'); END;
CREATE TRIGGER trust_custodian_keys_lapse_kept BEFORE UPDATE ON trust_custodian_keys
WHEN OLD.lapsed_evaluation IS NOT NULL
  AND (NEW.lapsed_evaluation IS NOT OLD.lapsed_evaluation
       OR NEW.observed_lapsed_at_ms IS NOT OLD.observed_lapsed_at_ms)
BEGIN SELECT RAISE(ABORT, 'an observed lapse never changes'); END;
UPDATE schema_meta SET schema_version = 2, min_reader_version = 2,
  applied_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now');
"#;

/// Version 2 to 3: the sync tables of the plan's reference DDL, with the
/// columns the published-profile push and pull use (`team::sync`). The plan's
/// `server_origins`, `accounts` and `fleet_key_state` do not exist yet, so
/// the `server_id`, `account_id`/`device_id` and FKEK foreign keys are left
/// out with their columns; every PK, UNIQUE and CHECK on a kept column stays.
/// A version 2 reader would skip pending operations, so 3 is the minimum.
const MIGRATE_V3: &str = r#"
-- Plan L1773-L1808. `accepted_restore_epoch` is the epoch the binding has
-- accepted (ADR 0002 rule 6, Q-1); `remote_version` with
-- `last_observed_head_hash` is the pinned head.
CREATE TABLE profile_bindings (
  local_profile_id        TEXT PRIMARY KEY,
  server_instance_id      TEXT NOT NULL CHECK (length(server_instance_id) = 32 AND server_instance_id NOT GLOB '*[^0-9a-f]*'),
  tenant_id               TEXT NOT NULL CHECK (length(tenant_id) = 32 AND tenant_id NOT GLOB '*[^0-9a-f]*'),
  fleet_id                TEXT NOT NULL CHECK (length(fleet_id) = 32 AND fleet_id NOT GLOB '*[^0-9a-f]*'),
  remote_profile_id       TEXT NOT NULL CHECK (length(remote_profile_id) = 32 AND remote_profile_id NOT GLOB '*[^0-9a-f]*'),
  remote_version          INTEGER NOT NULL CHECK (remote_version BETWEEN 0 AND 9223372036854775807),
  last_observed_head_hash BLOB CHECK (last_observed_head_hash IS NULL OR length(last_observed_head_hash) = 32),
  accepted_restore_epoch  INTEGER NOT NULL CHECK (accepted_restore_epoch BETWEEN 0 AND 9223372036854775807),
  fencing_token           INTEGER CHECK (fencing_token IS NULL OR fencing_token BETWEEN 0 AND 9223372036854775807),
  lease_id                TEXT,
  sync_state              TEXT NOT NULL CHECK (sync_state IN (
                            'LOCAL','AVAILABLE','CHECKED_OUT','LEASE_AT_RISK','OFFLINE_FORK',
                            'UPLOADING','RESTORE_REQUIRED','CONFLICT','QUARANTINED'
                          )),
  last_error_code         TEXT,
  UNIQUE(server_instance_id, tenant_id, remote_profile_id),
  CHECK ((lease_id IS NULL) = (fencing_token IS NULL)),
  CHECK ((remote_version = 0) = (last_observed_head_hash IS NULL))
) STRICT;

-- Plan L1810-L1870.
CREATE TABLE operations (
  op_id             TEXT PRIMARY KEY,
  local_profile_id  TEXT REFERENCES profile_bindings(local_profile_id) ON DELETE SET NULL,
  local_profile_id_at_request TEXT NOT NULL,
  server_instance_id TEXT NOT NULL,
  restore_epoch     INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
  tenant_id         TEXT NOT NULL,
  fleet_id          TEXT,
  remote_profile_id TEXT,
  snapshot_id       BLOB CHECK (snapshot_id IS NULL OR length(snapshot_id) = 16),
  manifest_replay_id BLOB CHECK (manifest_replay_id IS NULL OR length(manifest_replay_id) = 16),
  operation_scope   TEXT NOT NULL,
  kind              TEXT NOT NULL CHECK (kind IN ('PUBLISH','CHECKOUT','UPLOAD','FINALIZE','COMMIT','RELEASE','UNBIND','RECOVERY_EXPORT')),
  idempotency_key   TEXT NOT NULL,
  canonical_request_hash BLOB NOT NULL CHECK (length(canonical_request_hash) = 32),
  exact_request_bytes BLOB NOT NULL CHECK (length(exact_request_bytes) > 0),
  exact_request_bytes_sha256 BLOB NOT NULL CHECK (length(exact_request_bytes_sha256) = 32),
  remote_upload_id  TEXT,
  lease_id          TEXT,
  fencing_token     INTEGER CHECK (fencing_token IS NULL OR fencing_token BETWEEN 0 AND 9223372036854775807),
  base_version      INTEGER CHECK (base_version IS NULL OR base_version BETWEEN 0 AND 9223372036854775807),
  intent_hash       BLOB CHECK (intent_hash IS NULL OR length(intent_hash) = 32),
  ciphertext_sha256 BLOB CHECK (ciphertext_sha256 IS NULL OR length(ciphertext_sha256) = 32),
  signed_manifest_container_bytes BLOB,
  signed_manifest_container_hash BLOB CHECK (
    signed_manifest_container_hash IS NULL OR length(signed_manifest_container_hash) = 32
  ),
  signed_manifest_container_bytes_sha256 BLOB CHECK (
    signed_manifest_container_bytes_sha256 IS NULL OR length(signed_manifest_container_bytes_sha256) = 32
  ),
  state             TEXT NOT NULL CHECK (state IN ('PENDING','RUNNING','AWAITING_RETRY','COMPLETED','FAILED','QUARANTINED')),
  response_record_type TEXT,
  exact_response_bytes BLOB,
  exact_response_bytes_sha256 BLOB CHECK (
    exact_response_bytes_sha256 IS NULL OR length(exact_response_bytes_sha256) = 32
  ),
  exact_receipt_bytes BLOB,
  receipt_sha256   BLOB CHECK (receipt_sha256 IS NULL OR length(receipt_sha256) = 32),
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  UNIQUE(operation_scope, idempotency_key),
  UNIQUE(op_id, server_instance_id, restore_epoch),
  CHECK ((exact_response_bytes IS NULL) = (exact_response_bytes_sha256 IS NULL)),
  CHECK ((exact_response_bytes IS NULL) = (response_record_type IS NULL)),
  CHECK ((exact_receipt_bytes IS NULL) = (receipt_sha256 IS NULL)),
  CHECK ((signed_manifest_container_bytes IS NULL) = (signed_manifest_container_hash IS NULL)),
  CHECK ((signed_manifest_container_bytes IS NULL) = (signed_manifest_container_bytes_sha256 IS NULL)),
  CHECK (state <> 'COMPLETED' OR exact_response_bytes IS NOT NULL),
  CHECK (state <> 'COMPLETED' OR kind NOT IN ('COMMIT','RELEASE','UNBIND') OR exact_receipt_bytes IS NOT NULL),
  CHECK (kind <> 'COMMIT' OR (
    remote_upload_id IS NOT NULL AND lease_id IS NOT NULL AND fencing_token IS NOT NULL AND
    base_version IS NOT NULL AND snapshot_id IS NOT NULL AND manifest_replay_id IS NOT NULL AND
    intent_hash IS NOT NULL AND ciphertext_sha256 IS NOT NULL AND
    signed_manifest_container_bytes IS NOT NULL
  ))
) STRICT;

-- Plan L1872-L1929; `spool_ref` names `team-sync/spool/<it>.part`.
CREATE TABLE upload_sessions (
  upload_local_id             TEXT PRIMARY KEY,
  local_profile_id            TEXT REFERENCES profile_bindings(local_profile_id) ON DELETE SET NULL,
  local_profile_id_at_request TEXT NOT NULL,
  commit_op_id                TEXT NOT NULL UNIQUE REFERENCES operations(op_id) ON DELETE RESTRICT,
  server_instance_id          TEXT NOT NULL,
  restore_epoch               INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
  tenant_id                   TEXT NOT NULL,
  fleet_id                    TEXT NOT NULL,
  remote_profile_id           TEXT NOT NULL,
  remote_upload_id            TEXT NOT NULL,
  snapshot_id                 BLOB NOT NULL CHECK (length(snapshot_id) = 16),
  manifest_replay_id          BLOB NOT NULL CHECK (length(manifest_replay_id) = 16),
  intent_hash                 BLOB NOT NULL CHECK (length(intent_hash) = 32),
  preamble_sha256             BLOB NOT NULL CHECK (length(preamble_sha256) = 32),
  dek_slot_sha256             BLOB NOT NULL CHECK (length(dek_slot_sha256) = 32),
  fkek_key_id                 TEXT NOT NULL,
  key_generation              INTEGER NOT NULL CHECK (key_generation BETWEEN 0 AND 9223372036854775807),
  committed_offset            INTEGER NOT NULL DEFAULT 0 CHECK (committed_offset BETWEEN 0 AND 9223372036854775807),
  expected_ciphertext_sha256  BLOB NOT NULL CHECK (length(expected_ciphertext_sha256) = 32),
  expected_ciphertext_size    INTEGER NOT NULL CHECK (expected_ciphertext_size BETWEEN 0 AND 9223372036854775807),
  spool_ref                   TEXT NOT NULL CHECK (
                                length(spool_ref) > 0 AND
                                instr(spool_ref, '/') = 0 AND instr(spool_ref, char(92)) = 0
                              ),
  state                       TEXT NOT NULL CHECK (state IN ('OPEN','FINALIZING','READY','COMMITTED','ABORTED','QUARANTINED')),
  exact_finalize_response_bytes BLOB,
  finalize_response_sha256    BLOB CHECK (finalize_response_sha256 IS NULL OR length(finalize_response_sha256) = 32),
  exact_commit_receipt_binding_bytes BLOB,
  commit_receipt_binding_bytes_sha256 BLOB CHECK (
    commit_receipt_binding_bytes_sha256 IS NULL OR length(commit_receipt_binding_bytes_sha256) = 32
  ),
  created_at                  TEXT NOT NULL,
  updated_at                  TEXT NOT NULL,
  UNIQUE(server_instance_id, tenant_id, remote_upload_id),
  UNIQUE(server_instance_id, tenant_id, remote_profile_id, snapshot_id),
  UNIQUE(server_instance_id, tenant_id, remote_profile_id, manifest_replay_id),
  FOREIGN KEY(commit_op_id, server_instance_id, restore_epoch)
    REFERENCES operations(op_id, server_instance_id, restore_epoch) ON DELETE RESTRICT,
  CHECK (committed_offset <= expected_ciphertext_size),
  CHECK ((exact_finalize_response_bytes IS NULL) = (finalize_response_sha256 IS NULL)),
  CHECK ((exact_commit_receipt_binding_bytes IS NULL) = (commit_receipt_binding_bytes_sha256 IS NULL)),
  CHECK (state NOT IN ('READY','COMMITTED') OR exact_finalize_response_bytes IS NOT NULL),
  CHECK (state <> 'COMMITTED' OR exact_commit_receipt_binding_bytes IS NOT NULL)
) STRICT;
UPDATE schema_meta SET schema_version = 3, min_reader_version = 3,
  applied_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now');
"#;

/// Version 3 to 4: the rest of the plan's reference DDL (L1460-L1771,
/// L1931-L2029), as written there. The one change: version 3's
/// `profile_bindings` has no `server_id` yet, so a binding proof names its
/// binding by the instance-keyed UNIQUE the plan also declares (L1797). A
/// version 3 reader would skip the kept records `team::records` checks
/// before key use, so 4 is the minimum.
const MIGRATE_V4: &str = r#"
CREATE TABLE server_origins (
  server_id                 TEXT PRIMARY KEY,
  scheme                    TEXT NOT NULL CHECK (scheme IN ('https','http')),
  host                      TEXT NOT NULL CHECK (
                              length(host) BETWEEN 1 AND 253 AND
                              host = lower(trim(host)) AND
                              instr(host, '/') = 0 AND instr(host, '?') = 0 AND
                              instr(host, '#') = 0 AND instr(host, '@') = 0 AND
                              instr(host, ' ') = 0
                            ),
  port                      INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
  origin                    TEXT GENERATED ALWAYS AS
                              (scheme || '://' || host || ':' || CAST(port AS TEXT)) STORED,
  tls_policy                TEXT NOT NULL CHECK (tls_policy IN ('SYSTEM','PINNED')),
  server_instance_id        TEXT NOT NULL,
  last_restore_epoch        INTEGER NOT NULL CHECK (last_restore_epoch BETWEEN 0 AND 9223372036854775807),
  status                    TEXT NOT NULL CHECK (status IN ('ACTIVE','QUARANTINED','DISABLED')),
  UNIQUE(origin),
  UNIQUE(server_id, server_instance_id),
  CHECK (scheme = 'https' OR host IN ('127.0.0.1','localhost','[::1]'))
) STRICT;

CREATE TABLE accounts (
  server_id       TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  tenant_id       TEXT NOT NULL,
  account_id      TEXT NOT NULL,
  device_id       TEXT NOT NULL,
  role            TEXT NOT NULL CHECK (role IN ('owner','admin','member')),
  status          TEXT NOT NULL CHECK (status IN ('ACTIVE','REVOKED','AUTH_REQUIRED')),
  PRIMARY KEY(server_id, tenant_id, account_id, device_id),
  UNIQUE(server_id, tenant_id, device_id)
) STRICT;

CREATE TABLE device_state (
  server_id              TEXT NOT NULL,
  tenant_id              TEXT NOT NULL,
  account_id             TEXT NOT NULL,
  device_id              TEXT NOT NULL,
  signing_key_id         TEXT NOT NULL,
  hpke_key_id            TEXT NOT NULL,
  signing_credential_ref TEXT NOT NULL UNIQUE,
  hpke_credential_ref    TEXT NOT NULL UNIQUE,
  recovery_ready         INTEGER NOT NULL CHECK (recovery_ready IN (0,1)),
  PRIMARY KEY(server_id, tenant_id, device_id),
  FOREIGN KEY(server_id, tenant_id, account_id, device_id)
    REFERENCES accounts(server_id, tenant_id, account_id, device_id) ON DELETE CASCADE,
  CHECK (signing_key_id <> hpke_key_id),
  CHECK (signing_credential_ref <> hpke_credential_ref)
) STRICT;

CREATE TABLE signed_authorization_records (
  record_id                           TEXT PRIMARY KEY,
  server_id                           TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  tenant_id                           TEXT NOT NULL,
  record_kind                         TEXT NOT NULL CHECK (record_kind IN (
                                        'DeviceApprovalV2','TenantCapabilityGrantV2',
                                        'FleetKeyGrantV2::DeviceHpkeGrant',
                                        'FleetKeyGrantV2::RecoveryGrant',
                                        'FleetKeyGrantV2::RotationGrant'
                                      )),
  container_domain                    TEXT NOT NULL CHECK (container_domain = 'shardx.authorization.signed-container.v2'),
  container_version                   INTEGER NOT NULL CHECK (container_version = 2),
  payload_domain                      TEXT NOT NULL,
  payload_version                     INTEGER NOT NULL CHECK (payload_version = 2),
  replay_id                           BLOB NOT NULL CHECK (length(replay_id) = 16),
  subject_kind                        TEXT CHECK (subject_kind IN ('account','device')),
  subject_account_id                  TEXT,
  subject_device_id                   TEXT,
  subject_signing_key_id              TEXT,
  subject_hpke_key_id                 TEXT,
  approval_scope_kind                 TEXT CHECK (approval_scope_kind IN ('tenant','fleet')),
  approval_scope_id                   TEXT,
  approved_use                        TEXT CHECK (approved_use IS NULL OR approved_use = 'team.device'),
  scope_kind                          TEXT CHECK (scope_kind IN ('tenant','fleet','profile')),
  scope_id                            TEXT,
  capability                          TEXT,
  grant_variant                       TEXT CHECK (grant_variant IN ('DeviceHpkeGrant','RecoveryGrant','RotationGrant')),
  fleet_id                            TEXT,
  fkek_key_id                         TEXT,
  generation                          INTEGER CHECK (generation IS NULL OR generation BETWEEN 0 AND 9223372036854775807),
  grant_capability                    TEXT,
  recipient_hpke_key_id               TEXT,
  hpke_suite_id                       INTEGER CHECK (hpke_suite_id IS NULL OR hpke_suite_id BETWEEN 0 AND 65535),
  hpke_info_bytes                     BLOB,
  hpke_encapped_key_bytes             BLOB,
  hpke_wrapped_fleet_key_bytes        BLOB,
  recipient_root_key_id               TEXT,
  recipient_root_generation           INTEGER CHECK (recipient_root_generation IS NULL OR recipient_root_generation BETWEEN 0 AND 9223372036854775807),
  root_wrap_suite_id                  INTEGER CHECK (root_wrap_suite_id IS NULL OR root_wrap_suite_id BETWEEN 0 AND 65535),
  root_wrap_nonce_bytes               BLOB,
  root_wrap_context_bytes             BLOB,
  wrapped_fleet_key_bytes             BLOB,
  previous_fkek_key_id                TEXT,
  previous_generation                 INTEGER CHECK (previous_generation IS NULL OR previous_generation BETWEEN 0 AND 9223372036854775807),
  required_device_grant_count         INTEGER CHECK (required_device_grant_count IS NULL OR required_device_grant_count BETWEEN 0 AND 4294967295),
  required_device_grant_set_hash      BLOB CHECK (required_device_grant_set_hash IS NULL OR length(required_device_grant_set_hash) = 32),
  recovery_grant_signed_container_hash BLOB CHECK (recovery_grant_signed_container_hash IS NULL OR length(recovery_grant_signed_container_hash) = 32),
  activation_not_before_ms            INTEGER CHECK (activation_not_before_ms IS NULL OR activation_not_before_ms BETWEEN 0 AND 9223372036854775807),
  issued_at_ms                        INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
  not_before_ms                       INTEGER NOT NULL CHECK (not_before_ms BETWEEN 0 AND 9223372036854775807),
  not_after_ms                        INTEGER NOT NULL CHECK (
                                         not_after_ms BETWEEN 0 AND 9223372036854775807 AND
                                         not_after_ms > not_before_ms
                                       ),
  server_instance_id                  TEXT NOT NULL,
  restore_epoch                       INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
  canonical_payload_bytes             BLOB NOT NULL CHECK (length(canonical_payload_bytes) > 0),
  payload_sha256                      BLOB NOT NULL CHECK (length(payload_sha256) = 32),
  signature_suite_id                  INTEGER NOT NULL CHECK (signature_suite_id BETWEEN 0 AND 65535),
  signature_version                   INTEGER NOT NULL CHECK (signature_version = 1),
  issuer_signing_key_id               TEXT NOT NULL,
  signature_bytes                     BLOB NOT NULL CHECK (length(signature_bytes) > 0),
  signed_container_hash               BLOB NOT NULL CHECK (length(signed_container_hash) = 32),
  exact_signed_container_bytes        BLOB NOT NULL CHECK (length(exact_signed_container_bytes) > 0),
  exact_signed_container_bytes_sha256 BLOB NOT NULL CHECK (length(exact_signed_container_bytes_sha256) = 32),
  verified_at_ms                      INTEGER NOT NULL CHECK (verified_at_ms BETWEEN 0 AND 9223372036854775807),
  revoked_at_ms                       INTEGER CHECK (
                                         revoked_at_ms IS NULL OR
                                         (revoked_at_ms BETWEEN 0 AND 9223372036854775807 AND revoked_at_ms >= issued_at_ms)
                                       ),
  UNIQUE(server_id, tenant_id, payload_domain, replay_id),
  CHECK (issued_at_ms <= not_before_ms),
  CHECK (
    (record_kind = 'DeviceApprovalV2' AND
      payload_domain = 'shardx.auth.device-approval.v2' AND
      subject_account_id IS NOT NULL AND subject_device_id IS NOT NULL AND
      subject_signing_key_id IS NOT NULL AND subject_hpke_key_id IS NOT NULL AND
      approval_scope_kind IS NOT NULL AND approval_scope_id IS NOT NULL AND approved_use = 'team.device' AND
      subject_kind IS NULL AND scope_kind IS NULL AND scope_id IS NULL AND capability IS NULL AND
      grant_variant IS NULL AND fleet_id IS NULL AND fkek_key_id IS NULL AND generation IS NULL AND grant_capability IS NULL AND
      recipient_hpke_key_id IS NULL AND hpke_suite_id IS NULL AND hpke_info_bytes IS NULL AND
      hpke_encapped_key_bytes IS NULL AND hpke_wrapped_fleet_key_bytes IS NULL AND
      recipient_root_key_id IS NULL AND recipient_root_generation IS NULL AND root_wrap_suite_id IS NULL AND
      root_wrap_nonce_bytes IS NULL AND root_wrap_context_bytes IS NULL AND wrapped_fleet_key_bytes IS NULL AND
      previous_fkek_key_id IS NULL AND previous_generation IS NULL AND required_device_grant_count IS NULL AND
      required_device_grant_set_hash IS NULL AND recovery_grant_signed_container_hash IS NULL AND activation_not_before_ms IS NULL) OR
    (record_kind = 'TenantCapabilityGrantV2' AND
      payload_domain = 'shardx.auth.tenant-capability-grant.v2' AND
      subject_kind IS NOT NULL AND subject_account_id IS NOT NULL AND
      scope_kind IS NOT NULL AND scope_id IS NOT NULL AND capability IS NOT NULL AND
      approval_scope_kind IS NULL AND approval_scope_id IS NULL AND approved_use IS NULL AND
      grant_variant IS NULL AND fleet_id IS NULL AND fkek_key_id IS NULL AND generation IS NULL AND grant_capability IS NULL AND
      recipient_hpke_key_id IS NULL AND hpke_suite_id IS NULL AND hpke_info_bytes IS NULL AND
      hpke_encapped_key_bytes IS NULL AND hpke_wrapped_fleet_key_bytes IS NULL AND
      recipient_root_key_id IS NULL AND recipient_root_generation IS NULL AND root_wrap_suite_id IS NULL AND
      root_wrap_nonce_bytes IS NULL AND root_wrap_context_bytes IS NULL AND wrapped_fleet_key_bytes IS NULL AND
      previous_fkek_key_id IS NULL AND previous_generation IS NULL AND required_device_grant_count IS NULL AND
      required_device_grant_set_hash IS NULL AND recovery_grant_signed_container_hash IS NULL AND activation_not_before_ms IS NULL AND
      ((subject_kind = 'account' AND subject_device_id IS NULL AND subject_signing_key_id IS NULL AND subject_hpke_key_id IS NULL) OR
       (subject_kind = 'device' AND subject_device_id IS NOT NULL AND subject_signing_key_id IS NOT NULL AND subject_hpke_key_id IS NOT NULL))) OR
    (record_kind = 'FleetKeyGrantV2::DeviceHpkeGrant' AND
      payload_domain = 'shardx.keys.fleet-key-grant.device-hpke.v2' AND grant_variant = 'DeviceHpkeGrant' AND
      fleet_id IS NOT NULL AND fkek_key_id IS NOT NULL AND generation IS NOT NULL AND
      grant_capability = 'fleet.key.receive' AND subject_account_id IS NOT NULL AND subject_device_id IS NOT NULL AND
      subject_signing_key_id IS NOT NULL AND recipient_hpke_key_id IS NOT NULL AND
      hpke_suite_id IS NOT NULL AND hpke_info_bytes IS NOT NULL AND hpke_encapped_key_bytes IS NOT NULL AND
      hpke_wrapped_fleet_key_bytes IS NOT NULL AND length(hpke_info_bytes) BETWEEN 1 AND 1024 AND
      length(hpke_encapped_key_bytes) BETWEEN 1 AND 2048 AND length(hpke_wrapped_fleet_key_bytes) BETWEEN 1 AND 4096 AND
      subject_kind IS NULL AND subject_hpke_key_id IS NULL AND approval_scope_kind IS NULL AND approval_scope_id IS NULL AND
      approved_use IS NULL AND scope_kind IS NULL AND scope_id IS NULL AND capability IS NULL AND
      recipient_root_key_id IS NULL AND recipient_root_generation IS NULL AND root_wrap_suite_id IS NULL AND
      root_wrap_nonce_bytes IS NULL AND root_wrap_context_bytes IS NULL AND wrapped_fleet_key_bytes IS NULL AND
      previous_fkek_key_id IS NULL AND previous_generation IS NULL AND required_device_grant_count IS NULL AND
      required_device_grant_set_hash IS NULL AND recovery_grant_signed_container_hash IS NULL AND activation_not_before_ms IS NULL) OR
    (record_kind = 'FleetKeyGrantV2::RecoveryGrant' AND
      payload_domain = 'shardx.keys.fleet-key-grant.recovery.v2' AND grant_variant = 'RecoveryGrant' AND
      fleet_id IS NOT NULL AND fkek_key_id IS NOT NULL AND generation IS NOT NULL AND
      grant_capability = 'fleet.key.recover' AND recipient_root_key_id IS NOT NULL AND
      recipient_root_generation IS NOT NULL AND root_wrap_suite_id IS NOT NULL AND
      root_wrap_nonce_bytes IS NOT NULL AND root_wrap_context_bytes IS NOT NULL AND wrapped_fleet_key_bytes IS NOT NULL AND
      length(root_wrap_nonce_bytes) BETWEEN 1 AND 64 AND length(root_wrap_context_bytes) BETWEEN 1 AND 1024 AND
      length(wrapped_fleet_key_bytes) BETWEEN 1 AND 4096 AND
      subject_kind IS NULL AND subject_account_id IS NULL AND subject_device_id IS NULL AND subject_signing_key_id IS NULL AND
      subject_hpke_key_id IS NULL AND approval_scope_kind IS NULL AND approval_scope_id IS NULL AND approved_use IS NULL AND
      scope_kind IS NULL AND scope_id IS NULL AND capability IS NULL AND recipient_hpke_key_id IS NULL AND
      hpke_suite_id IS NULL AND hpke_info_bytes IS NULL AND hpke_encapped_key_bytes IS NULL AND hpke_wrapped_fleet_key_bytes IS NULL AND
      previous_fkek_key_id IS NULL AND previous_generation IS NULL AND required_device_grant_count IS NULL AND
      required_device_grant_set_hash IS NULL AND recovery_grant_signed_container_hash IS NULL AND activation_not_before_ms IS NULL) OR
    (record_kind = 'FleetKeyGrantV2::RotationGrant' AND
      payload_domain = 'shardx.keys.fleet-key-grant.rotation.v2' AND grant_variant = 'RotationGrant' AND
      fleet_id IS NOT NULL AND fkek_key_id IS NOT NULL AND generation IS NOT NULL AND
      grant_capability = 'key.rotate' AND previous_fkek_key_id IS NOT NULL AND previous_generation IS NOT NULL AND
      generation = previous_generation + 1 AND fkek_key_id <> previous_fkek_key_id AND
      required_device_grant_count IS NOT NULL AND required_device_grant_set_hash IS NOT NULL AND
      recovery_grant_signed_container_hash IS NOT NULL AND activation_not_before_ms IS NOT NULL AND
      length(required_device_grant_set_hash) = 32 AND length(recovery_grant_signed_container_hash) = 32 AND
      activation_not_before_ms BETWEEN not_before_ms AND not_after_ms - 1 AND
      subject_kind IS NULL AND subject_account_id IS NULL AND subject_device_id IS NULL AND subject_signing_key_id IS NULL AND
      subject_hpke_key_id IS NULL AND approval_scope_kind IS NULL AND approval_scope_id IS NULL AND approved_use IS NULL AND
      scope_kind IS NULL AND scope_id IS NULL AND capability IS NULL AND recipient_hpke_key_id IS NULL AND
      hpke_suite_id IS NULL AND hpke_info_bytes IS NULL AND hpke_encapped_key_bytes IS NULL AND hpke_wrapped_fleet_key_bytes IS NULL AND
      recipient_root_key_id IS NULL AND recipient_root_generation IS NULL AND root_wrap_suite_id IS NULL AND
      root_wrap_nonce_bytes IS NULL AND root_wrap_context_bytes IS NULL AND wrapped_fleet_key_bytes IS NULL)
  )
) STRICT;

CREATE TABLE tenant_root_key_generations (
  server_id                       TEXT NOT NULL,
  server_instance_id              TEXT NOT NULL,
  tenant_id                       TEXT NOT NULL,
  root_generation                 INTEGER NOT NULL CHECK (root_generation BETWEEN 0 AND 9223372036854775807),
  root_key_id                     TEXT NOT NULL,
  state                           TEXT NOT NULL CHECK (state IN ('PREPARING','ACTIVE','RETIRED')),
  recovery_bundle_sha256          BLOB CHECK (recovery_bundle_sha256 IS NULL OR length(recovery_bundle_sha256) = 32),
  required_custodian_grant_count  INTEGER NOT NULL CHECK (required_custodian_grant_count BETWEEN 1 AND 4294967295),
  required_custodian_grant_set_hash BLOB NOT NULL CHECK (length(required_custodian_grant_set_hash) = 32),
  created_at                      TEXT NOT NULL,
  activated_at                   TEXT,
  retired_at                     TEXT,
  PRIMARY KEY(server_id, server_instance_id, tenant_id, root_generation),
  UNIQUE(server_id, server_instance_id, tenant_id, root_key_id),
  UNIQUE(server_id, server_instance_id, tenant_id, root_generation, root_key_id),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT
) STRICT;

CREATE UNIQUE INDEX tenant_root_key_one_active_generation
ON tenant_root_key_generations(server_id, server_instance_id, tenant_id)
WHERE state = 'ACTIVE';

CREATE TABLE tenant_root_key_grants (
  server_id                           TEXT NOT NULL,
  server_instance_id                  TEXT NOT NULL,
  tenant_id                           TEXT NOT NULL,
  replay_id                           BLOB NOT NULL CHECK (length(replay_id) = 16),
  container_domain                    TEXT NOT NULL CHECK (container_domain = 'shardx.authorization.signed-container.v2'),
  container_version                   INTEGER NOT NULL CHECK (container_version = 2),
  payload_domain                      TEXT NOT NULL CHECK (payload_domain = 'shardx.keys.tenant-root-key-grant.v2'),
  payload_version                     INTEGER NOT NULL CHECK (payload_version = 2),
  grant_variant                       TEXT NOT NULL CHECK (grant_variant IN ('FirstRootSelfGrant','ExistingRootGrant','RotationGrant')),
  root_key_id                         TEXT NOT NULL,
  root_generation                     INTEGER NOT NULL CHECK (root_generation BETWEEN 0 AND 9223372036854775807),
  grant_capability                    TEXT NOT NULL CHECK (grant_capability = 'root.custody'),
  subject_account_id                  TEXT NOT NULL,
  subject_device_id                   TEXT NOT NULL,
  subject_signing_key_id              TEXT NOT NULL,
  subject_device_approval_replay_id   BLOB NOT NULL CHECK (length(subject_device_approval_replay_id) = 16),
  recipient_hpke_key_id               TEXT NOT NULL,
  hpke_suite_id                       INTEGER NOT NULL CHECK (hpke_suite_id = 1),
  hpke_mode_id                        INTEGER NOT NULL CHECK (hpke_mode_id = 0),
  hpke_kem_id                         INTEGER NOT NULL CHECK (hpke_kem_id = 32),
  hpke_kdf_id                         INTEGER NOT NULL CHECK (hpke_kdf_id = 1),
  hpke_aead_id                        INTEGER NOT NULL CHECK (hpke_aead_id = 3),
  hpke_info_bytes                     BLOB NOT NULL CHECK (length(hpke_info_bytes) BETWEEN 1 AND 1024),
  hpke_encapped_key_bytes             BLOB NOT NULL CHECK (length(hpke_encapped_key_bytes) = 32),
  hpke_wrapped_trk_bytes              BLOB NOT NULL CHECK (length(hpke_wrapped_trk_bytes) = 48),
  previous_root_key_id                TEXT,
  previous_root_generation            INTEGER CHECK (previous_root_generation IS NULL OR previous_root_generation BETWEEN 0 AND 9223372036854775807),
  issued_at_ms                        INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
  not_before_ms                       INTEGER NOT NULL CHECK (not_before_ms BETWEEN 0 AND 9223372036854775807),
  not_after_ms                        INTEGER NOT NULL CHECK (not_after_ms BETWEEN 0 AND 9223372036854775807 AND not_after_ms > not_before_ms),
  restore_epoch                       INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
  canonical_payload_bytes             BLOB NOT NULL CHECK (length(canonical_payload_bytes) BETWEEN 1 AND 65536),
  payload_sha256                      BLOB NOT NULL CHECK (length(payload_sha256) = 32),
  signature_suite_id                  INTEGER NOT NULL CHECK (signature_suite_id BETWEEN 0 AND 65535),
  signature_version                   INTEGER NOT NULL CHECK (signature_version = 1),
  issuer_signing_key_id               TEXT NOT NULL,
  signature_bytes                     BLOB NOT NULL CHECK (length(signature_bytes) BETWEEN 1 AND 4096),
  signed_container_hash               BLOB NOT NULL CHECK (length(signed_container_hash) = 32),
  exact_signed_container_bytes        BLOB NOT NULL CHECK (length(exact_signed_container_bytes) BETWEEN 1 AND 131072),
  exact_signed_container_bytes_sha256 BLOB NOT NULL CHECK (length(exact_signed_container_bytes_sha256) = 32),
  trk_credential_ref                  TEXT,
  acknowledged_at_ms                 INTEGER CHECK (acknowledged_at_ms IS NULL OR acknowledged_at_ms BETWEEN 0 AND 9223372036854775807),
  revoked_at_ms                       INTEGER CHECK (revoked_at_ms IS NULL OR revoked_at_ms BETWEEN 0 AND 9223372036854775807),
  PRIMARY KEY(server_id, server_instance_id, tenant_id, replay_id),
  UNIQUE(server_id, server_instance_id, tenant_id, payload_domain, replay_id),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, server_instance_id, tenant_id, root_generation, root_key_id)
    REFERENCES tenant_root_key_generations(server_id, server_instance_id, tenant_id, root_generation, root_key_id) ON DELETE RESTRICT,
  CHECK (subject_signing_key_id <> recipient_hpke_key_id),
  CHECK (issued_at_ms <= not_before_ms),
  CHECK (grant_variant <> 'FirstRootSelfGrant' OR root_generation = 0),
  CHECK (
    (grant_variant = 'RotationGrant' AND previous_root_key_id IS NOT NULL AND
      previous_root_generation IS NOT NULL AND root_generation = previous_root_generation + 1 AND
      root_key_id <> previous_root_key_id) OR
    (grant_variant IN ('FirstRootSelfGrant','ExistingRootGrant') AND
      previous_root_key_id IS NULL AND previous_root_generation IS NULL)
  )
) STRICT;

CREATE UNIQUE INDEX tenant_root_one_first_self_grant
ON tenant_root_key_grants(server_id, server_instance_id, tenant_id)
WHERE grant_variant = 'FirstRootSelfGrant';

-- shortcut: schema only; the launcher learns no account role, so accounts,
-- device_state and fleet_key_state are filled with publish-create, which
-- files the account a binding belongs to.
CREATE TABLE fleet_key_state (
  server_id                  TEXT NOT NULL,
  server_instance_id         TEXT NOT NULL,
  tenant_id                  TEXT NOT NULL,
  fleet_id                   TEXT NOT NULL,
  generation                 INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
  fkek_key_id                TEXT NOT NULL,
  device_id                  TEXT NOT NULL,
  device_hpke_grant_record_id TEXT NOT NULL UNIQUE REFERENCES signed_authorization_records(record_id) ON DELETE RESTRICT,
  fkek_credential_ref        TEXT NOT NULL UNIQUE,
  state                      TEXT NOT NULL CHECK (state IN ('PREPARING','ACTIVE','RETIRED')),
  acknowledged_at            TEXT,
  created_at                 TEXT NOT NULL,
  PRIMARY KEY(server_id, server_instance_id, tenant_id, fleet_id, generation),
  UNIQUE(server_id, server_instance_id, tenant_id, fleet_id, fkek_key_id),
  UNIQUE(server_id, server_instance_id, tenant_id, fleet_id, generation, fkek_key_id),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, tenant_id, device_id)
    REFERENCES device_state(server_id, tenant_id, device_id) ON DELETE RESTRICT,
  CHECK (length(device_hpke_grant_record_id) > 0)
) STRICT;

CREATE UNIQUE INDEX fleet_key_one_active_generation
ON fleet_key_state(server_id, server_instance_id, tenant_id, fleet_id)
WHERE state = 'ACTIVE';

-- The recovery and downgrade journals are written by `team::journal` and
-- used by `team::downgrade` (probe 9, L2044).
CREATE TABLE restore_journals (
  local_profile_id   TEXT PRIMARY KEY REFERENCES profile_bindings(local_profile_id) ON DELETE RESTRICT,
  journal_id         TEXT NOT NULL UNIQUE,
  phase              TEXT NOT NULL CHECK (phase IN (
                       'CREATED','DOWNLOADING','VERIFIED','EXTRACTING','VALIDATED','RESEALED',
                       'SWAP_STARTED','SWAPPED','SMOKE_PASSED','ROLLBACK_REQUIRED','ROLLED_BACK','COMPLETED'
                     )),
  staged_path        TEXT NOT NULL,
  backup_path        TEXT NOT NULL,
  old_binding_json   TEXT NOT NULL,
  target_version     INTEGER NOT NULL CHECK (target_version BETWEEN 0 AND 9223372036854775807),
  target_head_hash   BLOB NOT NULL CHECK (length(target_head_hash) = 32),
  created_at         TEXT NOT NULL,
  updated_at         TEXT NOT NULL
) STRICT;

CREATE TABLE downgrade_journals (
  journal_id                    TEXT PRIMARY KEY,
  mode                          TEXT NOT NULL CHECK (mode IN ('CLONE','PRE_V2_RESTORE')),
  original_local_profile_id     TEXT NOT NULL,
  new_local_profile_id          TEXT,
  phase                         TEXT NOT NULL CHECK (phase IN (
                                  'CREATED','CLAIMED','ORIGINAL_METADATA_MOVED','ORIGINAL_USER_DATA_MOVED',
                                  'DISCOVERY_SCAN_PASSED','CLONE_WRITTEN','PRE_V2_SET_RESTORED',
                                  'TEAM_ARTIFACTS_RETIRED','READBACK_PASSED','COMPLETED',
                                  'ROLLBACK_REQUIRED','ROLLED_BACK'
                                )),
  original_metadata_archive_path TEXT,
  original_user_data_archive_path TEXT,
  pre_v2_manifest_sha256        BLOB CHECK (pre_v2_manifest_sha256 IS NULL OR length(pre_v2_manifest_sha256) = 32),
  discovery_readback_sha256     BLOB CHECK (discovery_readback_sha256 IS NULL OR length(discovery_readback_sha256) = 32),
  created_at                    TEXT NOT NULL,
  updated_at                    TEXT NOT NULL,
  CHECK (new_local_profile_id IS NULL OR new_local_profile_id <> original_local_profile_id)
) STRICT;

-- `sync::accept_transitions` files the transitions a binding verified, with
-- its binding proofs (probe 7, L2042).
CREATE TABLE restore_epoch_transitions (
  server_id                  TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  tenant_id                  TEXT NOT NULL,
  server_instance_id         TEXT NOT NULL,
  transition_replay_id       BLOB NOT NULL CHECK (length(transition_replay_id) = 16),
  previous_epoch             INTEGER NOT NULL CHECK (previous_epoch BETWEEN 0 AND 9223372036854775807),
  new_epoch                  INTEGER NOT NULL CHECK (
                               new_epoch BETWEEN 0 AND 9223372036854775807 AND
                               new_epoch > previous_epoch
                             ),
  mapping_codec              TEXT NOT NULL CHECK (mapping_codec = 'PROFILE_HEAD_SET_MERKLE_V2'),
  mapping_count              INTEGER NOT NULL CHECK (mapping_count BETWEEN 1 AND 1000000),
  profile_head_mapping_root  BLOB NOT NULL CHECK (length(profile_head_mapping_root) = 32),
  reason_code                TEXT NOT NULL CHECK (reason_code IN ('operator_restore','disaster_recovery','verified_backup_rollback')),
  approver_account_id        TEXT NOT NULL,
  approver_device_id         TEXT NOT NULL,
  approver_signing_key_id    TEXT NOT NULL,
  issued_at_ms               INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
  nonce                      BLOB NOT NULL CHECK (length(nonce) = 16),
  canonical_transition_payload_bytes BLOB NOT NULL CHECK (length(canonical_transition_payload_bytes) BETWEEN 1 AND 131072),
  transition_payload_sha256  BLOB NOT NULL CHECK (length(transition_payload_sha256) = 32),
  signature_suite_id         INTEGER NOT NULL CHECK (signature_suite_id BETWEEN 0 AND 65535),
  signature_version          INTEGER NOT NULL CHECK (signature_version = 1),
  signature_bytes            BLOB NOT NULL CHECK (length(signature_bytes) BETWEEN 1 AND 4096),
  signed_transition_container_hash BLOB NOT NULL CHECK (length(signed_transition_container_hash) = 32),
  exact_signed_transition_bytes BLOB NOT NULL CHECK (length(exact_signed_transition_bytes) BETWEEN 1 AND 262144),
  exact_signed_transition_bytes_sha256 BLOB NOT NULL CHECK (length(exact_signed_transition_bytes_sha256) = 32),
  verified_at                TEXT NOT NULL,
  PRIMARY KEY(server_id, tenant_id, server_instance_id, previous_epoch, new_epoch),
  UNIQUE(server_id, server_instance_id, tenant_id, transition_replay_id),
  UNIQUE(server_id, server_instance_id, tenant_id, nonce),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT
) STRICT;

CREATE TABLE restore_epoch_binding_proofs (
  server_id                  TEXT NOT NULL,
  tenant_id                  TEXT NOT NULL,
  server_instance_id         TEXT NOT NULL,
  previous_epoch             INTEGER NOT NULL CHECK (previous_epoch BETWEEN 0 AND 9223372036854775807),
  new_epoch                  INTEGER NOT NULL CHECK (
                               new_epoch BETWEEN 0 AND 9223372036854775807 AND
                               new_epoch > previous_epoch
                             ),
  remote_profile_id          TEXT NOT NULL,
  previous_signed_head_hash  BLOB NOT NULL CHECK (length(previous_signed_head_hash) = 32),
  new_signed_head_hash       BLOB NOT NULL CHECK (length(new_signed_head_hash) = 32),
  leaf_index                 INTEGER NOT NULL CHECK (leaf_index BETWEEN 0 AND 999999),
  leaf_count                 INTEGER NOT NULL CHECK (leaf_count BETWEEN 1 AND 1000000 AND leaf_index < leaf_count),
  canonical_leaf_bytes       BLOB NOT NULL CHECK (length(canonical_leaf_bytes) BETWEEN 1 AND 1024),
  leaf_hash                  BLOB NOT NULL CHECK (length(leaf_hash) = 32),
  expected_root              BLOB NOT NULL CHECK (length(expected_root) = 32),
  canonical_inclusion_proof_bytes BLOB NOT NULL CHECK (length(canonical_inclusion_proof_bytes) BETWEEN 1 AND 65536),
  proof_sha256               BLOB NOT NULL CHECK (length(proof_sha256) = 32),
  verified_at                TEXT NOT NULL,
  PRIMARY KEY(server_id, tenant_id, server_instance_id, previous_epoch, new_epoch, remote_profile_id),
  FOREIGN KEY(server_id, tenant_id, server_instance_id, previous_epoch, new_epoch)
    REFERENCES restore_epoch_transitions(
      server_id, tenant_id, server_instance_id, previous_epoch, new_epoch
    ) ON DELETE RESTRICT,
  FOREIGN KEY(server_instance_id, tenant_id, remote_profile_id)
    REFERENCES profile_bindings(server_instance_id, tenant_id, remote_profile_id) ON DELETE RESTRICT
) STRICT;
UPDATE schema_meta SET schema_version = 4, min_reader_version = 4,
  applied_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now');
"#;

/// Version 4 to 5: a binding proof outlives its binding (L1422, L2239: an
/// unbind keeps its evidence, like its receipt and tombstone), so the
/// reference DDL's `ON DELETE RESTRICT` key to `profile_bindings` (L2027),
/// which would refuse every unbind once a proof is filed, becomes a check
/// at filing: a proof is still refused unless its binding exists. The key
/// to its transition stays. Rows are kept exactly. A filed transition or
/// proof is evidence (L2042): it never changes and is never forgotten.
const MIGRATE_V5: &str = r#"
CREATE TABLE restore_epoch_binding_proofs_v5 (
  server_id                  TEXT NOT NULL,
  tenant_id                  TEXT NOT NULL,
  server_instance_id         TEXT NOT NULL,
  previous_epoch             INTEGER NOT NULL CHECK (previous_epoch BETWEEN 0 AND 9223372036854775807),
  new_epoch                  INTEGER NOT NULL CHECK (
                               new_epoch BETWEEN 0 AND 9223372036854775807 AND
                               new_epoch > previous_epoch
                             ),
  remote_profile_id          TEXT NOT NULL,
  previous_signed_head_hash  BLOB NOT NULL CHECK (length(previous_signed_head_hash) = 32),
  new_signed_head_hash       BLOB NOT NULL CHECK (length(new_signed_head_hash) = 32),
  leaf_index                 INTEGER NOT NULL CHECK (leaf_index BETWEEN 0 AND 999999),
  leaf_count                 INTEGER NOT NULL CHECK (leaf_count BETWEEN 1 AND 1000000 AND leaf_index < leaf_count),
  canonical_leaf_bytes       BLOB NOT NULL CHECK (length(canonical_leaf_bytes) BETWEEN 1 AND 1024),
  leaf_hash                  BLOB NOT NULL CHECK (length(leaf_hash) = 32),
  expected_root              BLOB NOT NULL CHECK (length(expected_root) = 32),
  canonical_inclusion_proof_bytes BLOB NOT NULL CHECK (length(canonical_inclusion_proof_bytes) BETWEEN 1 AND 65536),
  proof_sha256               BLOB NOT NULL CHECK (length(proof_sha256) = 32),
  verified_at                TEXT NOT NULL,
  PRIMARY KEY(server_id, tenant_id, server_instance_id, previous_epoch, new_epoch, remote_profile_id),
  FOREIGN KEY(server_id, tenant_id, server_instance_id, previous_epoch, new_epoch)
    REFERENCES restore_epoch_transitions(
      server_id, tenant_id, server_instance_id, previous_epoch, new_epoch
    ) ON DELETE RESTRICT
) STRICT;
INSERT INTO restore_epoch_binding_proofs_v5 SELECT * FROM restore_epoch_binding_proofs;
DROP TABLE restore_epoch_binding_proofs;
ALTER TABLE restore_epoch_binding_proofs_v5 RENAME TO restore_epoch_binding_proofs;
CREATE TRIGGER restore_epoch_binding_proofs_need_binding
BEFORE INSERT ON restore_epoch_binding_proofs
WHEN NOT EXISTS (SELECT 1 FROM profile_bindings
                 WHERE server_instance_id = NEW.server_instance_id
                   AND tenant_id = NEW.tenant_id
                   AND remote_profile_id = NEW.remote_profile_id)
BEGIN SELECT RAISE(ABORT, 'restore_epoch_binding_proofs: no binding'); END;
CREATE TRIGGER restore_epoch_binding_proofs_fixed BEFORE UPDATE ON restore_epoch_binding_proofs
BEGIN SELECT RAISE(ABORT, 'a filed binding proof never changes'); END;
CREATE TRIGGER restore_epoch_binding_proofs_kept BEFORE DELETE ON restore_epoch_binding_proofs
BEGIN SELECT RAISE(ABORT, 'a filed binding proof is never forgotten'); END;
CREATE TRIGGER restore_epoch_transitions_fixed BEFORE UPDATE ON restore_epoch_transitions
BEGIN SELECT RAISE(ABORT, 'a filed transition never changes'); END;
CREATE TRIGGER restore_epoch_transitions_kept BEFORE DELETE ON restore_epoch_transitions
BEGIN SELECT RAISE(ABORT, 'a filed transition is never forgotten'); END;
UPDATE schema_meta SET schema_version = 5, min_reader_version = 5,
  applied_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now');
"#;

/// Version 5 to 6: the plan's columns and foreign keys on the three sync
/// tables (L1775-L1929). Each table is rebuilt, so the migration runs with
/// foreign keys off (a `DROP TABLE` would otherwise fire their actions on the
/// rows it keeps) and `open_at` checks every key before it commits. Rows are
/// kept exactly; the new columns come from rows this device already holds,
/// and a file that has bindings but no kept key evidence for them is refused
/// whole rather than given a guess.
const MIGRATE_V6: &str = r#"-- The proof's check names profile_bindings, which is rebuilt below.
DROP TRIGGER restore_epoch_binding_proofs_need_binding;

-- The account, device and fleet key rows the plan's foreign keys name (L1484,
-- L1748), from the fleet key grants this device already verified and kept
-- (G2-35): the grant's subject is the device, and the highest generation
-- kept for a fleet is its ACTIVE one. The credential references are the names the
-- seeds and the fleet key are, or will be, stored under; the account's role is
-- the least privilege: authority comes from signed capability grants, never
-- from this column.
INSERT OR IGNORE INTO accounts(server_id, tenant_id, account_id, device_id, role, status)
SELECT o.server_id, g.tenant_id, r.subject_account_id, r.subject_device_id, 'member', 'ACTIVE'
FROM trust_fleet_key_grants g
JOIN signed_authorization_records r ON r.exact_signed_container_bytes = g.exact_signed_container_bytes
  AND r.record_kind = 'FleetKeyGrantV2::DeviceHpkeGrant'
JOIN (SELECT server_instance_id, min(server_id) AS server_id FROM server_origins
      GROUP BY server_instance_id HAVING count(*) = 1) o
  ON o.server_instance_id = g.server_instance_id;

INSERT OR IGNORE INTO device_state(server_id, tenant_id, account_id, device_id, signing_key_id,
  hpke_key_id, signing_credential_ref, hpke_credential_ref, recovery_ready)
SELECT o.server_id, g.tenant_id, r.subject_account_id, r.subject_device_id,
  r.subject_signing_key_id, r.recipient_hpke_key_id,
  'device-signing.' || r.subject_device_id, 'device-hpke.' || r.subject_device_id, 0
FROM trust_fleet_key_grants g
JOIN signed_authorization_records r ON r.exact_signed_container_bytes = g.exact_signed_container_bytes
  AND r.record_kind = 'FleetKeyGrantV2::DeviceHpkeGrant'
JOIN (SELECT server_instance_id, min(server_id) AS server_id FROM server_origins
      GROUP BY server_instance_id HAVING count(*) = 1) o
  ON o.server_instance_id = g.server_instance_id;

INSERT OR IGNORE INTO fleet_key_state(server_id, server_instance_id, tenant_id, fleet_id,
  generation, fkek_key_id, device_id, device_hpke_grant_record_id, fkek_credential_ref, state,
  acknowledged_at, created_at)
SELECT o.server_id, g.server_instance_id, g.tenant_id, g.fleet_id, g.generation, g.fkek_key_id,
  r.subject_device_id, r.record_id, 'fleet-key.' || g.fleet_id || '.' || g.generation,
  CASE WHEN g.generation = (SELECT max(h.generation) FROM trust_fleet_key_grants h
                            WHERE h.server_instance_id = g.server_instance_id
                              AND h.tenant_id = g.tenant_id AND h.fleet_id = g.fleet_id)
       THEN 'ACTIVE' ELSE 'RETIRED' END,
  NULL, strftime('%Y-%m-%dT%H:%M:%SZ', 'now')
FROM trust_fleet_key_grants g
JOIN signed_authorization_records r ON r.exact_signed_container_bytes = g.exact_signed_container_bytes
  AND r.record_kind = 'FleetKeyGrantV2::DeviceHpkeGrant'
JOIN (SELECT server_instance_id, min(server_id) AS server_id FROM server_origins
      GROUP BY server_instance_id HAVING count(*) = 1) o
  ON o.server_instance_id = g.server_instance_id;

-- Plan L1775-L1808. `accepted_restore_epoch` is the epoch the binding has
-- accepted (ADR 0002 rule 6, Q-1), kept as version 3 had it; `remote_version`
-- with `last_observed_head_hash` is the pinned head.
CREATE TABLE profile_bindings_v6 (
  local_profile_id       TEXT PRIMARY KEY,
  server_id              TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  server_instance_id     TEXT NOT NULL CHECK (length(server_instance_id) = 32 AND server_instance_id NOT GLOB '*[^0-9a-f]*'),
  tenant_id              TEXT NOT NULL CHECK (length(tenant_id) = 32 AND tenant_id NOT GLOB '*[^0-9a-f]*'),
  account_id             TEXT NOT NULL,
  device_id              TEXT NOT NULL,
  fleet_id               TEXT NOT NULL CHECK (length(fleet_id) = 32 AND fleet_id NOT GLOB '*[^0-9a-f]*'),
  remote_profile_id      TEXT NOT NULL CHECK (length(remote_profile_id) = 32 AND remote_profile_id NOT GLOB '*[^0-9a-f]*'),
  remote_version         INTEGER NOT NULL CHECK (remote_version BETWEEN 0 AND 9223372036854775807),
  base_version           INTEGER NOT NULL CHECK (base_version BETWEEN 0 AND 9223372036854775807),
  accepted_restore_epoch INTEGER NOT NULL CHECK (accepted_restore_epoch BETWEEN 0 AND 9223372036854775807),
  fencing_token          INTEGER CHECK (fencing_token IS NULL OR fencing_token BETWEEN 0 AND 9223372036854775807),
  lease_id               TEXT,
  lease_expires_at       TEXT,
  fkek_key_id            TEXT NOT NULL,
  key_generation         INTEGER NOT NULL CHECK (key_generation BETWEEN 0 AND 9223372036854775807),
  last_observed_head_hash BLOB CHECK (last_observed_head_hash IS NULL OR length(last_observed_head_hash) = 32),
  sync_state             TEXT NOT NULL CHECK (sync_state IN (
                           'LOCAL','AVAILABLE','CHECKED_OUT','LEASE_AT_RISK','OFFLINE_FORK',
                           'UPLOADING','RESTORE_REQUIRED','CONFLICT','QUARANTINED'
                         )),
  dirty                  INTEGER NOT NULL CHECK (dirty IN (0,1)),
  last_error_code        TEXT,
  UNIQUE(server_id, tenant_id, remote_profile_id),
  UNIQUE(server_id, server_instance_id, tenant_id, remote_profile_id),
  UNIQUE(server_instance_id, tenant_id, remote_profile_id),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, tenant_id, account_id, device_id)
    REFERENCES accounts(server_id, tenant_id, account_id, device_id) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, server_instance_id, tenant_id, fleet_id, key_generation, fkek_key_id)
    REFERENCES fleet_key_state(server_id, server_instance_id, tenant_id, fleet_id, generation, fkek_key_id) ON DELETE RESTRICT,
  CHECK (
    (lease_id IS NULL AND fencing_token IS NULL AND lease_expires_at IS NULL) OR
    (lease_id IS NOT NULL AND fencing_token IS NOT NULL AND lease_expires_at IS NOT NULL)
  ),
  CHECK ((remote_version = 0) = (last_observed_head_hash IS NULL))
) STRICT;

-- Each binding's server, account and fleet key come from the rows above; one
-- that has none, or more than one, makes the NOT NULL column refuse, and the
-- whole migration with it. A lease kept without its server expiry (version 3
-- kept none) is marked LEASE_AT_RISK, with the migration's own time as the
-- expiry the CHECK below needs: the lease stays held (nothing reads the
-- expiry to free it), and the next renewal or push writes the server's.
INSERT INTO profile_bindings_v6(local_profile_id, server_id, server_instance_id, tenant_id,
  account_id, device_id, fleet_id, remote_profile_id, remote_version, base_version,
  accepted_restore_epoch, fencing_token, lease_id, lease_expires_at, fkek_key_id, key_generation,
  last_observed_head_hash, sync_state, dirty, last_error_code)
SELECT b.local_profile_id, so.server_id, b.server_instance_id, b.tenant_id, ac.account_id,
  ac.device_id, b.fleet_id, b.remote_profile_id, b.remote_version, b.remote_version,
  b.accepted_restore_epoch, b.fencing_token, b.lease_id,
  CASE WHEN b.lease_id IS NULL THEN NULL ELSE strftime('%Y-%m-%dT%H:%M:%fZ', 'now') END,
  fk.fkek_key_id, fk.generation, b.last_observed_head_hash,
  CASE WHEN b.lease_id IS NOT NULL AND b.sync_state <> 'QUARANTINED'
       THEN 'LEASE_AT_RISK' ELSE b.sync_state END, 0, b.last_error_code
FROM profile_bindings b
LEFT JOIN (SELECT server_instance_id, min(server_id) AS server_id FROM server_origins
           GROUP BY server_instance_id HAVING count(*) = 1) so
  ON so.server_instance_id = b.server_instance_id
LEFT JOIN (SELECT server_id, tenant_id, min(account_id) AS account_id, min(device_id) AS device_id
           FROM accounts GROUP BY server_id, tenant_id HAVING count(*) = 1) ac
  ON ac.server_id = so.server_id AND ac.tenant_id = b.tenant_id
LEFT JOIN fleet_key_state fk
  ON fk.server_id = so.server_id AND fk.server_instance_id = b.server_instance_id
 AND fk.tenant_id = b.tenant_id AND fk.fleet_id = b.fleet_id AND fk.state = 'ACTIVE';

-- Plan L1810-L1870.
CREATE TABLE operations_v6 (
  op_id             TEXT PRIMARY KEY,
  local_profile_id  TEXT REFERENCES profile_bindings(local_profile_id) ON DELETE SET NULL,
  local_profile_id_at_request TEXT NOT NULL,
  server_id         TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  server_instance_id TEXT NOT NULL,
  restore_epoch     INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
  tenant_id         TEXT NOT NULL,
  fleet_id          TEXT,
  remote_profile_id TEXT,
  snapshot_id       BLOB CHECK (snapshot_id IS NULL OR length(snapshot_id) = 16),
  manifest_replay_id BLOB CHECK (manifest_replay_id IS NULL OR length(manifest_replay_id) = 16),
  operation_scope   TEXT NOT NULL,
  kind              TEXT NOT NULL CHECK (kind IN ('PUBLISH','CHECKOUT','UPLOAD','FINALIZE','COMMIT','RELEASE','UNBIND','RECOVERY_EXPORT')),
  idempotency_key   TEXT NOT NULL,
  canonical_request_hash BLOB NOT NULL CHECK (length(canonical_request_hash) = 32),
  exact_request_bytes BLOB NOT NULL CHECK (length(exact_request_bytes) > 0),
  exact_request_bytes_sha256 BLOB NOT NULL CHECK (length(exact_request_bytes_sha256) = 32),
  remote_upload_id  TEXT,
  lease_id          TEXT,
  fencing_token     INTEGER CHECK (fencing_token IS NULL OR fencing_token BETWEEN 0 AND 9223372036854775807),
  base_version      INTEGER CHECK (base_version IS NULL OR base_version BETWEEN 0 AND 9223372036854775807),
  intent_hash       BLOB CHECK (intent_hash IS NULL OR length(intent_hash) = 32),
  ciphertext_sha256 BLOB CHECK (ciphertext_sha256 IS NULL OR length(ciphertext_sha256) = 32),
  signed_manifest_container_bytes BLOB,
  signed_manifest_container_hash BLOB CHECK (
    signed_manifest_container_hash IS NULL OR length(signed_manifest_container_hash) = 32
  ),
  signed_manifest_container_bytes_sha256 BLOB CHECK (
    signed_manifest_container_bytes_sha256 IS NULL OR length(signed_manifest_container_bytes_sha256) = 32
  ),
  state             TEXT NOT NULL CHECK (state IN ('PENDING','RUNNING','AWAITING_RETRY','COMPLETED','FAILED','QUARANTINED')),
  retry_count       INTEGER NOT NULL DEFAULT 0 CHECK (retry_count BETWEEN 0 AND 9223372036854775807),
  next_retry_at     TEXT,
  response_record_type TEXT,
  exact_response_bytes BLOB,
  exact_response_bytes_sha256 BLOB CHECK (
    exact_response_bytes_sha256 IS NULL OR length(exact_response_bytes_sha256) = 32
  ),
  exact_receipt_bytes BLOB,
  receipt_sha256   BLOB CHECK (receipt_sha256 IS NULL OR length(receipt_sha256) = 32),
  created_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL,
  UNIQUE(operation_scope, idempotency_key),
  UNIQUE(op_id, server_id, server_instance_id, restore_epoch),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT,
  CHECK ((exact_response_bytes IS NULL) = (exact_response_bytes_sha256 IS NULL)),
  CHECK ((exact_response_bytes IS NULL) = (response_record_type IS NULL)),
  CHECK ((exact_receipt_bytes IS NULL) = (receipt_sha256 IS NULL)),
  CHECK ((signed_manifest_container_bytes IS NULL) = (signed_manifest_container_hash IS NULL)),
  CHECK ((signed_manifest_container_bytes IS NULL) = (signed_manifest_container_bytes_sha256 IS NULL)),
  CHECK (state <> 'COMPLETED' OR exact_response_bytes IS NOT NULL),
  CHECK (state <> 'COMPLETED' OR kind NOT IN ('COMMIT','RELEASE','UNBIND') OR exact_receipt_bytes IS NOT NULL),
  CHECK (kind <> 'COMMIT' OR (
    remote_upload_id IS NOT NULL AND lease_id IS NOT NULL AND fencing_token IS NOT NULL AND
    base_version IS NOT NULL AND snapshot_id IS NOT NULL AND manifest_replay_id IS NOT NULL AND
    intent_hash IS NOT NULL AND ciphertext_sha256 IS NOT NULL AND
    signed_manifest_container_bytes IS NOT NULL
  ))
) STRICT;

INSERT INTO operations_v6(op_id, local_profile_id, local_profile_id_at_request, server_id,
  server_instance_id, restore_epoch, tenant_id, fleet_id, remote_profile_id, snapshot_id,
  manifest_replay_id, operation_scope, kind, idempotency_key, canonical_request_hash,
  exact_request_bytes, exact_request_bytes_sha256, remote_upload_id, lease_id, fencing_token,
  base_version, intent_hash, ciphertext_sha256, signed_manifest_container_bytes,
  signed_manifest_container_hash, signed_manifest_container_bytes_sha256, state,
  response_record_type, exact_response_bytes, exact_response_bytes_sha256, exact_receipt_bytes,
  receipt_sha256, created_at, updated_at)
SELECT p.op_id, p.local_profile_id, p.local_profile_id_at_request, so.server_id,
  p.server_instance_id, p.restore_epoch, p.tenant_id, p.fleet_id, p.remote_profile_id,
  p.snapshot_id, p.manifest_replay_id, p.operation_scope, p.kind, p.idempotency_key,
  p.canonical_request_hash, p.exact_request_bytes, p.exact_request_bytes_sha256,
  p.remote_upload_id, p.lease_id, p.fencing_token, p.base_version, p.intent_hash,
  p.ciphertext_sha256, p.signed_manifest_container_bytes, p.signed_manifest_container_hash,
  p.signed_manifest_container_bytes_sha256, p.state, p.response_record_type,
  p.exact_response_bytes, p.exact_response_bytes_sha256, p.exact_receipt_bytes, p.receipt_sha256,
  p.created_at, p.updated_at
FROM operations p
LEFT JOIN (SELECT server_instance_id, min(server_id) AS server_id FROM server_origins
           GROUP BY server_instance_id HAVING count(*) = 1) so
  ON so.server_instance_id = p.server_instance_id;

-- Plan L1872-L1929; `spool_ref` names `team-sync/spool/<it>.part`. The
-- request's scope, key and hash mirror the COMMIT operation's; a session whose
-- COMMIT operation is gone has none to mirror, so the NOT NULL columns refuse
-- the whole migration instead of dropping it.
CREATE TABLE upload_sessions_v6 (
  upload_local_id             TEXT PRIMARY KEY,
  local_profile_id            TEXT REFERENCES profile_bindings(local_profile_id) ON DELETE SET NULL,
  local_profile_id_at_request TEXT NOT NULL,
  commit_op_id                TEXT NOT NULL UNIQUE REFERENCES operations(op_id) ON DELETE RESTRICT,
  server_id                   TEXT NOT NULL REFERENCES server_origins(server_id) ON DELETE RESTRICT,
  server_instance_id          TEXT NOT NULL,
  restore_epoch               INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
  tenant_id                   TEXT NOT NULL,
  fleet_id                    TEXT NOT NULL,
  remote_profile_id           TEXT NOT NULL,
  remote_upload_id            TEXT NOT NULL,
  snapshot_id                 BLOB NOT NULL CHECK (length(snapshot_id) = 16),
  manifest_replay_id          BLOB NOT NULL CHECK (length(manifest_replay_id) = 16),
  operation_scope             TEXT NOT NULL,
  idempotency_key             TEXT NOT NULL,
  canonical_request_hash      BLOB NOT NULL CHECK (length(canonical_request_hash) = 32),
  intent_hash                 BLOB NOT NULL CHECK (length(intent_hash) = 32),
  preamble_sha256             BLOB NOT NULL CHECK (length(preamble_sha256) = 32),
  dek_slot_sha256             BLOB NOT NULL CHECK (length(dek_slot_sha256) = 32),
  fkek_key_id                 TEXT NOT NULL,
  key_generation              INTEGER NOT NULL CHECK (key_generation BETWEEN 0 AND 9223372036854775807),
  committed_offset            INTEGER NOT NULL DEFAULT 0 CHECK (committed_offset BETWEEN 0 AND 9223372036854775807),
  expected_ciphertext_sha256  BLOB NOT NULL CHECK (length(expected_ciphertext_sha256) = 32),
  expected_ciphertext_size    INTEGER NOT NULL CHECK (expected_ciphertext_size BETWEEN 0 AND 9223372036854775807),
  spool_ref                   TEXT NOT NULL CHECK (
                                length(spool_ref) > 0 AND
                                instr(spool_ref, '/') = 0 AND instr(spool_ref, char(92)) = 0
                              ),
  state                       TEXT NOT NULL CHECK (state IN ('OPEN','FINALIZING','READY','COMMITTED','ABORTED','QUARANTINED')),
  retry_state                 TEXT NOT NULL CHECK (retry_state IN ('NONE','BACKOFF','MANUAL')),
  retry_count                 INTEGER NOT NULL DEFAULT 0 CHECK (retry_count BETWEEN 0 AND 9223372036854775807),
  next_retry_at               TEXT,
  last_error_code             TEXT,
  exact_finalize_response_bytes BLOB,
  finalize_response_sha256    BLOB CHECK (finalize_response_sha256 IS NULL OR length(finalize_response_sha256) = 32),
  exact_commit_receipt_binding_bytes BLOB,
  commit_receipt_binding_bytes_sha256 BLOB CHECK (
    commit_receipt_binding_bytes_sha256 IS NULL OR length(commit_receipt_binding_bytes_sha256) = 32
  ),
  created_at                  TEXT NOT NULL,
  updated_at                  TEXT NOT NULL,
  UNIQUE(server_id, server_instance_id, tenant_id, remote_upload_id),
  UNIQUE(server_id, server_instance_id, tenant_id, remote_profile_id, snapshot_id),
  UNIQUE(server_id, server_instance_id, tenant_id, remote_profile_id, manifest_replay_id),
  UNIQUE(operation_scope, idempotency_key),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT,
  FOREIGN KEY(commit_op_id, server_id, server_instance_id, restore_epoch)
    REFERENCES operations(op_id, server_id, server_instance_id, restore_epoch) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, server_instance_id, tenant_id, fleet_id, key_generation, fkek_key_id)
    REFERENCES fleet_key_state(server_id, server_instance_id, tenant_id, fleet_id, generation, fkek_key_id) ON DELETE RESTRICT,
  CHECK (committed_offset <= expected_ciphertext_size),
  CHECK ((exact_finalize_response_bytes IS NULL) = (finalize_response_sha256 IS NULL)),
  CHECK ((exact_commit_receipt_binding_bytes IS NULL) = (commit_receipt_binding_bytes_sha256 IS NULL)),
  CHECK (state NOT IN ('READY','COMMITTED') OR exact_finalize_response_bytes IS NOT NULL),
  CHECK (state <> 'COMMITTED' OR exact_commit_receipt_binding_bytes IS NOT NULL)
) STRICT;

INSERT INTO upload_sessions_v6(upload_local_id, local_profile_id, local_profile_id_at_request,
  commit_op_id, server_id, server_instance_id, restore_epoch, tenant_id, fleet_id,
  remote_profile_id, remote_upload_id, snapshot_id, manifest_replay_id, operation_scope,
  idempotency_key, canonical_request_hash, intent_hash, preamble_sha256, dek_slot_sha256,
  fkek_key_id, key_generation, committed_offset, expected_ciphertext_sha256,
  expected_ciphertext_size, spool_ref, state, retry_state, exact_finalize_response_bytes,
  finalize_response_sha256, exact_commit_receipt_binding_bytes,
  commit_receipt_binding_bytes_sha256, created_at, updated_at)
SELECT u.upload_local_id, u.local_profile_id, u.local_profile_id_at_request, u.commit_op_id,
  so.server_id, u.server_instance_id, u.restore_epoch, u.tenant_id, u.fleet_id,
  u.remote_profile_id, u.remote_upload_id, u.snapshot_id, u.manifest_replay_id,
  c.operation_scope, c.idempotency_key, c.canonical_request_hash, u.intent_hash,
  u.preamble_sha256, u.dek_slot_sha256, u.fkek_key_id, u.key_generation, u.committed_offset,
  u.expected_ciphertext_sha256, u.expected_ciphertext_size, u.spool_ref, u.state, 'NONE',
  u.exact_finalize_response_bytes, u.finalize_response_sha256,
  u.exact_commit_receipt_binding_bytes, u.commit_receipt_binding_bytes_sha256, u.created_at,
  u.updated_at
FROM upload_sessions u
LEFT JOIN operations c ON c.op_id = u.commit_op_id
LEFT JOIN (SELECT server_instance_id, min(server_id) AS server_id FROM server_origins
           GROUP BY server_instance_id HAVING count(*) = 1) so
  ON so.server_instance_id = u.server_instance_id;

DROP TABLE upload_sessions;
DROP TABLE operations;
DROP TABLE profile_bindings;
ALTER TABLE profile_bindings_v6 RENAME TO profile_bindings;
ALTER TABLE operations_v6 RENAME TO operations;
ALTER TABLE upload_sessions_v6 RENAME TO upload_sessions;

-- The credential references name secrets in the credential store, and the
-- same device reached through two origins of one instance shares them, so
-- they are unique per server, not across the file.
CREATE TABLE device_state_v6 (
  server_id              TEXT NOT NULL,
  tenant_id              TEXT NOT NULL,
  account_id             TEXT NOT NULL,
  device_id              TEXT NOT NULL,
  signing_key_id         TEXT NOT NULL,
  hpke_key_id            TEXT NOT NULL,
  signing_credential_ref TEXT NOT NULL,
  hpke_credential_ref    TEXT NOT NULL,
  recovery_ready         INTEGER NOT NULL CHECK (recovery_ready IN (0,1)),
  PRIMARY KEY(server_id, tenant_id, device_id),
  UNIQUE(server_id, signing_credential_ref),
  UNIQUE(server_id, hpke_credential_ref),
  FOREIGN KEY(server_id, tenant_id, account_id, device_id)
    REFERENCES accounts(server_id, tenant_id, account_id, device_id) ON DELETE CASCADE,
  CHECK (signing_key_id <> hpke_key_id),
  CHECK (signing_credential_ref <> hpke_credential_ref)
) STRICT;
INSERT INTO device_state_v6 SELECT * FROM device_state;

CREATE TABLE fleet_key_state_v6 (
  server_id                  TEXT NOT NULL,
  server_instance_id         TEXT NOT NULL,
  tenant_id                  TEXT NOT NULL,
  fleet_id                   TEXT NOT NULL,
  generation                 INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
  fkek_key_id                TEXT NOT NULL,
  device_id                  TEXT NOT NULL,
  device_hpke_grant_record_id TEXT NOT NULL UNIQUE REFERENCES signed_authorization_records(record_id) ON DELETE RESTRICT,
  fkek_credential_ref        TEXT NOT NULL,
  state                      TEXT NOT NULL CHECK (state IN ('PREPARING','ACTIVE','RETIRED')),
  acknowledged_at            TEXT,
  created_at                 TEXT NOT NULL,
  PRIMARY KEY(server_id, server_instance_id, tenant_id, fleet_id, generation),
  UNIQUE(server_id, fkek_credential_ref),
  UNIQUE(server_id, server_instance_id, tenant_id, fleet_id, fkek_key_id),
  UNIQUE(server_id, server_instance_id, tenant_id, fleet_id, generation, fkek_key_id),
  FOREIGN KEY(server_id, server_instance_id)
    REFERENCES server_origins(server_id, server_instance_id) ON DELETE RESTRICT,
  FOREIGN KEY(server_id, tenant_id, device_id)
    REFERENCES device_state(server_id, tenant_id, device_id) ON DELETE RESTRICT,
  CHECK (length(device_hpke_grant_record_id) > 0)
) STRICT;
INSERT INTO fleet_key_state_v6 SELECT * FROM fleet_key_state;

DROP TABLE fleet_key_state;
DROP TABLE device_state;
ALTER TABLE device_state_v6 RENAME TO device_state;
ALTER TABLE fleet_key_state_v6 RENAME TO fleet_key_state;
CREATE UNIQUE INDEX fleet_key_one_active_generation
ON fleet_key_state(server_id, server_instance_id, tenant_id, fleet_id)
WHERE state = 'ACTIVE';

CREATE TRIGGER restore_epoch_binding_proofs_need_binding
BEFORE INSERT ON restore_epoch_binding_proofs
WHEN NOT EXISTS (SELECT 1 FROM profile_bindings
                 WHERE server_instance_id = NEW.server_instance_id
                   AND tenant_id = NEW.tenant_id
                   AND remote_profile_id = NEW.remote_profile_id)
BEGIN SELECT RAISE(ABORT, 'restore_epoch_binding_proofs: no binding'); END;
UPDATE schema_meta SET schema_version = 6, min_reader_version = 6,
  applied_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now');
"#;

/// Version 6 to 7 (G2-64 B1, B2): what each key held and what each fleet
/// activation binds, so the Q-18 commit block derives exposure through the
/// root and never forgets one (ADR 0002 C-1). A version 6 reader would block
/// less, so 7 is also the minimum reader. `ledger::backfill_holdings` files
/// the holdings of the evidence already kept.
const MIGRATE_V7: &str = r#"
-- C-1: a key holds a root generation (fleet_id '') or a fleet generation
-- when a container this device evaluated shows it issued or received it.
CREATE TABLE trust_key_holdings (
  server_instance_id    TEXT NOT NULL,
  tenant_id             TEXT NOT NULL,
  signing_key_id        TEXT NOT NULL CHECK (length(signing_key_id) = 64 AND signing_key_id NOT GLOB '*[^0-9a-f]*'),
  fleet_id              TEXT NOT NULL CHECK (fleet_id = '' OR (length(fleet_id) = 32 AND fleet_id NOT GLOB '*[^0-9a-f]*')),
  generation            INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
  first_seen_evaluation INTEGER NOT NULL REFERENCES trust_evaluations(evaluation_id) ON DELETE RESTRICT,
  PRIMARY KEY(server_instance_id, tenant_id, signing_key_id, fleet_id, generation),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

-- C-1's root clause: the root generation of the RecoveryGrant a verified
-- RotationGrant binds for a fleet generation and key, the lowest seen.
CREATE TABLE trust_fleet_activations (
  server_instance_id        TEXT NOT NULL,
  tenant_id                 TEXT NOT NULL,
  fleet_id                  TEXT NOT NULL CHECK (length(fleet_id) = 32 AND fleet_id NOT GLOB '*[^0-9a-f]*'),
  generation                INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
  fkek_key_id               TEXT NOT NULL CHECK (length(fkek_key_id) = 64 AND fkek_key_id NOT GLOB '*[^0-9a-f]*'),
  recipient_root_generation INTEGER NOT NULL CHECK (recipient_root_generation BETWEEN 0 AND 9223372036854775807),
  first_seen_evaluation     INTEGER NOT NULL REFERENCES trust_evaluations(evaluation_id) ON DELETE RESTRICT,
  PRIMARY KEY(server_instance_id, tenant_id, fleet_id, generation, fkek_key_id),
  FOREIGN KEY(server_instance_id, tenant_id)
    REFERENCES trust_anchors(server_instance_id, tenant_id) ON DELETE RESTRICT
) STRICT;

CREATE TRIGGER trust_key_holdings_kept BEFORE DELETE ON trust_key_holdings
BEGIN SELECT RAISE(ABORT, 'an exposure is never forgotten'); END;
CREATE TRIGGER trust_key_holdings_fixed BEFORE UPDATE ON trust_key_holdings
BEGIN SELECT RAISE(ABORT, 'an exposure never changes'); END;
CREATE TRIGGER trust_fleet_activations_kept BEFORE DELETE ON trust_fleet_activations
BEGIN SELECT RAISE(ABORT, 'an activation is never forgotten'); END;
CREATE TRIGGER trust_fleet_activations_lower BEFORE UPDATE ON trust_fleet_activations
WHEN NEW.recipient_root_generation > OLD.recipient_root_generation
  OR NEW.first_seen_evaluation IS NOT OLD.first_seen_evaluation
BEGIN SELECT RAISE(ABORT, 'a bound root generation only moves lower'); END;
UPDATE schema_meta SET schema_version = 7, min_reader_version = 7,
  applied_at = strftime('%Y-%m-%dT%H:%M:%SZ', 'now');
"#;

/// An open `team-sync.db` whose schema this binary reads.
pub struct Db {
    pub(crate) conn: Connection,
}

impl Db {
    /// `<config_root>/team-sync/team-sync.db` (plan L1440).
    pub fn open() -> Result<Self> {
        let path = Self::path()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        Self::open_at(&path)
    }

    pub fn path() -> Result<std::path::PathBuf> {
        Ok(crate::store::config_root()?
            .join("team-sync")
            .join("team-sync.db"))
    }

    /// Opens `path`, creating the schema only when the file holds nothing, and
    /// migrating a clean version 1 file forward.
    pub fn open_at(path: &Path) -> Result<Self> {
        let unreadable = || crate::errcode::code("team.trustLedgerUnreadable");
        let mut conn = Connection::open(path).with_context(unreadable)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .with_context(unreadable)?;
        // Off until the migrations are checked: a table rebuild must not fire
        // the actions of the keys that name it.
        conn.pragma_update(None, "foreign_keys", false)
            .with_context(unreadable)?;
        // SQLite refuses to leave WAL while another connection reads, with an
        // error rather than another mode.
        conn.pragma_update_and_check(None, "journal_mode", "DELETE", |r| r.get::<_, String>(0))
            .with_context(unreadable)?;
        conn.pragma_update(None, "synchronous", "FULL")
            .with_context(unreadable)?;
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .with_context(unreadable)?;
        let objects: i64 = tx
            .query_row("SELECT count(*) FROM sqlite_schema", [], |r| r.get(0))
            .with_context(unreadable)?;
        if objects == 0 {
            tx.execute_batch(SCHEMA_V1).with_context(unreadable)?;
        }
        let from = meta(&tx).ok().and_then(|m| m.first().map(|r| r.0));
        // Only from exactly one clean version 1 row: anything else is left as
        // it is for `compatible` to refuse, and a step that fails rolls the
        // whole migration back.
        if matches!(meta(&tx).as_deref(), Ok([(1, 1, state)]) if state == "CLEAN") {
            tx.execute_batch(MIGRATE_V2).with_context(unreadable)?;
        }
        if matches!(meta(&tx).as_deref(), Ok([(2, 2, state)]) if state == "CLEAN") {
            tx.execute_batch(MIGRATE_V3).with_context(unreadable)?;
        }
        if matches!(meta(&tx).as_deref(), Ok([(3, 3, state)]) if state == "CLEAN") {
            tx.execute_batch(MIGRATE_V4).with_context(unreadable)?;
        }
        if matches!(meta(&tx).as_deref(), Ok([(4, 4, state)]) if state == "CLEAN") {
            tx.execute_batch(MIGRATE_V5).with_context(unreadable)?;
        }
        if matches!(meta(&tx).as_deref(), Ok([(5, 5, state)]) if state == "CLEAN") {
            tx.execute_batch(MIGRATE_V6).with_context(unreadable)?;
        }
        if matches!(meta(&tx).as_deref(), Ok([(6, 6, state)]) if state == "CLEAN") {
            tx.execute_batch(MIGRATE_V7).with_context(unreadable)?;
            super::ledger::backfill_holdings(&tx).with_context(unreadable)?;
        }
        if from.is_some_and(|v| v < SCHEMA_VERSION) {
            let broken: i64 = tx
                .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |r| {
                    r.get(0)
                })
                .with_context(unreadable)?;
            if broken != 0 {
                bail!(unreadable());
            }
        }
        tx.commit().with_context(unreadable)?;
        conn.pragma_update(None, "foreign_keys", true)
            .with_context(unreadable)?;
        if !compatible(&conn) {
            bail!(crate::errcode::code("team.trustLedgerUnsupported"));
        }
        Ok(Self { conn })
    }
}

/// The startup compatibility query (plan L2032): exactly one row, clean, of a
/// version this binary reads and whose minimum reader it meets.
fn compatible(conn: &Connection) -> bool {
    matches!(
        meta(conn).as_deref(),
        Ok([(version, min_reader, state)])
            if *version <= SCHEMA_VERSION && *min_reader <= SCHEMA_VERSION && state == "CLEAN"
    )
}

/// Every `schema_meta` row: version, minimum reader and migration state.
fn meta(conn: &Connection) -> rusqlite::Result<Vec<(i64, i64, String)>> {
    conn.prepare("SELECT schema_version, min_reader_version, migration_state FROM schema_meta")?
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
        .collect()
}

/// Test support: the rows version 6's keys name, so a fixture can bind a
/// profile without a sync.
#[cfg(test)]
pub(crate) mod fixtures {
    use rusqlite::Connection;

    /// A device, a fleet key of generation 1 and the signed grant that
    /// delivered it, for fleet `f` of tenant `t` on instance `i`, filed
    /// under server `s`: what the version 5 sync files held for a binding.
    pub(crate) fn evidence(c: &Connection, s: &str, i: &str, t: &str, f: &str) {
        c.execute_batch(&format!(
            "INSERT OR IGNORE INTO trust_anchors VALUES ('{i}', '{t}', '{anchor}', 'BOOTSTRAP', 0);
             INSERT OR IGNORE INTO trust_evaluations VALUES (1, '{i}', '{t}', 0);
             INSERT OR IGNORE INTO trust_fleet_generations VALUES ('{i}', '{t}', '{f}', 1);
             INSERT OR IGNORE INTO trust_fleet_key_grants
               VALUES ('{i}', '{t}', '{f}', 1, '{fkek}', 1, x'ab', x'80');
             INSERT OR IGNORE INTO signed_authorization_records(record_id, server_id, tenant_id,
               record_kind, container_domain, container_version, payload_domain, payload_version,
               replay_id, subject_account_id, subject_device_id, subject_signing_key_id,
               grant_variant, fleet_id, fkek_key_id, generation, grant_capability,
               recipient_hpke_key_id, hpke_suite_id, hpke_info_bytes, hpke_encapped_key_bytes,
               hpke_wrapped_fleet_key_bytes, issued_at_ms, not_before_ms, not_after_ms,
               server_instance_id, restore_epoch, canonical_payload_bytes, payload_sha256,
               signature_suite_id, signature_version, issuer_signing_key_id, signature_bytes,
               signed_container_hash, exact_signed_container_bytes,
               exact_signed_container_bytes_sha256, verified_at_ms)
             VALUES ('rec-{f}', '{s}', '{t}', 'FleetKeyGrantV2::DeviceHpkeGrant',
               'shardx.authorization.signed-container.v2', 2,
               'shardx.keys.fleet-key-grant.device-hpke.v2', 2, x'{f}', '{account}', '{device}',
               '{signing}', 'DeviceHpkeGrant', '{f}', '{fkek}', 1, 'fleet.key.receive', '{hpke}',
               1, x'01', x'01', x'01', 1, 1, 2, '{i}', 0, x'01', zeroblob(32), 1, 1, '{anchor}',
               x'01', zeroblob(32), x'ab', zeroblob(32), 1);",
            anchor = "ef".repeat(32),
            fkek = "cd".repeat(32),
            account = "a1".repeat(16),
            device = "d1".repeat(16),
            signing = "51".repeat(32),
            hpke = "b2".repeat(32),
        ))
        .unwrap();
    }

    /// Binds `local` to `remote`, with the origin, account, device and fleet
    /// key it needs, under server `s`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn seed_binding(
        c: &Connection,
        s: &str,
        local: &str,
        i: &str,
        t: &str,
        f: &str,
        remote: &str,
        epoch: i64,
    ) {
        c.execute_batch(&format!(
            "INSERT OR IGNORE INTO server_origins(server_id, scheme, host, port, tls_policy,
               server_instance_id, last_restore_epoch, status)
             VALUES ('{s}', 'https', 'h{}.test', 443, 'SYSTEM', '{i}', 0, 'ACTIVE');",
            &i[..8]
        ))
        .unwrap();
        evidence(c, s, i, t, f);
        c.execute_batch(&format!(
            "INSERT OR IGNORE INTO accounts VALUES ('{s}', '{t}', '{a}', '{d}', 'member', 'ACTIVE');
             INSERT OR IGNORE INTO device_state VALUES ('{s}', '{t}', '{a}', '{d}', '{sig}',
               '{hpke}', 'device-signing.{d}', 'device-hpke.{d}', 0);
             INSERT OR IGNORE INTO fleet_key_state VALUES ('{s}', '{i}', '{t}', '{f}', 1, '{fkek}',
               '{d}', 'rec-{f}', 'fleet-key.{f}.1', 'ACTIVE', NULL, 't');",
            a = "a1".repeat(16),
            d = "d1".repeat(16),
            sig = "51".repeat(32),
            hpke = "b2".repeat(32),
            fkek = "cd".repeat(32),
        ))
        .unwrap();
        c.execute(
            "INSERT INTO profile_bindings(local_profile_id, server_id, server_instance_id,
               tenant_id, account_id, device_id, fleet_id, remote_profile_id, remote_version,
               base_version, accepted_restore_epoch, fkek_key_id, key_generation, sync_state,
               dirty)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, 0, ?9, ?10, 1, 'AVAILABLE', 0)",
            rusqlite::params![
                local,
                s,
                i,
                t,
                "a1".repeat(16),
                "d1".repeat(16),
                f,
                remote,
                epoch,
                "cd".repeat(32)
            ],
        )
        .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        drop(Db::open_at(&path).unwrap());
        (dir, path)
    }

    /// A new file gets the schema once, rollback journal and full fsync, and
    /// reopens as it was.
    #[test]
    fn a_new_database_reopens_with_its_schema_and_settings() {
        let (_dir, path) = fresh();
        let db = Db::open_at(&path).unwrap();
        let meta: (i64, i64, String) = db
            .conn
            .query_row(
                "SELECT schema_version, min_reader_version, migration_state FROM schema_meta",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(meta, (7, 7, "CLEAN".into()));
        let pragma = |name: &str| -> String {
            db.conn
                .query_row(&format!("SELECT * FROM pragma_{name}"), [], |r| {
                    r.get::<_, rusqlite::types::Value>(0)
                })
                .map(|v| format!("{v:?}"))
                .unwrap()
        };
        assert_eq!(pragma("journal_mode"), "Text(\"delete\")");
        assert_eq!(pragma("synchronous"), "Integer(2)");
        assert_eq!(pragma("foreign_keys"), "Integer(1)");
    }

    /// Probe 8 (plan L2043, G2-40): a newer schema, a higher minimum reader,
    /// an unclean migration, no row or two rows, or a file whose tables are
    /// not ours: Team is refused on every reopen and nothing is rewritten.
    #[test]
    fn an_unknown_schema_fails_closed_and_is_left_as_it_was() {
        let mutations = [
            "UPDATE schema_meta SET schema_version = 8",
            "UPDATE schema_meta SET min_reader_version = 8",
            "UPDATE schema_meta SET migration_state = 'MIGRATING'",
            "UPDATE schema_meta SET migration_state = 'RECOVERY_REQUIRED'",
            "DELETE FROM schema_meta",
            "PRAGMA ignore_check_constraints = 1; \
             INSERT INTO schema_meta VALUES (2, 1, 1, 'CLEAN', 'x')",
            "DROP TABLE schema_meta",
        ];
        for sql in mutations {
            let (_dir, path) = fresh();
            Connection::open(&path).unwrap().execute_batch(sql).unwrap();
            let before = std::fs::read(&path).unwrap();
            for _ in 0..2 {
                let err = Db::open_at(&path).err().expect(sql).to_string();
                assert!(
                    crate::errcode::has_code(&err, "team.trustLedgerUnsupported"),
                    "{sql}: {err}"
                );
            }
            assert_eq!(std::fs::read(&path).unwrap(), before, "{sql}");
        }
        // A file that is not a database is refused, never replaced.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        std::fs::write(&path, b"not a database at all, not even close").unwrap();
        let err = Db::open_at(&path).err().unwrap().to_string();
        assert!(crate::errcode::has_code(&err, "team.trustLedgerUnreadable"));
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"not a database at all, not even close"
        );
    }

    /// A version 1 file, as #188 wrote it, moves to version 5 in one
    /// transaction and keeps its rows; it then reopens as version 5.
    #[test]
    fn a_version_1_file_migrates_to_version_5_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        let pin = format!(
            "INSERT INTO trust_anchors VALUES ('{}', '{}', '{}', 'BOOTSTRAP', 0);",
            "11".repeat(16),
            "22".repeat(16),
            "33".repeat(32)
        );
        let v1 = Connection::open(&path).unwrap();
        v1.execute_batch(SCHEMA_V1).unwrap();
        v1.execute_batch(&pin).unwrap();
        drop(v1);
        for _ in 0..2 {
            let db = Db::open_at(&path).unwrap();
            let rows = meta(&db.conn).unwrap();
            assert_eq!(rows, [(7, 7, "CLEAN".to_string())]);
            let count = |table: &str| -> i64 {
                let sql = format!("SELECT count(*) FROM {table}");
                db.conn.query_row(&sql, [], |r| r.get(0)).unwrap()
            };
            assert_eq!(count("trust_anchors"), 1, "kept");
            assert_eq!(count("trust_custodian_keys"), 0);
            assert_eq!(count("trust_fleet_key_grants"), 0);
        }
    }

    /// A clean version 2 file gains the sync tables and keeps its ledger; one
    /// that already holds a sync table, or is not clean, is refused as it was.
    #[test]
    fn a_version_2_file_migrates_to_version_5_or_is_left_as_it_was() {
        let v2 = |path: &Path| {
            let c = Connection::open(path).unwrap();
            c.execute_batch(SCHEMA_V1).unwrap();
            c.execute_batch(MIGRATE_V2).unwrap();
            c.execute_batch(&format!(
                "INSERT INTO trust_anchors VALUES ('{}', '{}', '{}', 'BOOTSTRAP', 0);",
                "11".repeat(16),
                "22".repeat(16),
                "33".repeat(32)
            ))
            .unwrap();
            c
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        drop(v2(&path));
        for _ in 0..2 {
            let db = Db::open_at(&path).unwrap();
            assert_eq!(meta(&db.conn).unwrap(), [(7, 7, "CLEAN".to_string())]);
            for (table, rows) in [
                ("trust_anchors", 1),
                ("profile_bindings", 0),
                ("operations", 0),
                ("upload_sessions", 0),
            ] {
                let sql = format!("SELECT count(*) FROM {table}");
                let n: i64 = db.conn.query_row(&sql, [], |r| r.get(0)).unwrap();
                assert_eq!(n, rows, "{table}");
            }
        }
        for (sql, code) in [
            (
                "UPDATE schema_meta SET migration_state = 'MIGRATING'",
                "team.trustLedgerUnsupported",
            ),
            (
                "CREATE TABLE operations (x INTEGER)",
                "team.trustLedgerUnreadable",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("team-sync.db");
            v2(&path).execute_batch(sql).unwrap();
            let before = std::fs::read(&path).unwrap();
            let err = Db::open_at(&path).err().expect(sql).to_string();
            assert!(crate::errcode::has_code(&err, code), "{sql}: {err}");
            assert_eq!(std::fs::read(&path).unwrap(), before, "{sql}");
        }
    }

    /// A clean version 3 file gains the rest of the plan's tables; one that
    /// already holds a version 4 table, or is not clean, is refused as it
    /// was, and so is one with a binding: version 3 kept no evidence of the
    /// key a binding was made under (version 6 needs it).
    #[test]
    fn a_version_3_file_migrates_to_version_6_or_is_left_as_it_was() {
        let v3 = |path: &Path| {
            let c = Connection::open(path).unwrap();
            for sql in [SCHEMA_V1, MIGRATE_V2, MIGRATE_V3] {
                c.execute_batch(sql).unwrap();
            }
            c
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        drop(v3(&path));
        for _ in 0..2 {
            let db = Db::open_at(&path).unwrap();
            assert_eq!(meta(&db.conn).unwrap(), [(7, 7, "CLEAN".to_string())]);
            for (table, rows) in [
                ("profile_bindings", 0),
                ("server_origins", 0),
                ("accounts", 0),
                ("device_state", 0),
                ("signed_authorization_records", 0),
                ("tenant_root_key_generations", 0),
                ("tenant_root_key_grants", 0),
                ("fleet_key_state", 0),
                ("restore_journals", 0),
                ("downgrade_journals", 0),
                ("restore_epoch_transitions", 0),
                ("restore_epoch_binding_proofs", 0),
            ] {
                let sql = format!("SELECT count(*) FROM {table}");
                let n: i64 = db.conn.query_row(&sql, [], |r| r.get(0)).unwrap();
                assert_eq!(n, rows, "{table}");
            }
        }
        for (sql, code) in [
            (
                "UPDATE schema_meta SET migration_state = 'RECOVERY_REQUIRED'",
                "team.trustLedgerUnsupported",
            ),
            (
                "CREATE TABLE server_origins (x INTEGER)",
                "team.trustLedgerUnreadable",
            ),
            (
                "CREATE TABLE restore_epoch_binding_proofs (x INTEGER)",
                "team.trustLedgerUnreadable",
            ),
            (
                "INSERT INTO profile_bindings(local_profile_id, server_instance_id, tenant_id,
                   fleet_id, remote_profile_id, remote_version, accepted_restore_epoch, sync_state)
                 VALUES ('p', '11111111111111111111111111111111', '11111111111111111111111111111111',
                   '11111111111111111111111111111111', '11111111111111111111111111111111', 0, 0,
                   'AVAILABLE')",
                "team.trustLedgerUnreadable",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("team-sync.db");
            v3(&path).execute_batch(sql).unwrap();
            let before = std::fs::read(&path).unwrap();
            for _ in 0..2 {
                let err = Db::open_at(&path).err().expect(sql).to_string();
                assert!(crate::errcode::has_code(&err, code), "{sql}: {err}");
            }
            assert_eq!(std::fs::read(&path).unwrap(), before, "{sql}");
        }
    }

    /// The schema half of probes 7 and 9 (L2042, L2044): journal phases and
    /// modes are closed sets, a clone never reuses the original's ID, and a
    /// binding with a restore journal cannot be deleted; a proof is filed
    /// only for a binding and a transition that exist, inside its leaf
    /// count, and outlives its binding (L1422, L2239); a filed transition
    /// or proof is never changed or deleted. Rows survive a reopen exactly.
    #[test]
    fn journals_and_epoch_proofs_keep_their_constraints_across_a_reopen() {
        let (_dir, path) = fresh();
        let i = "11".repeat(16);
        let h = format!("x'{}'", "22".repeat(32));
        let n = format!("x'{}'", "33".repeat(16));
        let row = |table: &str, values: &str| format!("INSERT INTO {table} VALUES ({values});");
        let journal = row(
            "restore_journals",
            &format!(
                "'p', 'j', 'SWAP_STARTED', 'st', 'bk', '{{}}', 9223372036854775807, {h}, 't', 't'"
            ),
        );
        let downgrade = row(
            "downgrade_journals",
            &format!("'d', 'CLONE', 'p', 'q', 'CLONE_WRITTEN', NULL, NULL, {h}, NULL, 't', 't'"),
        );
        // Epochs `e -> e + 1`, `n` its replay ID and nonce.
        let transition = |e: u32, n: &str| {
            row(
                "restore_epoch_transitions",
                &format!(
                    "'s', '{i}', '{i}', {n}, {e}, {}, 'PROFILE_HEAD_SET_MERKLE_V2', 1, {h},
                     'operator_restore', 'a', 'd', 'k', 0, {n}, x'01', {h}, 1, 1, x'01', {h}, x'01', {h}, 't'",
                    e + 1
                ),
            )
        };
        let proof = |profile: &str, e: u32, index: u32, count: u32| {
            row(
                "restore_epoch_binding_proofs",
                &format!(
                    "'s', '{i}', '{i}', {e}, {}, '{profile}', {h}, {h}, {index}, {count},
                     x'01', {h}, {h}, x'01', {h}, 't'",
                    e + 1
                ),
            )
        };
        let db = Db::open_at(&path).unwrap();
        fixtures::seed_binding(&db.conn, "s", "p", &i, &i, &i, &i, 0);
        db.conn
            .execute_batch(&format!(
                "{}{}{journal}{downgrade}{}",
                transition(0, &n),
                transition(1, &format!("x'{}'", "34".repeat(16))),
                proof(&i, 0, 0, 1)
            ))
            .unwrap();
        let other = "44".repeat(16);
        // The journal keeps the binding; the proof does not.
        let sql = "SAVEPOINT p; DELETE FROM profile_bindings;";
        assert!(db.conn.execute_batch(sql).is_err(), "{sql}");
        db.conn.execute_batch("ROLLBACK TO p; RELEASE p;").unwrap();
        // In range, for a binding and a transition that exist, a proof is
        // filed: what is refused below is refused for its own reason.
        let sql = format!("SAVEPOINT p; {}", proof(&i, 1, 0, 1));
        db.conn.execute_batch(&sql).unwrap();
        db.conn.execute_batch("ROLLBACK TO p; RELEASE p;").unwrap();
        for sql in [
            "DELETE FROM restore_epoch_transitions".to_string(),
            "DELETE FROM server_origins".to_string(),
            "UPDATE restore_journals SET phase = 'SWAPPING'".to_string(),
            "UPDATE restore_journals SET target_version = -1".to_string(),
            "UPDATE downgrade_journals SET phase = 'MOVED'".to_string(),
            "UPDATE downgrade_journals SET mode = 'RESTORE'".to_string(),
            "UPDATE downgrade_journals SET new_local_profile_id = 'p'".to_string(),
            proof(&other, 1, 0, 1),
            proof(&i, 1, 1, 1),
            "UPDATE restore_epoch_binding_proofs SET new_epoch = 2".to_string(),
            format!("UPDATE restore_epoch_binding_proofs SET remote_profile_id = '{other}'"),
            "UPDATE restore_epoch_binding_proofs SET canonical_inclusion_proof_bytes = x'00'"
                .to_string(),
            "DELETE FROM restore_epoch_binding_proofs".to_string(),
            "UPDATE restore_epoch_transitions SET new_epoch = 0".to_string(),
            "UPDATE restore_epoch_transitions SET verified_at = 'u' WHERE previous_epoch = 1"
                .to_string(),
            "DELETE FROM restore_epoch_transitions WHERE previous_epoch = 1".to_string(),
        ] {
            let sql = format!("SAVEPOINT p; {sql};");
            assert!(db.conn.execute_batch(&sql).is_err(), "{sql}");
            db.conn.execute_batch("ROLLBACK TO p; RELEASE p;").unwrap();
        }
        drop(db);
        let db = Db::open_at(&path).unwrap();
        let kept: (String, i64, String, Option<String>) = db
            .conn
            .query_row(
                "SELECT r.phase, r.target_version, d.phase, d.new_local_profile_id
                 FROM restore_journals r, downgrade_journals d",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            kept,
            (
                "SWAP_STARTED".into(),
                i64::MAX,
                "CLONE_WRITTEN".into(),
                Some("q".into())
            )
        );
        // The journal goes first, then the binding can (L2044); its proof
        // stays, and no proof is filed for it any more.
        db.conn
            .execute_batch(
                "UPDATE restore_journals SET phase = 'COMPLETED';
                 DELETE FROM restore_journals; DELETE FROM profile_bindings;",
            )
            .unwrap();
        let proofs: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM restore_epoch_binding_proofs",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(proofs, 1);
        assert!(db.conn.execute_batch(&proof(&i, 1, 0, 1)).is_err());
    }

    /// A clean version 4 file with a filed proof moves on with the
    /// proof's bytes exactly, the key to its transition and the check at
    /// filing; its binding can then be deleted, as an unbind does, and the
    /// proof stays. One that already holds the rebuilt table, or is not
    /// clean, is refused as it was.
    #[test]
    fn a_version_4_file_keeps_its_proofs_and_lets_them_outlive_the_binding() {
        let i = "11".repeat(16);
        let h = format!("x'{}'", "22".repeat(32));
        let n = format!("x'{}'", "33".repeat(16));
        let v4 = |path: &Path| {
            let c = Connection::open(path).unwrap();
            for sql in [SCHEMA_V1, MIGRATE_V2, MIGRATE_V3, MIGRATE_V4] {
                c.execute_batch(sql).unwrap();
            }
            c.execute_batch(&format!(
                "INSERT INTO profile_bindings(local_profile_id, server_instance_id, tenant_id,
                   fleet_id, remote_profile_id, remote_version, accepted_restore_epoch, sync_state)
                 VALUES ('p', '{i}', '{i}', '{i}', '{i}', 0, 0, 'AVAILABLE');
                 INSERT INTO server_origins(server_id, scheme, host, port, tls_policy,
                   server_instance_id, last_restore_epoch, status)
                 VALUES ('s', 'https', 'fleet.test', 443, 'SYSTEM', '{i}', 0, 'ACTIVE');
                 INSERT INTO restore_epoch_transitions VALUES ('s', '{i}', '{i}', {n}, 0, 1,
                   'PROFILE_HEAD_SET_MERKLE_V2', 1, {h}, 'operator_restore', 'a', 'd', 'k', 0,
                   {n}, x'01', {h}, 1, 1, x'01', {h}, x'01', {h}, 't');
                 INSERT INTO restore_epoch_binding_proofs VALUES ('s', '{i}', '{i}', 0, 1,
                   '{i}', {h}, {h}, 0, 1, x'01', {h}, {h}, x'0102', {h}, 't');"
            ))
            .unwrap();
            fixtures::evidence(&c, "s", &i, &i, &i);
            c
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        let before: Vec<Vec<u8>> = v4(&path)
            .prepare("SELECT canonical_inclusion_proof_bytes FROM restore_epoch_binding_proofs")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        for _ in 0..2 {
            let db = Db::open_at(&path).unwrap();
            assert_eq!(meta(&db.conn).unwrap(), [(7, 7, "CLEAN".to_string())]);
            let kept: Vec<u8> = db
                .conn
                .query_row(
                    "SELECT canonical_inclusion_proof_bytes FROM restore_epoch_binding_proofs",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(before, [kept]);
        }
        let db = Db::open_at(&path).unwrap();
        let count = |sql: &str| -> i64 { db.conn.query_row(sql, [], |r| r.get(0)).unwrap() };
        assert!(db
            .conn
            .execute_batch("DELETE FROM restore_epoch_transitions")
            .is_err());
        db.conn
            .execute_batch("DELETE FROM profile_bindings")
            .unwrap();
        assert_eq!(
            count("SELECT count(*) FROM restore_epoch_binding_proofs"),
            1
        );
        assert_eq!(count("SELECT count(*) FROM pragma_foreign_key_check"), 0);
        let orphan = "INSERT INTO restore_epoch_binding_proofs
            SELECT server_id, tenant_id, server_instance_id, previous_epoch, new_epoch,
              'ffffffffffffffffffffffffffffffff', previous_signed_head_hash,
              new_signed_head_hash, leaf_index, leaf_count, canonical_leaf_bytes, leaf_hash,
              expected_root, canonical_inclusion_proof_bytes, proof_sha256, verified_at
            FROM restore_epoch_binding_proofs";
        assert!(db.conn.execute_batch(orphan).is_err());
        drop(db);
        for (sql, code) in [
            (
                "UPDATE schema_meta SET migration_state = 'MIGRATING'",
                "team.trustLedgerUnsupported",
            ),
            (
                "CREATE TABLE restore_epoch_binding_proofs_v5 (x INTEGER)",
                "team.trustLedgerUnreadable",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("team-sync.db");
            v4(&path).execute_batch(sql).unwrap();
            let before = std::fs::read(&path).unwrap();
            for _ in 0..2 {
                let err = Db::open_at(&path).err().expect(sql).to_string();
                assert!(crate::errcode::has_code(&err, code), "{sql}: {err}");
            }
            assert_eq!(std::fs::read(&path).unwrap(), before, "{sql}");
        }
    }

    /// A version 1 file that is not clean, or already holds a table the
    /// migration adds, is not migrated: it is refused and left as it was.
    #[test]
    fn an_unexpected_version_1_file_is_not_migrated() {
        for (sql, code) in [
            (
                "UPDATE schema_meta SET migration_state = 'MIGRATING'",
                "team.trustLedgerUnsupported",
            ),
            (
                "CREATE TABLE trust_fleet_key_grants (x INTEGER)",
                "team.trustLedgerUnreadable",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("team-sync.db");
            let v1 = Connection::open(&path).unwrap();
            v1.execute_batch(SCHEMA_V1).unwrap();
            v1.execute_batch(sql).unwrap();
            drop(v1);
            let before = std::fs::read(&path).unwrap();
            for _ in 0..2 {
                let err = Db::open_at(&path).err().expect(sql).to_string();
                assert!(crate::errcode::has_code(&err, code), "{sql}: {err}");
            }
            assert_eq!(std::fs::read(&path).unwrap(), before, "{sql}");
        }
    }

    /// A file another connection holds in WAL mode cannot leave it, and is
    /// refused rather than used under a journal the plan has not cleared.
    #[test]
    fn a_database_held_in_wal_mode_is_refused() {
        let (_dir, path) = fresh();
        let other = Connection::open(&path).unwrap();
        let mode: String = other
            .pragma_update_and_check(None, "journal_mode", "WAL", |r| r.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        // A read transaction keeps it there.
        other
            .execute_batch("BEGIN; SELECT * FROM schema_meta;")
            .unwrap();
        let err = Db::open_at(&path).err().unwrap().to_string();
        assert!(crate::errcode::has_code(&err, "team.trustLedgerUnreadable"));
        drop(other);
        assert!(Db::open_at(&path).is_ok(), "back to the rollback journal");
    }

    /// The ledger's triggers keep what it learned: a pin, a proven or reported
    /// revocation, and the highest verified generation never go back.
    #[test]
    fn the_ledger_never_takes_back_what_it_learned() {
        let (_dir, path) = fresh();
        let db = Db::open_at(&path).unwrap();
        let (i, t) = ("11".repeat(16), "22".repeat(16));
        db.conn
            .execute_batch(&format!(
                "INSERT INTO trust_anchors VALUES ('{i}', '{t}', '{k}', 'BOOTSTRAP', 0);
                 INSERT INTO trust_proven_revocations VALUES
                   ('{i}', '{t}', '{k}', 'LOCAL_DISTRUST', 0, 0, NULL);
                 INSERT INTO trust_reported_revocations VALUES ('{i}', '{t}', 'd', '{i}', 5);
                 INSERT INTO trust_reported_device_revocations VALUES ('{i}', '{t}', '{i}', 5);
                 INSERT INTO trust_fleet_generations VALUES ('{i}', '{t}', '{i}', 3);
                 INSERT INTO trust_evaluations VALUES (1, '{i}', '{t}', 0);
                 INSERT INTO trust_evaluations VALUES (2, '{i}', '{t}', 0);
                 INSERT INTO trust_custodian_keys VALUES ('{i}', '{t}', '{k}', 1, 5, 9, 1, 7);",
                k = "33".repeat(32)
            ))
            .unwrap();
        for sql in [
            "UPDATE trust_custodian_keys SET first_not_before_ms = 6",
            "UPDATE trust_custodian_keys SET first_seen_evaluation = 2",
            "UPDATE trust_custodian_keys SET latest_not_after_ms = 8",
            "UPDATE trust_custodian_keys SET observed_lapsed_at_ms = 8",
            "UPDATE trust_custodian_keys SET lapsed_evaluation = 2",
            "UPDATE trust_custodian_keys SET lapsed_evaluation = NULL, observed_lapsed_at_ms = NULL",
            "DELETE FROM trust_custodian_keys",
            "UPDATE trust_anchors SET anchor_key_id = lower(hex(zeroblob(32)))",
            "UPDATE trust_proven_revocations SET counted_evaluation = 9",
            "DELETE FROM trust_proven_revocations",
            "DELETE FROM trust_reported_revocations",
            "UPDATE trust_reported_revocations SET revoked_at_ms = 6",
            "DELETE FROM trust_reported_device_revocations",
            "UPDATE trust_reported_device_revocations SET revoked_at_ms = 6",
            "UPDATE trust_fleet_generations SET highest_verified_generation = 2",
            "DELETE FROM trust_anchors",
        ] {
            assert!(db.conn.execute_batch(sql).is_err(), "{sql}");
        }
        // Moving forward is allowed.
        db.conn
            .execute_batch(
                "UPDATE trust_reported_revocations SET revoked_at_ms = 4;
                 UPDATE trust_reported_device_revocations SET revoked_at_ms = 4;
                 UPDATE trust_fleet_generations SET highest_verified_generation = 4;
                 UPDATE trust_custodian_keys SET first_not_before_ms = 4;
                 UPDATE trust_custodian_keys SET latest_not_after_ms = 10;",
            )
            .unwrap();
        // Each row on its own, so only its trigger can refuse the delete.
        let anchor = format!(
            "INSERT INTO trust_anchors VALUES ('{i}', '{t}', '{}', 'BOOTSTRAP', 0);",
            "33".repeat(32)
        );
        let evaluation =
            format!("{anchor} INSERT INTO trust_evaluations VALUES (1, '{i}', '{t}', 0);");
        for (rows, table) in [
            (anchor.clone(), "trust_anchors"),
            (evaluation.clone(), "trust_evaluations"),
            (
                format!(
                    "{evaluation} INSERT INTO trust_sightings VALUES ('{i}', '{t}', '{k}', '{k}', 1, 0);",
                    k = "44".repeat(32)
                ),
                "trust_sightings",
            ),
            (
                format!("{anchor} INSERT INTO trust_fleet_generations VALUES ('{i}', '{t}', '{i}', 3);"),
                "trust_fleet_generations",
            ),
        ] {
            let (_dir, path) = fresh();
            let db = Db::open_at(&path).unwrap();
            db.conn.execute_batch(&rows).unwrap();
            let sql = format!("DELETE FROM {table}");
            assert!(db.conn.execute_batch(&sql).is_err(), "{sql}");
        }
    }

    /// L-1: a version 5 upload session whose COMMIT operation is gone has
    /// nothing to mirror its scope and key from, so the migration refuses the
    /// whole file instead of dropping the session, and leaves it as it was.
    #[test]
    fn a_version_5_upload_session_without_its_commit_operation_refuses_the_file() {
        let i = "11".repeat(16);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        {
            let c = Connection::open(&path).unwrap();
            for sql in [SCHEMA_V1, MIGRATE_V2, MIGRATE_V3, MIGRATE_V4, MIGRATE_V5] {
                c.execute_batch(sql).unwrap();
            }
            c.execute_batch(&format!(
                "PRAGMA foreign_keys = OFF;
                 INSERT INTO server_origins(server_id, scheme, host, port, tls_policy,
                   server_instance_id, last_restore_epoch, status)
                 VALUES ('s', 'https', 'fleet.test', 443, 'SYSTEM', '{i}', 0, 'ACTIVE');
                 INSERT INTO upload_sessions(upload_local_id, local_profile_id,
                   local_profile_id_at_request, commit_op_id, server_instance_id, restore_epoch,
                   tenant_id, fleet_id, remote_profile_id, remote_upload_id, snapshot_id,
                   manifest_replay_id, intent_hash, preamble_sha256, dek_slot_sha256, fkek_key_id,
                   key_generation, committed_offset, expected_ciphertext_sha256,
                   expected_ciphertext_size, spool_ref, state, created_at, updated_at)
                 VALUES ('u1', NULL, 'p', 'ghost', '{i}', 0, '{i}', '{i}', '{i}', 'up1',
                   zeroblob(16), zeroblob(16), zeroblob(32), zeroblob(32), zeroblob(32), 'k',
                   1, 5, zeroblob(32), 10, 'u1.part', 'OPEN', 't1', 't2');"
            ))
            .unwrap();
        }
        let err = Db::open_at(&path)
            .err()
            .expect("the broken file is refused");
        assert!(
            err.to_string().contains("team.trustLedgerUnreadable"),
            "{err}"
        );
        let c = Connection::open(&path).unwrap();
        let (version, sessions): (i64, i64) = c
            .query_row(
                "SELECT (SELECT schema_version FROM schema_meta),
                        (SELECT count(*) FROM upload_sessions)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((version, sessions), (5, 1), "rolled back whole");
    }

    /// Every named trigger and index of a version 5 file is still there, with
    /// the same SQL, after the migration to version 6.
    #[test]
    fn the_triggers_and_indexes_of_a_version_5_file_survive_version_6() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        let list = |c: &Connection| -> Vec<(String, String, String)> {
            c.prepare(
                "SELECT type, name, coalesce(sql, '') FROM sqlite_schema
                 WHERE type IN ('trigger', 'index') AND name NOT LIKE 'sqlite_autoindex%'
                 ORDER BY type, name",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
        };
        let before = {
            let c = Connection::open(&path).unwrap();
            for sql in [SCHEMA_V1, MIGRATE_V2, MIGRATE_V3, MIGRATE_V4, MIGRATE_V5] {
                c.execute_batch(sql).unwrap();
            }
            list(&c)
        };
        assert!(before.len() > 10, "{}", before.len());
        let after = list(&Db::open_at(&path).unwrap().conn);
        for kept in &before {
            assert!(after.contains(kept), "lost or changed {kept:?}");
        }
    }

    /// G2-32, G2-35, G2-36: a clean version 5 file with data moves to
    /// version 6 with every row it had, exactly: the three sync tables are
    /// rebuilt without their foreign-key actions firing (an operation keeps
    /// its binding), the new columns come from the rows the file already
    /// holds, and the plan's keys are then enforced. A file that cannot be
    /// given them, with no kept key evidence for a binding, two origins for
    /// an instance or an operation of an instance with no origin, is refused
    /// whole and left as it was.
    #[test]
    fn a_version_5_file_with_data_moves_to_version_6_keeping_every_row() {
        let i = "11".repeat(16);
        let (key, account, device) = ("cd".repeat(32), "a1".repeat(16), "d1".repeat(16));
        let v5 = |path: &Path| {
            let c = Connection::open(path).unwrap();
            for sql in [SCHEMA_V1, MIGRATE_V2, MIGRATE_V3, MIGRATE_V4, MIGRATE_V5] {
                c.execute_batch(sql).unwrap();
            }
            c.execute_batch(&format!(
                "INSERT INTO server_origins(server_id, scheme, host, port, tls_policy,
                   server_instance_id, last_restore_epoch, status)
                 VALUES ('s', 'https', 'fleet.test', 443, 'SYSTEM', '{i}', 4, 'ACTIVE');
                 INSERT INTO profile_bindings(local_profile_id, server_instance_id, tenant_id,
                   fleet_id, remote_profile_id, remote_version, last_observed_head_hash,
                   accepted_restore_epoch, fencing_token, lease_id, sync_state)
                 VALUES ('p', '{i}', '{i}', '{i}', '{i}', 3, zeroblob(32), 4, 2, '{lease}',
                   'CHECKED_OUT'),
                   ('q', '{i}', '{i}', '{i}', '{other}', 0, NULL, 4, NULL, NULL, 'AVAILABLE'),
                   ('r', '{i}', '{i}', '{i}', '{third}', 0, NULL, 4, 5, '{lease2}', 'QUARANTINED');
                 INSERT INTO operations(op_id, local_profile_id, local_profile_id_at_request,
                   server_instance_id, restore_epoch, tenant_id, fleet_id, remote_profile_id,
                   snapshot_id, manifest_replay_id, operation_scope, kind, idempotency_key,
                   canonical_request_hash, exact_request_bytes, exact_request_bytes_sha256,
                   remote_upload_id, lease_id, fencing_token, base_version, intent_hash,
                   ciphertext_sha256, signed_manifest_container_bytes,
                   signed_manifest_container_hash, signed_manifest_container_bytes_sha256, state,
                   created_at, updated_at)
                 VALUES ('op1', 'p', 'p', '{i}', 4, '{i}', '{i}', '{i}', zeroblob(16),
                   zeroblob(16), 'scope1', 'COMMIT', 'k1', x'{canonical}', x'0102', zeroblob(32),
                   'up1', '{lease}', 2, 3, zeroblob(32), zeroblob(32), x'03', zeroblob(32),
                   zeroblob(32), 'PENDING', 't1', 't2'),
                   ('op2', 'q', 'q', '{i}', 4, '{i}', '{i}', '{other}', NULL, NULL, 'scope2',
                   'PUBLISH', 'k2', zeroblob(32), x'01', zeroblob(32), NULL, NULL, NULL, NULL,
                   NULL, NULL, NULL, NULL, NULL, 'PENDING', 't1', 't2'),
                   ('op3', NULL, 'gone', '{i}', 4, '{i}', '{i}', '{i}', NULL, NULL, 'scope3',
                   'UNBIND', 'k3', zeroblob(32), x'01', zeroblob(32), NULL, NULL, NULL, NULL,
                   NULL, NULL, NULL, NULL, NULL, 'PENDING', 't1', 't2');
                 INSERT INTO upload_sessions(upload_local_id, local_profile_id,
                   local_profile_id_at_request, commit_op_id, server_instance_id, restore_epoch,
                   tenant_id, fleet_id, remote_profile_id, remote_upload_id, snapshot_id,
                   manifest_replay_id, intent_hash, preamble_sha256, dek_slot_sha256, fkek_key_id,
                   key_generation, committed_offset, expected_ciphertext_sha256,
                   expected_ciphertext_size, spool_ref, state, created_at, updated_at)
                 VALUES ('u1', 'p', 'p', 'op1', '{i}', 4, '{i}', '{i}', '{i}', 'up1',
                   zeroblob(16), zeroblob(16), zeroblob(32), zeroblob(32), zeroblob(32), '{key}',
                   1, 5, zeroblob(32), 10, 'op1.part', 'OPEN', 't1', 't2');
                 INSERT INTO restore_journals VALUES ('p', 'j', 'CREATED', 's', 'b', '{{}}', 0,
                   zeroblob(32), 't', 't');",
                lease = "aa".repeat(16),
                other = "22".repeat(16),
                third = "33".repeat(16),
                lease2 = "bb".repeat(16),
                canonical = "0a".repeat(32),
            ))
            .unwrap();
            fixtures::evidence(&c, "s", &i, &i, &i);
            c
        };
        type Rows = Vec<Vec<rusqlite::types::Value>>;
        let tables = ["profile_bindings", "operations", "upload_sessions"];
        let dump = |c: &Connection, table: &str, cols: &[String]| -> Rows {
            let cols: Vec<String> = cols.iter().map(|c| format!("\"{c}\"")).collect();
            c.prepare(&format!(
                "SELECT {} FROM {table} ORDER BY 1",
                cols.join(", ")
            ))
            .unwrap()
            .query_map([], |r| {
                (0..cols.len())
                    .map(|n| r.get::<_, rusqlite::types::Value>(n))
                    .collect()
            })
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("team-sync.db");
        let mut had = Vec::new();
        {
            let c = v5(&path);
            for table in tables {
                let cols: Vec<String> = c
                    .prepare("SELECT name FROM pragma_table_info(?1)")
                    .unwrap()
                    .query_map([table], |r| r.get(0))
                    .unwrap()
                    .collect::<rusqlite::Result<_>>()
                    .unwrap();
                // A held lease is marked at risk, checked apart below.
                let cols: Vec<String> = cols.into_iter().filter(|c| c != "sync_state").collect();
                let rows = dump(&c, table, &cols);
                had.push((table, cols, rows));
            }
        }
        for round in 0..2 {
            let db = Db::open_at(&path).unwrap();
            assert_eq!(meta(&db.conn).unwrap(), [(7, 7, "CLEAN".to_string())]);
            for (table, cols, rows) in &had {
                assert_eq!(&dump(&db.conn, table, cols), rows, "{table} round {round}");
            }
            let one = |sql: &str| -> String { db.conn.query_row(sql, [], |r| r.get(0)).unwrap() };
            let count = |sql: &str| -> i64 { db.conn.query_row(sql, [], |r| r.get(0)).unwrap() };
            assert_eq!(
                one(
                    "SELECT server_id || account_id || device_id || fkek_key_id || key_generation
                       || base_version || dirty FROM profile_bindings WHERE local_profile_id = 'p'"
                ),
                format!("s{account}{device}{key}130"),
            );
            // The lease is still held, marked at risk with the migration's time
            // as its unknown expiry: no 1970 sentinel, and not free.
            assert_eq!(
                count(
                    "SELECT count(*) FROM profile_bindings WHERE local_profile_id = 'p'
                       AND sync_state = 'LEASE_AT_RISK' AND lease_id IS NOT NULL
                       AND fencing_token = 2
                       AND lease_expires_at > '2020' AND lease_expires_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"
                ),
                1
            );
            assert_eq!(
                count(
                    "SELECT count(*) FROM profile_bindings WHERE lease_expires_at IS NULL
                       AND sync_state = 'AVAILABLE'"
                ),
                1
            );
            // A quarantined lease keeps its reason's state.
            assert_eq!(
                count(
                    "SELECT count(*) FROM profile_bindings WHERE local_profile_id = 'r'
                       AND sync_state = 'QUARANTINED' AND lease_id IS NOT NULL
                       AND lease_expires_at IS NOT NULL"
                ),
                1
            );
            assert_eq!(
                count("SELECT count(*) FROM operations WHERE server_id = 's'"),
                3
            );
            // The rebuild did not fire the keys' actions: the operations keep
            // their binding, and the unbound one stays unbound.
            assert_eq!(
                count("SELECT count(*) FROM operations WHERE local_profile_id IS NOT NULL"),
                2
            );
            assert_eq!(
                one(
                    "SELECT server_id || retry_state || operation_scope || idempotency_key
                       FROM upload_sessions"
                ),
                "sNONEscope1k1"
            );
            assert_eq!(
                one("SELECT hex(canonical_request_hash) FROM upload_sessions"),
                "0A".repeat(32)
            );
            assert_eq!(count("SELECT count(*) FROM restore_journals"), 1);
            assert_eq!(
                one(
                    "SELECT role || status || signing_credential_ref || hpke_credential_ref
                       FROM accounts JOIN device_state USING (server_id, tenant_id, device_id)"
                ),
                format!("memberACTIVEdevice-signing.{device}device-hpke.{device}"),
            );
            assert_eq!(
                one(
                    "SELECT state || fkek_credential_ref || device_hpke_grant_record_id
                       FROM fleet_key_state"
                ),
                format!("ACTIVEfleet-key.{i}.1rec-{i}"),
            );
            assert_eq!(count("SELECT count(*) FROM pragma_foreign_key_check"), 0);
            let pragma: i64 = db
                .conn
                .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
                .unwrap();
            assert_eq!(pragma, 1);
            // The plan's keys now hold.
            for sql in [
                "UPDATE profile_bindings SET server_id = 'nowhere' WHERE local_profile_id = 'q'",
                "UPDATE profile_bindings SET key_generation = 9 WHERE local_profile_id = 'q'",
                "UPDATE profile_bindings SET account_id = 'nobody' WHERE local_profile_id = 'q'",
                "UPDATE operations SET server_id = 'nowhere' WHERE op_id = 'op2'",
                "UPDATE upload_sessions SET server_id = 'nowhere'",
                "UPDATE upload_sessions SET key_generation = 9",
                "UPDATE profile_bindings SET lease_expires_at = NULL WHERE local_profile_id = 'p'",
                "UPDATE profile_bindings SET lease_id = NULL, fencing_token = NULL
                   WHERE local_profile_id = 'p'",
                "UPDATE profile_bindings SET dirty = 2 WHERE local_profile_id = 'q'",
                "UPDATE upload_sessions SET retry_state = 'LATER'",
                "UPDATE upload_sessions SET spool_ref = 'a/b'",
                "UPDATE operations SET kind = 'COMMIT' WHERE op_id = 'op2'",
                "DELETE FROM fleet_key_state",
                "DELETE FROM accounts",
                "DELETE FROM server_origins",
            ] {
                assert!(db.conn.execute_batch(sql).is_err(), "{sql}");
            }
            // The binding alone holds the key: with the upload session gone,
            // it cannot be deleted.
            let sql = "SAVEPOINT p; DELETE FROM upload_sessions; DELETE FROM restore_journals;
                       DELETE FROM fleet_key_state";
            assert!(db.conn.execute_batch(sql).is_err(), "{sql}");
            db.conn.execute_batch("ROLLBACK TO p; RELEASE p;").unwrap();
        }
        for (sql, what) in [
            ("DELETE FROM signed_authorization_records", "no kept grant"),
            ("DELETE FROM trust_fleet_key_grants", "no verified grant"),
            (
                "INSERT INTO server_origins(server_id, scheme, host, port, tls_policy,
                   server_instance_id, last_restore_epoch, status)
                 VALUES ('s2', 'https', 'other.test', 443, 'SYSTEM',
                   '11111111111111111111111111111111', 0, 'ACTIVE')",
                "two origins",
            ),
            (
                "UPDATE operations SET server_instance_id = 'ffffffffffffffffffffffffffffffff'
                 WHERE op_id = 'op2'",
                "an operation of no origin",
            ),
            (
                "INSERT INTO server_origins(server_id, scheme, host, port, tls_policy,
                   server_instance_id, last_restore_epoch, status)
                 VALUES ('s5', 'https', 'a5.test', 443, 'SYSTEM',
                   'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 0, 'ACTIVE'),
                   ('s6', 'https', 'a6.test', 443, 'SYSTEM',
                   'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee', 0, 'ACTIVE');
                 UPDATE operations SET server_instance_id = 'eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
                 WHERE op_id = 'op2'",
                "an operation of two origins",
            ),
            (
                "PRAGMA foreign_keys = OFF;
                 INSERT INTO restore_journals VALUES ('ghost', 'g', 'CREATED', 's', 'b', '{}', 0,
                   zeroblob(32), 't', 't')",
                "a key already broken",
            ),
            (
                "CREATE TEMP TABLE copy AS SELECT * FROM signed_authorization_records;
                 UPDATE copy SET record_id = 'rec2', replay_id = x'02020202020202020202020202020202',
                   subject_device_id = 'd2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2',
                   subject_account_id = 'a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2',
                   fleet_id = '22222222222222222222222222222222',
                   exact_signed_container_bytes = x'ac';
                 INSERT INTO signed_authorization_records SELECT * FROM copy;
                 INSERT INTO trust_fleet_generations
                   VALUES ('11111111111111111111111111111111', '11111111111111111111111111111111',
                     '22222222222222222222222222222222', 1);
                 INSERT INTO trust_fleet_key_grants
                   VALUES ('11111111111111111111111111111111', '11111111111111111111111111111111',
                     '22222222222222222222222222222222', 1,
                     'cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd', 1, x'ac', x'00')",
                "two devices of a tenant",
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("team-sync.db");
            v5(&path).execute_batch(sql).unwrap();
            let before = std::fs::read(&path).unwrap();
            for _ in 0..2 {
                let err = Db::open_at(&path).err().expect(what).to_string();
                assert!(
                    crate::errcode::has_code(&err, "team.trustLedgerUnreadable"),
                    "{what}: {err}"
                );
            }
            assert_eq!(std::fs::read(&path).unwrap(), before, "{what}");
        }
    }

    use rusqlite::types::Value as Sql;

    /// A `COMMIT` operation of server `s`, instance `i` and epoch `epoch`.
    fn commit_op_sql(op: &str, s: &str, i: &str, epoch: i64, scope: &str, key: &str) -> String {
        format!(
            "INSERT INTO operations(op_id, local_profile_id, local_profile_id_at_request,
               server_id, server_instance_id, restore_epoch, tenant_id, fleet_id,
               remote_profile_id, snapshot_id, manifest_replay_id, operation_scope, kind,
               idempotency_key, canonical_request_hash, exact_request_bytes,
               exact_request_bytes_sha256, remote_upload_id, lease_id, fencing_token,
               base_version, intent_hash, ciphertext_sha256, signed_manifest_container_bytes,
               signed_manifest_container_hash, signed_manifest_container_bytes_sha256, state,
               created_at, updated_at)
             VALUES ('{op}', 'p', 'p', '{s}', '{i}', {epoch}, '{i}', '{i}', '{i}', zeroblob(16),
               zeroblob(16), '{scope}', 'COMMIT', '{key}', zeroblob(32), x'01', zeroblob(32),
               'up-{op}', 'aa', 1, 0, zeroblob(32), zeroblob(32), x'01', zeroblob(32),
               zeroblob(32), 'PENDING', 't', 't');"
        )
    }

    /// The upload session of the `COMMIT` operation `op`, with the identity
    /// and replay columns `snapshot`, `replay` and `upload`, under key
    /// generation `generation` of fleet key `fkek`.
    #[allow(clippy::too_many_arguments)]
    fn session_sql(
        id: &str,
        op: &str,
        s: &str,
        i: &str,
        epoch: i64,
        ids: (&str, &str, &str),
        scope_key: (&str, &str),
        generation: i64,
    ) -> String {
        let (upload, snapshot, replay) = ids;
        let (scope, key) = scope_key;
        format!(
            "INSERT INTO upload_sessions(upload_local_id, local_profile_id,
               local_profile_id_at_request, commit_op_id, server_id, server_instance_id,
               restore_epoch, tenant_id, fleet_id, remote_profile_id, remote_upload_id,
               snapshot_id, manifest_replay_id, operation_scope, idempotency_key,
               canonical_request_hash, intent_hash, preamble_sha256, dek_slot_sha256, fkek_key_id,
               key_generation, committed_offset, expected_ciphertext_sha256,
               expected_ciphertext_size, spool_ref, state, retry_state, created_at, updated_at)
             VALUES ('{id}', 'p', 'p', '{op}', '{s}', '{i}', {epoch}, '{i}', '{i}', '{i}',
               '{upload}', x'{snapshot}', x'{replay}', '{scope}', '{key}', zeroblob(32),
               x'{intent}', x'{preamble}', x'{slot}', '{fkek}', {generation}, 7,
               x'{digest}', 100, '{id}.part', 'OPEN', 'NONE', 't', 't');",
            intent = "31".repeat(32),
            preamble = "32".repeat(32),
            slot = "33".repeat(32),
            digest = "34".repeat(32),
            fkek = "cd".repeat(32),
        )
    }

    /// Probe 4 (L2038, G2-36): an upload session keeps its identity, replay
    /// and resume columns across a reopen. A second session cannot reuse the
    /// upload, snapshot, replay or scope and key of the first, nor bind to a
    /// commit operation of another instance, epoch or server, nor to a fleet
    /// key of another instance. `READY` and `COMMITTED` need the finalize
    /// response bytes, and `COMMITTED` the commit receipt binding bytes,
    /// with their hashes.
    #[test]
    fn an_upload_session_refuses_a_second_identity_and_a_stranger_commit_or_key() {
        let (_dir, path) = fresh();
        let i = "11".repeat(16);
        let other = "22".repeat(16);
        let (snap1, snap2) = ("a1".repeat(16), "a2".repeat(16));
        let (rep1, rep2) = ("b1".repeat(16), "b2".repeat(16));
        {
            let db = Db::open_at(&path).unwrap();
            fixtures::seed_binding(&db.conn, "s", "p", &i, &i, &i, &i, 0);
            db.conn
                .execute_batch(&format!(
                    "INSERT INTO server_origins(server_id, scheme, host, port, tls_policy,
                       server_instance_id, last_restore_epoch, status)
                     VALUES ('s2', 'https', 'two.test', 443, 'SYSTEM', '{other}', 0, 'ACTIVE');
                     {}{}{}{}",
                    commit_op_sql("op1", "s", &i, 0, "scope1", "k1"),
                    commit_op_sql("op2", "s", &i, 0, "scope2", "k2"),
                    commit_op_sql("op3", "s", &i, 3, "scope3", "k3"),
                    commit_op_sql("op4", "s2", &other, 0, "scope4", "k4"),
                ))
                .unwrap();
            let first = session_sql(
                "u1",
                "op1",
                "s",
                &i,
                0,
                ("up1", &snap1, &rep1),
                ("scope1", "k1"),
                1,
            );
            db.conn.execute_batch(&first).unwrap();
        }
        // The session reopens exactly.
        let db = Db::open_at(&path).unwrap();
        let kept: (String, String, String, i64, i64, i64, String, String) = db
            .conn
            .query_row(
                "SELECT remote_upload_id, hex(snapshot_id), hex(manifest_replay_id),
                   committed_offset, expected_ciphertext_size, key_generation,
                   hex(intent_hash) || hex(preamble_sha256) || hex(dek_slot_sha256),
                   hex(expected_ciphertext_sha256)
                 FROM upload_sessions",
                [],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                        r.get(7)?,
                    ))
                },
            )
            .unwrap();
        assert_eq!(
            kept,
            (
                "up1".into(),
                snap1.to_uppercase(),
                rep1.to_uppercase(),
                7,
                100,
                1,
                format!("{}{}{}", "31".repeat(32), "32".repeat(32), "33".repeat(32)),
                "34".repeat(32)
            )
        );
        let ok = session_sql(
            "u2",
            "op2",
            "s",
            &i,
            0,
            ("up2", &snap2, &rep2),
            ("scope2", "k2"),
            1,
        );
        for (what, sql) in [
            (
                "the same upload",
                session_sql(
                    "u2",
                    "op2",
                    "s",
                    &i,
                    0,
                    ("up1", &snap2, &rep2),
                    ("scope2", "k2"),
                    1,
                ),
            ),
            (
                "the same snapshot",
                session_sql(
                    "u2",
                    "op2",
                    "s",
                    &i,
                    0,
                    ("up2", &snap1, &rep2),
                    ("scope2", "k2"),
                    1,
                ),
            ),
            (
                "the same replay",
                session_sql(
                    "u2",
                    "op2",
                    "s",
                    &i,
                    0,
                    ("up2", &snap2, &rep1),
                    ("scope2", "k2"),
                    1,
                ),
            ),
            (
                "the same scope and key",
                session_sql(
                    "u2",
                    "op2",
                    "s",
                    &i,
                    0,
                    ("up2", &snap2, &rep2),
                    ("scope1", "k1"),
                    1,
                ),
            ),
            (
                "the same commit operation",
                session_sql(
                    "u2",
                    "op1",
                    "s",
                    &i,
                    0,
                    ("up2", &snap2, &rep2),
                    ("scope2", "k2"),
                    1,
                ),
            ),
            (
                "a commit operation of another epoch",
                session_sql(
                    "u2",
                    "op3",
                    "s",
                    &i,
                    0,
                    ("up2", &snap2, &rep2),
                    ("scope3", "k3"),
                    1,
                ),
            ),
            (
                "a commit operation of another instance",
                session_sql(
                    "u2",
                    "op4",
                    "s",
                    &i,
                    0,
                    ("up2", &snap2, &rep2),
                    ("scope4", "k4"),
                    1,
                ),
            ),
            (
                "a commit operation of another server",
                session_sql(
                    "u2",
                    "op2",
                    "s2",
                    &i,
                    0,
                    ("up2", &snap2, &rep2),
                    ("scope2", "k2"),
                    1,
                ),
            ),
            (
                "a fleet key of another instance",
                session_sql(
                    "u2",
                    "op4",
                    "s2",
                    &other,
                    0,
                    ("up2", &snap2, &rep2),
                    ("scope4", "k4"),
                    1,
                ),
            ),
            (
                "a generation that is not filed",
                session_sql(
                    "u2",
                    "op2",
                    "s",
                    &i,
                    0,
                    ("up2", &snap2, &rep2),
                    ("scope2", "k2"),
                    2,
                ),
            ),
        ] {
            let sql = format!("SAVEPOINT p; {sql}");
            assert!(db.conn.execute_batch(&sql).is_err(), "{what}");
            db.conn.execute_batch("ROLLBACK TO p; RELEASE p;").unwrap();
        }
        // Nothing but the first session was kept; a second, distinct one is.
        let sessions = |db: &Db| -> i64 {
            db.conn
                .query_row("SELECT count(*) FROM upload_sessions", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(sessions(&db), 1);
        db.conn.execute_batch(&ok).unwrap();
        assert_eq!(sessions(&db), 2);

        // READY and COMMITTED need the bytes they stand on, with their hashes.
        let set = |sql: &str| db.conn.execute_batch(&format!("SAVEPOINT p; {sql}"));
        let undo = || db.conn.execute_batch("ROLLBACK TO p; RELEASE p;").unwrap();
        for (what, sql) in [
            (
                "READY with no finalize response",
                "UPDATE upload_sessions SET state = 'READY'",
            ),
            (
                "COMMITTED with no finalize response",
                "UPDATE upload_sessions SET state = 'COMMITTED'",
            ),
            (
                "COMMITTED with no receipt binding",
                "UPDATE upload_sessions SET state = 'COMMITTED',
                   exact_finalize_response_bytes = x'01', finalize_response_sha256 = zeroblob(32)",
            ),
            (
                "COMMITTED with a receipt binding but no finalize response",
                "UPDATE upload_sessions SET state = 'COMMITTED',
                   exact_commit_receipt_binding_bytes = x'02',
                   commit_receipt_binding_bytes_sha256 = zeroblob(32)",
            ),
            (
                "finalize bytes with no hash",
                "UPDATE upload_sessions SET exact_finalize_response_bytes = x'01'",
            ),
            (
                "a receipt binding with no hash",
                "UPDATE upload_sessions SET exact_commit_receipt_binding_bytes = x'02'",
            ),
            (
                "a receipt hash of the wrong length",
                "UPDATE upload_sessions SET exact_commit_receipt_binding_bytes = x'02',
                   commit_receipt_binding_bytes_sha256 = zeroblob(31)",
            ),
        ] {
            assert!(
                set(&format!("{sql} WHERE upload_local_id = 'u2'")).is_err(),
                "{what}"
            );
            undo();
        }
        db.conn
            .execute_batch(
                "UPDATE upload_sessions SET state = 'READY',
                   exact_finalize_response_bytes = x'01', finalize_response_sha256 = zeroblob(32)
                 WHERE upload_local_id = 'u2';
                 UPDATE upload_sessions SET state = 'COMMITTED',
                   exact_commit_receipt_binding_bytes = x'02',
                   commit_receipt_binding_bytes_sha256 = zeroblob(32)
                 WHERE upload_local_id = 'u2'",
            )
            .unwrap();
        drop(db);
        let db = Db::open_at(&path).unwrap();
        let (state, finalize, receipt): (String, Vec<u8>, Vec<u8>) = db
            .conn
            .query_row(
                "SELECT state, exact_finalize_response_bytes, exact_commit_receipt_binding_bytes
                 FROM upload_sessions WHERE upload_local_id = 'u2'",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(
            (state.as_str(), finalize, receipt),
            ("COMMITTED", vec![1], vec![2])
        );
        assert_eq!(sessions(&db), 2);
    }

    /// Probe 10 (L2045, G2-42) on the sync tables, the integer classes of
    /// version 3: version (`remote_version`, `base_version`, the epochs),
    /// fencing (`fencing_token`) and offset and size (`committed_offset`,
    /// `expected_ciphertext_size`), with the retry counts. Both bounds are kept
    /// exactly across a reopen; one past either bound, 2^63, 2^64 - 1, a
    /// fraction, and text or bytes that name no integer are refused with the
    /// value left as it was. STRICT converts text or a real naming an in-range
    /// integer losslessly, so that is stored as the exact INTEGER.
    #[test]
    fn every_sync_integer_class_keeps_its_range_across_a_reopen() {
        let (_dir, path) = fresh();
        let i = "11".repeat(16);
        let db = Db::open_at(&path).unwrap();
        fixtures::seed_binding(&db.conn, "s", "p", &i, &i, &i, &i, 0);
        db.conn
            .execute_batch(&format!(
                "UPDATE profile_bindings SET lease_id = 'aa', fencing_token = 1,
                   lease_expires_at = 'x' WHERE local_profile_id = 'p';
                 {}{}",
                commit_op_sql("op1", "s", &i, 0, "scope1", "k1"),
                session_sql(
                    "u1",
                    "op1",
                    "s",
                    &i,
                    0,
                    ("up1", &"a1".repeat(16), &"b1".repeat(16)),
                    ("scope1", "k1"),
                    1,
                ),
            ))
            .unwrap();
        // A release request no upload hangs on, whose epoch can move alone.
        db.conn
            .execute_batch(&format!(
                "INSERT INTO operations(op_id, local_profile_id, local_profile_id_at_request,
                   server_id, server_instance_id, restore_epoch, tenant_id, fleet_id,
                   remote_profile_id, operation_scope, kind, idempotency_key,
                   canonical_request_hash, exact_request_bytes, exact_request_bytes_sha256, state,
                   created_at, updated_at)
                 VALUES ('rel', 'p', 'p', 's', '{i}', 0, '{i}', '{i}', '{i}', 'scope-rel',
                   'RELEASE', 'k-rel', zeroblob(32), x'01', zeroblob(32), 'PENDING', 't', 't')"
            ))
            .unwrap();
        let max = i64::MAX;
        let bound = "local_profile_id = 'p'";
        let rel = "op_id = 'rel'";
        let up = "upload_local_id = 'u1'";
        // (table, column, SET tail, row, lowest, highest). `remote_version`
        // names a head exactly when it is not 0 (L1796).
        let head = ", last_observed_head_hash = CASE WHEN ?1 = 0 THEN NULL ELSE zeroblob(32) END";
        let probes = [
            ("profile_bindings", "remote_version", head, bound, 0, max),
            ("profile_bindings", "base_version", "", bound, 0, max),
            (
                "profile_bindings",
                "accepted_restore_epoch",
                "",
                bound,
                0,
                max,
            ),
            ("profile_bindings", "fencing_token", "", bound, 0, max),
            ("operations", "restore_epoch", "", rel, 0, max),
            ("operations", "fencing_token", "", rel, 0, max),
            ("operations", "base_version", "", rel, 0, max),
            ("operations", "retry_count", "", rel, 0, max),
            ("upload_sessions", "retry_count", "", up, 0, max),
            // The size first, with the offset at 0; then the offset, with the
            // size at its highest: the offset never passes the size.
            (
                "upload_sessions",
                "expected_ciphertext_size",
                ", committed_offset = 0",
                up,
                0,
                max,
            ),
            ("upload_sessions", "committed_offset", "", up, 0, max),
        ];
        let set = |table: &str, col: &str, tail: &str, row: &str, v: Sql| {
            db.conn.execute(
                &format!("UPDATE {table} SET {col} = ?1{tail} WHERE {row}"),
                [v],
            )
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
        for (table, col, tail, row, lo, hi) in &probes {
            let at = format!("{table}.{col}");
            for v in [*lo, *hi] {
                assert_eq!(
                    set(table, col, tail, row, Sql::Integer(v)).unwrap(),
                    1,
                    "{at} = {v}"
                );
            }
            let bad = [
                Sql::Integer(lo - 1),
                Sql::Real(2f64.powi(63)),
                Sql::Real(u64::MAX as f64),
                Sql::Real(0.5),
                Sql::Text("zero".into()),
                Sql::Text("9223372036854775808".into()),
                Sql::Text("-1".into()),
                Sql::Blob(vec![1]),
            ];
            for v in bad {
                assert!(
                    set(table, col, tail, row, v.clone()).is_err(),
                    "{at} = {v:?}"
                );
                assert_eq!(get(&db, table, col, row).0, Sql::Integer(*hi), "{at}");
            }
            // Lossless conversions land as the exact integer.
            for v in [Sql::Text(hi.to_string()), Sql::Real(*lo as f64)] {
                set(table, col, tail, row, v).unwrap();
            }
            assert_eq!(
                get(&db, table, col, row),
                (Sql::Integer(*lo), "integer".into()),
                "{at}"
            );
            set(table, col, tail, row, Sql::Integer(*hi)).unwrap();
        }
        drop(db);
        let db = Db::open_at(&path).unwrap();
        for (table, col, _, row, _, hi) in &probes {
            assert_eq!(
                get(&db, table, col, row),
                (Sql::Integer(*hi), "integer".into()),
                "{table}.{col}"
            );
        }
        // The head stays what the version says.
        let heads: i64 = db
            .conn
            .query_row(
                "SELECT count(*) FROM profile_bindings WHERE last_observed_head_hash IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(heads, 1);
    }
}
