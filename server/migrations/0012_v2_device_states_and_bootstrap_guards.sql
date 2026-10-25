-- Device states, the first-device bootstrap guard and its offline
-- confirmation (ADR 0001 D1, R1, R4).
--
-- Enrollment now stores a device as `pending` (plan L369); only an approval
-- makes it `active`. A device enrolled before this migration was inserted as
-- `active` without the proof-of-possession and approval contract, so nothing
-- proves it was ever trusted. R4 forbids downgrading such a row to `pending`
-- and forbids blessing it, so it becomes `quarantined`, with the reason
-- recorded in `v2_device_quarantine`. Revoked rows stay revoked.
--
-- `v2_bootstrap_guards` holds the one first-device opportunity of a tenant.
-- `tenant create` writes it as `unused`; it is never inferred from empty
-- tables. Here only a tenant that `tenant create` provably made (its offline
-- audit row) and that holds nothing yet is seeded `unused`; every other
-- existing tenant is `recovery_required`. Tenants of a database without an
-- identity mirror get their guard from the startup integrity pass, which
-- never writes `unused`.
--
-- `v2_device_approvals` is rebuilt with the 5.6.1 value checks and the
-- instance-scoped key the confirmation's consumed link refers to. No code
-- writes approvals yet, so the rebuild refuses a non-empty table instead of
-- guessing how to carry rows over.
--
-- Like 0011 this rebuilds tables, so it needs foreign-key enforcement off
-- (the application runner arranges that) and revalidates every foreign key
-- before committing.

CREATE TEMP TABLE m0012_fk_off (
    ok INTEGER NOT NULL
        CONSTRAINT m0012_requires_foreign_keys_off CHECK (ok = 1)
);
INSERT INTO temp.m0012_fk_off
SELECT foreign_keys = 0 FROM pragma_foreign_keys;

CREATE TEMP TABLE m0012_no_approvals (
    ok INTEGER NOT NULL
        CONSTRAINT m0012_device_approvals_must_be_empty CHECK (ok = 1)
);
INSERT INTO temp.m0012_no_approvals
SELECT NOT EXISTS (SELECT 1 FROM v2_device_approvals);

-- ---------------------------------------------------------------- devices ---

CREATE TABLE v2_devices_new (
    id                 BLOB    NOT NULL CHECK (length(id) = 16),
    tenant_id          BLOB    NOT NULL,
    account_id         BLOB    NOT NULL,
    label_ciphertext   BLOB    NOT NULL,
    signing_key_id     BLOB    NOT NULL CHECK (length(signing_key_id) = 32),
    signing_public_key BLOB    NOT NULL CHECK (length(signing_public_key) = 32),
    signing_suite      INTEGER NOT NULL CHECK (signing_suite BETWEEN 0 AND 9223372036854775807),
    hpke_key_id        BLOB    NOT NULL CHECK (length(hpke_key_id) = 32),
    hpke_public_key    BLOB    NOT NULL CHECK (length(hpke_public_key) = 32),
    hpke_suite         INTEGER NOT NULL CHECK (hpke_suite BETWEEN 0 AND 9223372036854775807),
    status             TEXT    NOT NULL
        CHECK (status IN ('pending', 'active', 'revoked', 'quarantined')),
    last_seen_at       TEXT,
    created_at         TEXT    NOT NULL,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES v2_accounts(tenant_id, id) ON DELETE CASCADE,
    UNIQUE (tenant_id, signing_key_id),
    UNIQUE (tenant_id, hpke_key_id)
);
INSERT INTO v2_devices_new
SELECT id, tenant_id, account_id, label_ciphertext, signing_key_id, signing_public_key,
       signing_suite, hpke_key_id, hpke_public_key, hpke_suite,
       CASE status WHEN 'active' THEN 'quarantined' ELSE status END,
       last_seen_at, created_at
  FROM v2_devices;

-- Why a device is quarantined. A row is never deleted: it is the record that
-- this device's keys were not trusted, kept for the operator's review.
CREATE TABLE v2_device_quarantine (
    tenant_id             BLOB NOT NULL,
    device_id             BLOB NOT NULL,
    reason                TEXT NOT NULL CHECK (reason IN (
                              'legacy_unproven_active', 'key_id_mismatch',
                              'invalid_key_encoding')),
    prior_status          TEXT NOT NULL CHECK (prior_status IN ('pending', 'active', 'revoked')),
    stored_signing_key_id BLOB NOT NULL CHECK (length(stored_signing_key_id) = 32),
    stored_hpke_key_id    BLOB NOT NULL CHECK (length(stored_hpke_key_id) = 32),
    created_at            TEXT NOT NULL,
    PRIMARY KEY (tenant_id, device_id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES v2_devices(tenant_id, id)
);
INSERT INTO v2_device_quarantine
SELECT tenant_id, id, 'legacy_unproven_active', 'active', signing_key_id, hpke_key_id,
       strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')
  FROM v2_devices
 WHERE status = 'active';

DROP TABLE v2_devices;
ALTER TABLE v2_devices_new RENAME TO v2_devices;
-- Dropping the old table dropped its index (0004).
CREATE INDEX v2_devices_by_account ON v2_devices (tenant_id, account_id);

-- R4: quarantining a device revokes its sessions in the same step.
UPDATE v2_sessions SET revoked_at = strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')
 WHERE revoked_at IS NULL
   AND EXISTS (SELECT 1 FROM v2_device_quarantine q
                WHERE q.tenant_id = v2_sessions.tenant_id
                  AND q.device_id = v2_sessions.device_id);

CREATE TRIGGER v2_device_quarantine_no_delete
BEFORE DELETE ON v2_device_quarantine
BEGIN
    SELECT RAISE(ABORT, 'v2_device_quarantine rows are permanent');
END;

-- A quarantined device leaves quarantine only through a reviewed path that
-- does not exist yet, so for now it can only be revoked. Keyed on the
-- quarantine record, not the old status, so revoking first is no way out.
CREATE TRIGGER v2_devices_quarantine_is_final
BEFORE UPDATE OF status ON v2_devices
WHEN NEW.status IN ('pending', 'active')
 AND (OLD.status = 'quarantined'
      OR EXISTS (SELECT 1 FROM v2_device_quarantine q
                  WHERE q.tenant_id = OLD.tenant_id AND q.device_id = OLD.id))
BEGIN
    SELECT RAISE(ABORT, 'a quarantined device can only be revoked');
END;

-- REPLACE would delete the old row without firing the delete trigger.
CREATE TRIGGER v2_device_quarantine_no_replace
BEFORE INSERT ON v2_device_quarantine
WHEN EXISTS (SELECT 1 FROM v2_device_quarantine q
              WHERE q.tenant_id = NEW.tenant_id AND q.device_id = NEW.device_id)
BEGIN
    SELECT RAISE(ABORT, 'v2_device_quarantine rows are permanent');
END;

-- -------------------------------------------------------------- approvals ---

DROP TABLE v2_device_approvals;
CREATE TABLE v2_device_approvals (
    tenant_id                        BLOB    NOT NULL REFERENCES v2_tenants(id),
    replay_id                        BLOB    NOT NULL CHECK (length(replay_id) = 16),
    payload_domain                   TEXT    NOT NULL
        CHECK (payload_domain = 'shardx.auth.device-approval.v2'),
    payload_version                  INTEGER NOT NULL CHECK (payload_version = 2),
    subject_account_id               BLOB    NOT NULL CHECK (length(subject_account_id) = 16),
    subject_device_id                BLOB    NOT NULL CHECK (length(subject_device_id) = 16),
    subject_signing_key_id           BLOB    NOT NULL CHECK (length(subject_signing_key_id) = 32),
    subject_hpke_key_id              BLOB    NOT NULL CHECK (length(subject_hpke_key_id) = 32),
    approval_scope_kind              TEXT    NOT NULL CHECK (approval_scope_kind IN ('tenant', 'fleet')),
    approval_scope_id                BLOB    NOT NULL CHECK (length(approval_scope_id) = 16),
    approved_use                     TEXT    NOT NULL CHECK (approved_use = 'team.device'),
    issued_at_ms                     INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
    not_before_ms                    INTEGER NOT NULL CHECK (not_before_ms BETWEEN 0 AND 9223372036854775807),
    not_after_ms                     INTEGER NOT NULL CHECK (not_after_ms BETWEEN 0 AND 9223372036854775807),
    server_instance_id               BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    restore_epoch                    INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    canonical_payload_bytes          BLOB    NOT NULL CHECK (length(canonical_payload_bytes) BETWEEN 1 AND 65536),
    payload_sha256                   BLOB    NOT NULL CHECK (length(payload_sha256) = 32),
    signature_suite_id               INTEGER NOT NULL CHECK (signature_suite_id = 1),
    signature_version                INTEGER NOT NULL CHECK (signature_version = 1),
    signature_bytes                  BLOB    NOT NULL CHECK (length(signature_bytes) = 64),
    issuer_signing_key_id            BLOB    NOT NULL CHECK (length(issuer_signing_key_id) = 32),
    signed_container_hash            BLOB    NOT NULL CHECK (length(signed_container_hash) = 32),
    exact_signed_container_bytes     BLOB    NOT NULL
        CHECK (length(exact_signed_container_bytes) BETWEEN 1 AND 262144),
    exact_signed_container_bytes_sha256 BLOB NOT NULL CHECK (length(exact_signed_container_bytes_sha256) = 32),
    revoked_at                       TEXT,
    created_at                       TEXT    NOT NULL,
    PRIMARY KEY (tenant_id, payload_domain, replay_id),
    -- The confirmation's consumed link names the instance as well.
    UNIQUE (server_instance_id, tenant_id, payload_domain, replay_id),
    FOREIGN KEY (tenant_id, subject_account_id) REFERENCES v2_accounts(tenant_id, id),
    FOREIGN KEY (tenant_id, subject_device_id) REFERENCES v2_devices(tenant_id, id),
    CHECK (subject_signing_key_id <> subject_hpke_key_id),
    CHECK (issued_at_ms <= not_before_ms AND not_before_ms < not_after_ms)
);
CREATE INDEX idx_v2_device_approvals_subject
    ON v2_device_approvals (tenant_id, subject_device_id, revoked_at);

-- --------------------------------------------------------- bootstrap guard ---

CREATE TABLE v2_bootstrap_guards (
    server_instance_id BLOB NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id          BLOB NOT NULL REFERENCES v2_tenants(id),
    state              TEXT NOT NULL CHECK (state IN (
                           'unused', 'reserved', 'consumed', 'closed', 'recovery_required')),
    recovery_reason    TEXT CHECK (recovery_reason IN (
                           'legacy_tenant', 'missing_guard', 'inconsistent_confirmation',
                           'integrity_failure')),
    updated_at         TEXT NOT NULL,
    PRIMARY KEY (server_instance_id, tenant_id),
    CHECK ((state = 'recovery_required') = (recovery_reason IS NOT NULL))
);

CREATE TRIGGER v2_bootstrap_guards_no_delete
BEFORE DELETE ON v2_bootstrap_guards
BEGIN
    SELECT RAISE(ABORT, 'a bootstrap guard is never deleted');
END;

-- R1: a used or closed guard never returns to `unused`, and recovery is final
-- until an operator investigation defines how it ends.
CREATE TRIGGER v2_bootstrap_guards_forward_only
BEFORE UPDATE OF state ON v2_bootstrap_guards
WHEN NOT (
       (OLD.state = 'unused'   AND NEW.state IN ('reserved', 'recovery_required'))
    OR (OLD.state = 'reserved' AND NEW.state IN ('consumed', 'closed', 'recovery_required'))
    OR (OLD.state IN ('consumed', 'closed') AND NEW.state = 'recovery_required')
)
BEGIN
    SELECT RAISE(ABORT, 'bootstrap guard transition not allowed');
END;

CREATE TRIGGER v2_bootstrap_guards_recovery_is_frozen
BEFORE UPDATE ON v2_bootstrap_guards
WHEN OLD.state = 'recovery_required'
BEGIN
    SELECT RAISE(ABORT, 'a guard in recovery_required is kept as found');
END;

-- A guard is born `unused` (tenant create) or `recovery_required`, and never
-- replaces another: REPLACE would skip the delete and transition triggers.
CREATE TRIGGER v2_bootstrap_guards_insert
BEFORE INSERT ON v2_bootstrap_guards
WHEN NEW.state NOT IN ('unused', 'recovery_required')
  OR EXISTS (SELECT 1 FROM v2_bootstrap_guards g
              WHERE g.server_instance_id = NEW.server_instance_id
                AND g.tenant_id = NEW.tenant_id)
BEGIN
    SELECT RAISE(ABORT, 'a bootstrap guard is inserted once, unused or recovery_required');
END;

CREATE TRIGGER v2_bootstrap_guards_identity_is_fixed
BEFORE UPDATE OF server_instance_id, tenant_id ON v2_bootstrap_guards
BEGIN
    SELECT RAISE(ABORT, 'a bootstrap guard cannot move to another instance or tenant');
END;

-- Seed only where the instance is known. `unused` needs proof that `tenant
-- create` made this tenant and that it holds nothing.
INSERT INTO v2_bootstrap_guards (server_instance_id, tenant_id, state, recovery_reason, updated_at)
SELECT s.server_instance_id, t.id,
       CASE WHEN EXISTS (SELECT 1 FROM v2_audit_events a
                          WHERE a.tenant_id = t.id AND a.action = 'tenant.create'
                            AND a.target_id = t.id
                            AND a.reason_code = 'offline_operator_cli')
             AND NOT EXISTS (SELECT 1 FROM v2_devices d WHERE d.tenant_id = t.id)
             AND NOT EXISTS (SELECT 1 FROM v2_capability_grants g WHERE g.tenant_id = t.id)
             AND NOT EXISTS (SELECT 1 FROM v2_root_key_generations r WHERE r.tenant_id = t.id)
             AND NOT EXISTS (SELECT 1 FROM v2_tenant_root_key_grants r WHERE r.tenant_id = t.id)
            THEN 'unused' ELSE 'recovery_required' END,
       CASE WHEN EXISTS (SELECT 1 FROM v2_audit_events a
                          WHERE a.tenant_id = t.id AND a.action = 'tenant.create'
                            AND a.target_id = t.id
                            AND a.reason_code = 'offline_operator_cli')
             AND NOT EXISTS (SELECT 1 FROM v2_devices d WHERE d.tenant_id = t.id)
             AND NOT EXISTS (SELECT 1 FROM v2_capability_grants g WHERE g.tenant_id = t.id)
             AND NOT EXISTS (SELECT 1 FROM v2_root_key_generations r WHERE r.tenant_id = t.id)
             AND NOT EXISTS (SELECT 1 FROM v2_tenant_root_key_grants r WHERE r.tenant_id = t.id)
            THEN NULL ELSE 'legacy_tenant' END,
       strftime('%Y-%m-%dT%H:%M:%f+00:00', 'now')
  FROM v2_tenants t, v2_server_state s;

-- ------------------------------------------------ first-device confirmation ---

-- One per tenant and instance, deliberately not per epoch (R1). Subject,
-- context and keys never change; the consumed link and terminal fields are
-- written once.
CREATE TABLE v2_first_device_confirmations (
    server_instance_id             BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id                      BLOB    NOT NULL REFERENCES v2_tenants(id),
    confirmation_id                BLOB    NOT NULL CHECK (length(confirmation_id) = 16),
    account_id                     BLOB    NOT NULL CHECK (length(account_id) = 16),
    device_id                      BLOB    NOT NULL CHECK (length(device_id) = 16),
    request_id                     BLOB    NOT NULL CHECK (length(request_id) = 16),
    restore_epoch                  INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    confirmed_at_ms                INTEGER NOT NULL CHECK (confirmed_at_ms BETWEEN 0 AND 9223372036854775807),
    signing_key_id                 BLOB    NOT NULL CHECK (length(signing_key_id) = 32),
    hpke_key_id                    BLOB    NOT NULL CHECK (length(hpke_key_id) = 32),
    signing_public_key             BLOB    NOT NULL CHECK (length(signing_public_key) = 32),
    hpke_public_key                BLOB    NOT NULL CHECK (length(hpke_public_key) = 32),
    signing_suite                  INTEGER NOT NULL CHECK (signing_suite = 1),
    hpke_suite                     INTEGER NOT NULL CHECK (hpke_suite = 1),
    state                          TEXT    NOT NULL
        CHECK (state IN ('pending', 'consumed', 'cancelled', 'invalidated')),
    consumed_at_ms                 INTEGER CHECK (consumed_at_ms BETWEEN 0 AND 9223372036854775807),
    approval_payload_domain        TEXT    CHECK (approval_payload_domain = 'shardx.auth.device-approval.v2'),
    approval_replay_id             BLOB    CHECK (length(approval_replay_id) = 16),
    approval_payload_sha256        BLOB    CHECK (length(approval_payload_sha256) = 32),
    approval_signed_container_hash BLOB    CHECK (length(approval_signed_container_hash) = 32),
    approval_outer_sha256          BLOB    CHECK (length(approval_outer_sha256) = 32),
    terminal_at_ms                 INTEGER CHECK (terminal_at_ms BETWEEN 0 AND 9223372036854775807),
    terminal_reason                TEXT    CHECK (terminal_reason IN (
                                       'operator_cancelled', 'device_revoked', 'epoch_changed',
                                       'integrity_failure')),
    PRIMARY KEY (server_instance_id, tenant_id),
    UNIQUE (server_instance_id, confirmation_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES v2_accounts(tenant_id, id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES v2_devices(tenant_id, id),
    FOREIGN KEY (server_instance_id, tenant_id, approval_payload_domain, approval_replay_id)
        REFERENCES v2_device_approvals(server_instance_id, tenant_id, payload_domain, replay_id)
        ON DELETE RESTRICT,
    CHECK (signing_key_id <> hpke_key_id),
    -- Every consumed field is present exactly when the row is consumed.
    CHECK ((state = 'consumed') = (consumed_at_ms IS NOT NULL)),
    CHECK ((state = 'consumed') = (approval_payload_domain IS NOT NULL)),
    CHECK ((state = 'consumed') = (approval_replay_id IS NOT NULL)),
    CHECK ((state = 'consumed') = (approval_payload_sha256 IS NOT NULL)),
    CHECK ((state = 'consumed') = (approval_signed_container_hash IS NOT NULL)),
    CHECK ((state = 'consumed') = (approval_outer_sha256 IS NOT NULL)),
    -- Terminal fields exactly when cancelled or invalidated, with a matching reason.
    CHECK ((state IN ('cancelled', 'invalidated')) = (terminal_at_ms IS NOT NULL)),
    CHECK ((state IN ('cancelled', 'invalidated')) = (terminal_reason IS NOT NULL)),
    CHECK (state <> 'cancelled' OR terminal_reason = 'operator_cancelled'),
    CHECK (state <> 'invalidated' OR terminal_reason <> 'operator_cancelled')
);

CREATE TRIGGER v2_first_device_confirmations_no_delete
BEFORE DELETE ON v2_first_device_confirmations
BEGIN
    SELECT RAISE(ABORT, 'a first-device confirmation is never deleted');
END;

CREATE TRIGGER v2_first_device_confirmations_tuple_is_fixed
BEFORE UPDATE OF server_instance_id, tenant_id, confirmation_id, account_id, device_id,
                 request_id, restore_epoch, confirmed_at_ms, signing_key_id, hpke_key_id,
                 signing_public_key, hpke_public_key, signing_suite, hpke_suite
ON v2_first_device_confirmations
BEGIN
    SELECT RAISE(ABORT, 'a first-device confirmation subject never changes');
END;

-- A confirmation is born pending and never replaces another.
CREATE TRIGGER v2_first_device_confirmations_insert
BEFORE INSERT ON v2_first_device_confirmations
WHEN NEW.state <> 'pending'
  OR EXISTS (SELECT 1 FROM v2_first_device_confirmations c
              WHERE (c.server_instance_id = NEW.server_instance_id AND c.tenant_id = NEW.tenant_id)
                 OR (c.server_instance_id = NEW.server_instance_id
                     AND c.confirmation_id = NEW.confirmation_id))
BEGIN
    SELECT RAISE(ABORT, 'a first-device confirmation is inserted once, pending');
END;

-- Only a pending row moves, once; a settled row (and its link) never changes.
-- A pending row cannot change without settling: the CHECKs above tie every
-- other mutable column to a settled state.
CREATE TRIGGER v2_first_device_confirmations_settled_is_final
BEFORE UPDATE ON v2_first_device_confirmations
WHEN OLD.state <> 'pending'
BEGIN
    SELECT RAISE(ABORT, 'a settled first-device confirmation never changes');
END;

-- Enforcement was off for the rebuild; prove every reference still holds,
-- in these tables and in every other one, before the migration commits.
CREATE TEMP TABLE m0012_foreign_keys (
    ok INTEGER NOT NULL
        CONSTRAINT m0012_foreign_key_violation CHECK (ok = 1)
);
INSERT INTO temp.m0012_foreign_keys
SELECT NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check);

DROP TABLE m0012_fk_off;
DROP TABLE m0012_no_approvals;
DROP TABLE m0012_foreign_keys;
