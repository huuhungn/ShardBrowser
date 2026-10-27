-- ADR 0002 D-9: the fleet key-generation lifecycle, FLEET_GENERATION_CREATE
-- and FLEET_GRANT_CREATE (`POST /v2/fleets/{id}/key-generations` and
-- `.../key-generations/{generation}/grants`).
--
-- `v2_idempotency` is rebuilt because its closed `operation_kind` CHECK (0015)
-- lacks the six D-9 kinds and a CHECK cannot change in place. Its index and
-- the triggers of 0015-0017 are recreated as they were.

CREATE TABLE v2_idempotency_new (
    server_instance_id          BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id                   BLOB    NOT NULL REFERENCES v2_tenants(id),
    actor_device_id             BLOB    NOT NULL CHECK (length(actor_device_id) = 16),
    operation_scope             TEXT    NOT NULL CHECK (length(operation_scope) BETWEEN 1 AND 128),
    idempotency_key             BLOB    NOT NULL CHECK (length(idempotency_key) = 16),
    operation_kind              TEXT    NOT NULL CHECK (operation_kind IN (
        'PROFILE_PUBLISH_CREATE', 'PROFILE_CHECKOUT', 'CREATE_UPLOAD', 'FINALIZE_UPLOAD',
        'RELEASE_LEASE', 'LOCAL_UNBIND', 'ROOT_GENERATION_CREATE', 'ROOT_GRANT_CREATE',
        'ROOT_GRANT_ACK', 'ROOT_GENERATION_ACTIVATE', 'ROOT_GRANT_REVOKE',
        'FLEET_GENERATION_CREATE', 'FLEET_GRANT_CREATE', 'FLEET_GRANT_ACK',
        'FLEET_GENERATION_ACTIVATE', 'FLEET_GRANT_REVOKE', 'DEVICE_REVOKE',
        'COMMIT', 'DEVICE_APPROVE')),
    canonical_request_hash      BLOB    NOT NULL CHECK (length(canonical_request_hash) = 32),
    exact_request_bytes         BLOB    NOT NULL
        CHECK (length(exact_request_bytes) BETWEEN 1 AND 262144),
    exact_request_bytes_sha256  BLOB    NOT NULL CHECK (length(exact_request_bytes_sha256) = 32),
    status                      TEXT    NOT NULL CHECK (status IN ('in_flight', 'succeeded', 'failed')),
    response_record_type        TEXT,
    exact_response_bytes        BLOB,
    exact_response_bytes_sha256 BLOB    CHECK (length(exact_response_bytes_sha256) = 32),
    retained_until              INTEGER NOT NULL
        CHECK (retained_until BETWEEN 0 AND 9223372036854775807),
    approval_payload_domain     TEXT
        CHECK (approval_payload_domain = 'shardx.auth.device-approval.v2'),
    restore_epoch               INTEGER CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    actor_account_id            BLOB    CHECK (length(actor_account_id) = 16),
    subject_device_id           BLOB    CHECK (length(subject_device_id) = 16),
    PRIMARY KEY (server_instance_id, tenant_id, actor_device_id, operation_scope, idempotency_key),
    -- NULL for every other kind, so the reference only binds approvals.
    FOREIGN KEY (tenant_id, approval_payload_domain, idempotency_key)
        REFERENCES v2_device_approvals(tenant_id, payload_domain, replay_id) ON DELETE RESTRICT,
    CHECK ((operation_kind = 'DEVICE_APPROVE') = (approval_payload_domain IS NOT NULL)),
    CHECK ((operation_kind = 'DEVICE_APPROVE') = (restore_epoch IS NOT NULL)),
    CHECK ((operation_kind = 'DEVICE_APPROVE') = (actor_account_id IS NOT NULL)),
    CHECK ((operation_kind = 'DEVICE_APPROVE') = (subject_device_id IS NOT NULL)),
    -- Only the committing transaction writes an approval row, with its receipt.
    -- A comparison with NULL is NULL, which a CHECK lets through, so every
    -- required column is also named IS NOT NULL.
    CHECK (operation_kind <> 'DEVICE_APPROVE' OR (
        operation_scope = 'tenant.device-approve.v2'
        AND status = 'succeeded'
        AND response_record_type IS NOT NULL
        AND response_record_type = 'DeviceApprovalReceiptV2'
        AND exact_response_bytes IS NOT NULL
        AND length(exact_response_bytes) BETWEEN 1 AND 4096
        AND exact_response_bytes_sha256 IS NOT NULL))
);

INSERT INTO v2_idempotency_new SELECT * FROM v2_idempotency;
DROP TABLE v2_idempotency;
ALTER TABLE v2_idempotency_new RENAME TO v2_idempotency;

CREATE UNIQUE INDEX v2_idempotency_one_row_per_approval
    ON v2_idempotency (tenant_id, approval_payload_domain, idempotency_key)
 WHERE operation_kind = 'DEVICE_APPROVE';

CREATE TRIGGER v2_idempotency_device_approve_is_fixed
BEFORE UPDATE ON v2_idempotency
WHEN OLD.operation_kind = 'DEVICE_APPROVE'
BEGIN
    SELECT RAISE(ABORT, 'a device-approval idempotency row never changes');
END;

CREATE TRIGGER v2_idempotency_succeeded_is_fixed
BEFORE UPDATE ON v2_idempotency
WHEN OLD.status = 'succeeded'
BEGIN
    SELECT RAISE(ABORT, 'a stored idempotent response never changes');
END;

CREATE TRIGGER v2_idempotency_succeeded_no_replace
BEFORE INSERT ON v2_idempotency
WHEN EXISTS (SELECT 1 FROM v2_idempotency i
              WHERE i.status = 'succeeded'
                AND ((i.server_instance_id = NEW.server_instance_id
                      AND i.tenant_id = NEW.tenant_id
                      AND i.actor_device_id = NEW.actor_device_id
                      AND i.operation_scope = NEW.operation_scope
                      AND i.idempotency_key = NEW.idempotency_key)
                  OR (NEW.operation_kind = 'DEVICE_APPROVE'
                      AND i.operation_kind = 'DEVICE_APPROVE'
                      AND i.tenant_id = NEW.tenant_id
                      AND i.idempotency_key = NEW.idempotency_key)))
BEGIN
    SELECT RAISE(ABORT, 'a stored idempotent response never changes');
END;

CREATE TRIGGER v2_idempotency_root_generation_create_is_complete
BEFORE INSERT ON v2_idempotency
WHEN NEW.operation_kind = 'ROOT_GENERATION_CREATE'
 AND (NEW.operation_scope IS NOT 'tenant.root-generation-create.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'TenantRootGenerationCreatedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a root generation create is stored with its response');
END;

CREATE TRIGGER v2_idempotency_root_grant_ack_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'ROOT_GRANT_ACK' OR NEW.operation_scope = 'tenant.root-grant-ack.v2')
 AND (NEW.operation_kind IS NOT 'ROOT_GRANT_ACK'
      OR NEW.operation_scope IS NOT 'tenant.root-grant-ack.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'TenantRootGrantAckedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a root grant acknowledgement is stored with its response');
END;

CREATE TRIGGER v2_idempotency_root_generation_activate_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'ROOT_GENERATION_ACTIVATE'
       OR NEW.operation_scope = 'tenant.root-generation-activate.v2')
 AND (NEW.operation_kind IS NOT 'ROOT_GENERATION_ACTIVATE'
      OR NEW.operation_scope IS NOT 'tenant.root-generation-activate.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'TenantRootGenerationActivatedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a root generation activation is stored with its response');
END;

-- A fleet create and a fleet grant filing commit with their responses.
CREATE TRIGGER v2_idempotency_fleet_generation_create_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'FLEET_GENERATION_CREATE'
       OR NEW.operation_scope = 'fleet.key-generation-create.v2')
 AND (NEW.operation_kind IS NOT 'FLEET_GENERATION_CREATE'
      OR NEW.operation_scope IS NOT 'fleet.key-generation-create.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'FleetKeyGenerationCreatedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a fleet generation create is stored with its response');
END;

CREATE TRIGGER v2_idempotency_fleet_grant_create_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'FLEET_GRANT_CREATE' OR NEW.operation_scope = 'fleet.key-grant-create.v2')
 AND (NEW.operation_kind IS NOT 'FLEET_GRANT_CREATE'
      OR NEW.operation_scope IS NOT 'fleet.key-grant-create.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'FleetKeyGrantCreatedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a fleet grant filing is stored with its response');
END;

-- ------------------------------------------------------ fleet generations ---

-- The D-9 terms a generation is created and activated under. NULL on rows the
-- legacy self-grant path wrote, which has none; FLEET_GENERATION_CREATE
-- writes all three, and the rotation hash iff it rotates.
ALTER TABLE v2_fleet_key_generations ADD COLUMN required_device_grant_count INTEGER
    CHECK (required_device_grant_count BETWEEN 1 AND 65535);
ALTER TABLE v2_fleet_key_generations ADD COLUMN required_grant_set_hash BLOB
    CHECK (length(required_grant_set_hash) = 32);
ALTER TABLE v2_fleet_key_generations ADD COLUMN recovery_grant_hash BLOB
    CHECK (length(recovery_grant_hash) = 32);
ALTER TABLE v2_fleet_key_generations ADD COLUMN previous_fkek_key_id BLOB
    CHECK (length(previous_fkek_key_id) = 32);
ALTER TABLE v2_fleet_key_generations ADD COLUMN rotation_grant_hash BLOB
    CHECK (length(rotation_grant_hash) = 32);

-- ---------------------------------------------------------- fleet grants ---

-- Plan 7.2 rows for the three D-9 `FleetKeyGrantV2` variants, one table each.
-- Every column is read from the verified record; the exact container is the
-- authority. A grant starts PENDING_ACK (acked_at NULL).
CREATE TABLE v2_fleet_device_hpke_grants (
    server_instance_id               BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id                        BLOB    NOT NULL,
    replay_id                        BLOB    NOT NULL CHECK (length(replay_id) = 16),
    payload_domain                   TEXT    NOT NULL
        CHECK (payload_domain = 'shardx.keys.fleet-key-grant.device-hpke.v2'),
    payload_version                  INTEGER NOT NULL CHECK (payload_version = 2),
    grant_variant                    TEXT    NOT NULL CHECK (grant_variant = 'DeviceHpkeGrant'),
    fleet_id                         BLOB    NOT NULL CHECK (length(fleet_id) = 16),
    fkek_key_id                      BLOB    NOT NULL CHECK (length(fkek_key_id) = 32),
    generation                       INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
    grant_capability                 TEXT    NOT NULL CHECK (grant_capability = 'fleet.key.receive'),
    subject_account_id               BLOB    NOT NULL CHECK (length(subject_account_id) = 16),
    subject_device_id                BLOB    NOT NULL CHECK (length(subject_device_id) = 16),
    subject_signing_key_id           BLOB    NOT NULL CHECK (length(subject_signing_key_id) = 32),
    recipient_hpke_key_id            BLOB    NOT NULL CHECK (length(recipient_hpke_key_id) = 32),
    hpke_suite_id                    INTEGER NOT NULL CHECK (hpke_suite_id = 1),
    hpke_info_bytes                  BLOB    NOT NULL CHECK (length(hpke_info_bytes) BETWEEN 1 AND 1024),
    hpke_encapped_key_bytes          BLOB    NOT NULL CHECK (length(hpke_encapped_key_bytes) = 32),
    hpke_wrapped_fleet_key_bytes     BLOB    NOT NULL CHECK (length(hpke_wrapped_fleet_key_bytes) = 48),
    issued_at_ms                     INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
    not_before_ms                    INTEGER NOT NULL CHECK (not_before_ms BETWEEN 0 AND 9223372036854775807),
    not_after_ms                     INTEGER NOT NULL CHECK (not_after_ms BETWEEN 0 AND 9223372036854775807),
    restore_epoch                    INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    canonical_payload_bytes          BLOB    NOT NULL CHECK (length(canonical_payload_bytes) BETWEEN 1 AND 65536),
    payload_sha256                   BLOB    NOT NULL CHECK (length(payload_sha256) = 32),
    signature_suite_id               INTEGER NOT NULL CHECK (signature_suite_id = 1),
    signature_version                INTEGER NOT NULL CHECK (signature_version = 1),
    signature_bytes                  BLOB    NOT NULL CHECK (length(signature_bytes) = 64),
    issuer_signing_key_id            BLOB    NOT NULL CHECK (length(issuer_signing_key_id) = 32),
    signed_container_hash            BLOB    NOT NULL CHECK (length(signed_container_hash) = 32),
    exact_signed_container_bytes     BLOB    NOT NULL
        CHECK (length(exact_signed_container_bytes) BETWEEN 1 AND 131072),
    exact_signed_container_bytes_sha256 BLOB NOT NULL
        CHECK (length(exact_signed_container_bytes_sha256) = 32),
    acked_at                         TEXT,
    revoked_at                       TEXT,
    created_at                       TEXT    NOT NULL,
    PRIMARY KEY (server_instance_id, tenant_id, replay_id),
    UNIQUE (server_instance_id, tenant_id, payload_domain, replay_id),
    FOREIGN KEY (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id)
        REFERENCES v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id),
    FOREIGN KEY (tenant_id, subject_account_id) REFERENCES v2_accounts(tenant_id, id),
    FOREIGN KEY (tenant_id, subject_device_id) REFERENCES v2_devices(tenant_id, id),
    CHECK (subject_signing_key_id <> recipient_hpke_key_id),
    CHECK (issued_at_ms <= not_before_ms AND not_before_ms < not_after_ms)
);
CREATE INDEX idx_v2_fleet_device_hpke_grants_subject
    ON v2_fleet_device_hpke_grants (tenant_id, subject_device_id, revoked_at);

CREATE TABLE v2_fleet_recovery_grants (
    server_instance_id               BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id                        BLOB    NOT NULL,
    replay_id                        BLOB    NOT NULL CHECK (length(replay_id) = 16),
    payload_domain                   TEXT    NOT NULL
        CHECK (payload_domain = 'shardx.keys.fleet-key-grant.recovery.v2'),
    payload_version                  INTEGER NOT NULL CHECK (payload_version = 2),
    grant_variant                    TEXT    NOT NULL CHECK (grant_variant = 'RecoveryGrant'),
    fleet_id                         BLOB    NOT NULL CHECK (length(fleet_id) = 16),
    fkek_key_id                      BLOB    NOT NULL CHECK (length(fkek_key_id) = 32),
    generation                       INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
    grant_capability                 TEXT    NOT NULL CHECK (grant_capability = 'fleet.key.recover'),
    recipient_root_key_id            BLOB    NOT NULL CHECK (length(recipient_root_key_id) = 32),
    recipient_root_generation        INTEGER NOT NULL
        CHECK (recipient_root_generation BETWEEN 0 AND 9223372036854775807),
    root_wrap_suite_id               INTEGER NOT NULL CHECK (root_wrap_suite_id = 1),
    root_wrap_nonce_bytes            BLOB    NOT NULL CHECK (length(root_wrap_nonce_bytes) = 12),
    root_wrap_context_bytes          BLOB    NOT NULL CHECK (length(root_wrap_context_bytes) BETWEEN 1 AND 1024),
    wrapped_fleet_key_bytes          BLOB    NOT NULL CHECK (length(wrapped_fleet_key_bytes) = 48),
    issued_at_ms                     INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
    not_before_ms                    INTEGER NOT NULL CHECK (not_before_ms BETWEEN 0 AND 9223372036854775807),
    not_after_ms                     INTEGER NOT NULL CHECK (not_after_ms BETWEEN 0 AND 9223372036854775807),
    restore_epoch                    INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    canonical_payload_bytes          BLOB    NOT NULL CHECK (length(canonical_payload_bytes) BETWEEN 1 AND 65536),
    payload_sha256                   BLOB    NOT NULL CHECK (length(payload_sha256) = 32),
    signature_suite_id               INTEGER NOT NULL CHECK (signature_suite_id = 1),
    signature_version                INTEGER NOT NULL CHECK (signature_version = 1),
    signature_bytes                  BLOB    NOT NULL CHECK (length(signature_bytes) = 64),
    issuer_signing_key_id            BLOB    NOT NULL CHECK (length(issuer_signing_key_id) = 32),
    signed_container_hash            BLOB    NOT NULL CHECK (length(signed_container_hash) = 32),
    exact_signed_container_bytes     BLOB    NOT NULL
        CHECK (length(exact_signed_container_bytes) BETWEEN 1 AND 131072),
    exact_signed_container_bytes_sha256 BLOB NOT NULL
        CHECK (length(exact_signed_container_bytes_sha256) = 32),
    acked_at                         TEXT,
    revoked_at                       TEXT,
    created_at                       TEXT    NOT NULL,
    PRIMARY KEY (server_instance_id, tenant_id, replay_id),
    UNIQUE (server_instance_id, tenant_id, payload_domain, replay_id),
    FOREIGN KEY (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id)
        REFERENCES v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id),
    FOREIGN KEY (server_instance_id, tenant_id, recipient_root_generation, recipient_root_key_id)
        REFERENCES v2_root_key_generations (server_instance_id, tenant_id, generation, root_key_id),
    CHECK (issued_at_ms <= not_before_ms AND not_before_ms < not_after_ms)
);
CREATE INDEX idx_v2_fleet_recovery_grants_generation
    ON v2_fleet_recovery_grants (server_instance_id, tenant_id, fleet_id, generation);

CREATE TABLE v2_fleet_rotation_grants (
    server_instance_id               BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id                        BLOB    NOT NULL,
    replay_id                        BLOB    NOT NULL CHECK (length(replay_id) = 16),
    payload_domain                   TEXT    NOT NULL
        CHECK (payload_domain = 'shardx.keys.fleet-key-grant.rotation.v2'),
    payload_version                  INTEGER NOT NULL CHECK (payload_version = 2),
    grant_variant                    TEXT    NOT NULL CHECK (grant_variant = 'RotationGrant'),
    fleet_id                         BLOB    NOT NULL CHECK (length(fleet_id) = 16),
    fkek_key_id                      BLOB    NOT NULL CHECK (length(fkek_key_id) = 32),
    generation                       INTEGER NOT NULL CHECK (generation BETWEEN 1 AND 9223372036854775807),
    grant_capability                 TEXT    NOT NULL CHECK (grant_capability = 'key.rotate'),
    previous_fkek_key_id             BLOB    NOT NULL CHECK (length(previous_fkek_key_id) = 32),
    previous_generation              INTEGER NOT NULL
        CHECK (previous_generation BETWEEN 0 AND 9223372036854775807),
    required_device_grant_count      INTEGER NOT NULL CHECK (required_device_grant_count BETWEEN 1 AND 65535),
    required_device_grant_set_hash   BLOB    NOT NULL CHECK (length(required_device_grant_set_hash) = 32),
    recovery_grant_signed_container_hash BLOB NOT NULL
        CHECK (length(recovery_grant_signed_container_hash) = 32),
    activation_not_before_ms         INTEGER NOT NULL
        CHECK (activation_not_before_ms BETWEEN 0 AND 9223372036854775807),
    issued_at_ms                     INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
    not_before_ms                    INTEGER NOT NULL CHECK (not_before_ms BETWEEN 0 AND 9223372036854775807),
    not_after_ms                     INTEGER NOT NULL CHECK (not_after_ms BETWEEN 0 AND 9223372036854775807),
    restore_epoch                    INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    canonical_payload_bytes          BLOB    NOT NULL CHECK (length(canonical_payload_bytes) BETWEEN 1 AND 65536),
    payload_sha256                   BLOB    NOT NULL CHECK (length(payload_sha256) = 32),
    signature_suite_id               INTEGER NOT NULL CHECK (signature_suite_id = 1),
    signature_version                INTEGER NOT NULL CHECK (signature_version = 1),
    signature_bytes                  BLOB    NOT NULL CHECK (length(signature_bytes) = 64),
    issuer_signing_key_id            BLOB    NOT NULL CHECK (length(issuer_signing_key_id) = 32),
    signed_container_hash            BLOB    NOT NULL CHECK (length(signed_container_hash) = 32),
    exact_signed_container_bytes     BLOB    NOT NULL
        CHECK (length(exact_signed_container_bytes) BETWEEN 1 AND 131072),
    exact_signed_container_bytes_sha256 BLOB NOT NULL
        CHECK (length(exact_signed_container_bytes_sha256) = 32),
    acked_at                         TEXT,
    revoked_at                       TEXT,
    created_at                       TEXT    NOT NULL,
    PRIMARY KEY (server_instance_id, tenant_id, replay_id),
    UNIQUE (server_instance_id, tenant_id, payload_domain, replay_id),
    FOREIGN KEY (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id)
        REFERENCES v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id),
    CHECK (generation = previous_generation + 1 AND previous_fkek_key_id <> fkek_key_id),
    CHECK (activation_not_before_ms >= not_before_ms AND activation_not_before_ms < not_after_ms),
    CHECK (issued_at_ms <= not_before_ms AND not_before_ms < not_after_ms)
);
-- One rotation grant per target generation: the create row names exactly one.
CREATE UNIQUE INDEX idx_v2_fleet_rotation_grants_one_per_generation
    ON v2_fleet_rotation_grants (server_instance_id, tenant_id, fleet_id, generation);

-- A grant is history: acknowledged once, revoked once, never edited or removed.
CREATE TRIGGER v2_fleet_device_hpke_grants_no_delete
BEFORE DELETE ON v2_fleet_device_hpke_grants
BEGIN
    SELECT RAISE(ABORT, 'a fleet device grant is never deleted');
END;

CREATE TRIGGER v2_fleet_device_hpke_grants_record_is_fixed
BEFORE UPDATE OF server_instance_id, tenant_id, replay_id, payload_domain, payload_version,
                 grant_variant, fleet_id, fkek_key_id, generation, grant_capability,
                 subject_account_id, subject_device_id, subject_signing_key_id,
                 recipient_hpke_key_id, hpke_suite_id, hpke_info_bytes, hpke_encapped_key_bytes,
                 hpke_wrapped_fleet_key_bytes, issued_at_ms, not_before_ms, not_after_ms,
                 restore_epoch, canonical_payload_bytes, payload_sha256, signature_suite_id,
                 signature_version, signature_bytes, issuer_signing_key_id,
                 signed_container_hash, exact_signed_container_bytes,
                 exact_signed_container_bytes_sha256, created_at
ON v2_fleet_device_hpke_grants
BEGIN
    SELECT RAISE(ABORT, 'a fleet device grant record never changes');
END;

CREATE TRIGGER v2_fleet_device_hpke_grants_no_replace
BEFORE INSERT ON v2_fleet_device_hpke_grants
WHEN EXISTS (SELECT 1 FROM v2_fleet_device_hpke_grants g
              WHERE g.server_instance_id = NEW.server_instance_id
                AND g.tenant_id = NEW.tenant_id AND g.replay_id = NEW.replay_id)
BEGIN
    SELECT RAISE(ABORT, 'a fleet device grant is never replaced');
END;

CREATE TRIGGER v2_fleet_device_hpke_grants_marks_are_final
BEFORE UPDATE OF acked_at, revoked_at ON v2_fleet_device_hpke_grants
WHEN (OLD.acked_at IS NOT NULL AND NEW.acked_at IS NOT OLD.acked_at)
  OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
BEGIN
    SELECT RAISE(ABORT, 'an acknowledgement or revocation is written once');
END;

CREATE TRIGGER v2_fleet_recovery_grants_no_delete
BEFORE DELETE ON v2_fleet_recovery_grants
BEGIN
    SELECT RAISE(ABORT, 'a fleet recovery grant is never deleted');
END;

CREATE TRIGGER v2_fleet_recovery_grants_record_is_fixed
BEFORE UPDATE OF server_instance_id, tenant_id, replay_id, payload_domain, payload_version,
                 grant_variant, fleet_id, fkek_key_id, generation, grant_capability,
                 recipient_root_key_id, recipient_root_generation, root_wrap_suite_id,
                 root_wrap_nonce_bytes, root_wrap_context_bytes, wrapped_fleet_key_bytes,
                 issued_at_ms, not_before_ms, not_after_ms, restore_epoch,
                 canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version,
                 signature_bytes, issuer_signing_key_id, signed_container_hash,
                 exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at
ON v2_fleet_recovery_grants
BEGIN
    SELECT RAISE(ABORT, 'a fleet recovery grant record never changes');
END;

CREATE TRIGGER v2_fleet_recovery_grants_no_replace
BEFORE INSERT ON v2_fleet_recovery_grants
WHEN EXISTS (SELECT 1 FROM v2_fleet_recovery_grants g
              WHERE g.server_instance_id = NEW.server_instance_id
                AND g.tenant_id = NEW.tenant_id AND g.replay_id = NEW.replay_id)
BEGIN
    SELECT RAISE(ABORT, 'a fleet recovery grant is never replaced');
END;

CREATE TRIGGER v2_fleet_recovery_grants_marks_are_final
BEFORE UPDATE OF acked_at, revoked_at ON v2_fleet_recovery_grants
WHEN (OLD.acked_at IS NOT NULL AND NEW.acked_at IS NOT OLD.acked_at)
  OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
BEGIN
    SELECT RAISE(ABORT, 'an acknowledgement or revocation is written once');
END;

CREATE TRIGGER v2_fleet_rotation_grants_no_delete
BEFORE DELETE ON v2_fleet_rotation_grants
BEGIN
    SELECT RAISE(ABORT, 'a fleet rotation grant is never deleted');
END;

CREATE TRIGGER v2_fleet_rotation_grants_record_is_fixed
BEFORE UPDATE OF server_instance_id, tenant_id, replay_id, payload_domain, payload_version,
                 grant_variant, fleet_id, fkek_key_id, generation, grant_capability,
                 previous_fkek_key_id, previous_generation, required_device_grant_count,
                 required_device_grant_set_hash, recovery_grant_signed_container_hash,
                 activation_not_before_ms, issued_at_ms, not_before_ms, not_after_ms,
                 restore_epoch, canonical_payload_bytes, payload_sha256, signature_suite_id,
                 signature_version, signature_bytes, issuer_signing_key_id,
                 signed_container_hash, exact_signed_container_bytes,
                 exact_signed_container_bytes_sha256, created_at
ON v2_fleet_rotation_grants
BEGIN
    SELECT RAISE(ABORT, 'a fleet rotation grant record never changes');
END;

CREATE TRIGGER v2_fleet_rotation_grants_no_replace
BEFORE INSERT ON v2_fleet_rotation_grants
WHEN EXISTS (SELECT 1 FROM v2_fleet_rotation_grants g
              WHERE g.server_instance_id = NEW.server_instance_id
                AND g.tenant_id = NEW.tenant_id AND g.replay_id = NEW.replay_id)
BEGIN
    SELECT RAISE(ABORT, 'a fleet rotation grant is never replaced');
END;

CREATE TRIGGER v2_fleet_rotation_grants_marks_are_final
BEFORE UPDATE OF acked_at, revoked_at ON v2_fleet_rotation_grants
WHEN (OLD.acked_at IS NOT NULL AND NEW.acked_at IS NOT OLD.acked_at)
  OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
BEGIN
    SELECT RAISE(ABORT, 'an acknowledgement or revocation is written once');
END;
