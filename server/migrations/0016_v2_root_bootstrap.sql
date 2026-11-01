-- Plan 5.6.4 and 7.2: the exact `TenantRootKeyGrantV2` table, and the
-- custodian and recovery columns a root generation carries from its create
-- request (ADR 0002 D-4, D-5). The first writer is the S6 bootstrap,
-- `POST /v2/tenants/{id}/root-key-generations`.
--
-- Grants of the earlier spike shape (`CustodianIssued`, another payload
-- domain, no payload bytes) cannot be restated in the exact table, so they
-- stay as they are under `v2_legacy_tenant_root_key_grants`: read-only, never
-- used to authorize anything. A tenant that holds any of them reached 0012 or
-- later with history, so its bootstrap guard is not `unused`.

ALTER TABLE v2_tenant_root_key_grants RENAME TO v2_legacy_tenant_root_key_grants;
DROP INDEX idx_v2_tenant_root_key_grants_one_self_grant;

CREATE TRIGGER v2_legacy_tenant_root_key_grants_no_insert
BEFORE INSERT ON v2_legacy_tenant_root_key_grants
BEGIN
    SELECT RAISE(ABORT, 'legacy root key grants are read-only');
END;

CREATE TRIGGER v2_legacy_tenant_root_key_grants_no_update
BEFORE UPDATE ON v2_legacy_tenant_root_key_grants
BEGIN
    SELECT RAISE(ABORT, 'legacy root key grants are read-only');
END;

-- Deleting a tenant may still remove them through the cascade.

-- ------------------------------------------------------- root generations ---

-- NULL only on rows from before 0016; every new row names its custodian set
-- and recovery bundle, which activation checks.
ALTER TABLE v2_root_key_generations ADD COLUMN required_custodian_grant_count INTEGER
    CHECK (required_custodian_grant_count BETWEEN 1 AND 65535);
ALTER TABLE v2_root_key_generations ADD COLUMN required_custodian_grant_set_hash BLOB
    CHECK (length(required_custodian_grant_set_hash) = 32);
ALTER TABLE v2_root_key_generations ADD COLUMN recovery_bundle_sha256 BLOB
    CHECK (length(recovery_bundle_sha256) = 32);

CREATE TRIGGER v2_root_key_generations_new_rows_are_complete
BEFORE INSERT ON v2_root_key_generations
WHEN NEW.required_custodian_grant_count IS NULL
  OR NEW.required_custodian_grant_set_hash IS NULL
  OR NEW.recovery_bundle_sha256 IS NULL
BEGIN
    SELECT RAISE(ABORT, 'a root generation names its custodian set and recovery bundle');
END;

-- REPLACE would delete the old row without firing any delete trigger.
CREATE TRIGGER v2_root_key_generations_no_replace
BEFORE INSERT ON v2_root_key_generations
WHEN EXISTS (SELECT 1 FROM v2_root_key_generations g
              WHERE g.server_instance_id = NEW.server_instance_id
                AND g.tenant_id = NEW.tenant_id
                AND (g.generation = NEW.generation OR g.root_key_id = NEW.root_key_id))
BEGIN
    SELECT RAISE(ABORT, 'a root generation is never replaced');
END;

CREATE TRIGGER v2_root_key_generations_terms_are_fixed
BEFORE UPDATE OF server_instance_id, tenant_id, generation, root_key_id,
                 required_custodian_grant_count, required_custodian_grant_set_hash,
                 recovery_bundle_sha256
ON v2_root_key_generations
BEGIN
    SELECT RAISE(ABORT, 'a root generation keeps the terms it was created with');
END;

-- ----------------------------------------------------------- root grants ---

CREATE TABLE v2_tenant_root_key_grants (
    server_instance_id               BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id                        BLOB    NOT NULL REFERENCES v2_tenants(id),
    replay_id                        BLOB    NOT NULL CHECK (length(replay_id) = 16),
    container_domain                 TEXT    NOT NULL
        CHECK (container_domain = 'shardx.authorization.signed-container.v2'),
    container_version                INTEGER NOT NULL CHECK (container_version = 2),
    payload_domain                   TEXT    NOT NULL
        CHECK (payload_domain = 'shardx.keys.tenant-root-key-grant.v2'),
    payload_version                  INTEGER NOT NULL CHECK (payload_version = 2),
    grant_variant                    TEXT    NOT NULL
        CHECK (grant_variant IN ('FirstRootSelfGrant', 'ExistingRootGrant', 'RotationGrant')),
    root_key_id                      BLOB    NOT NULL CHECK (length(root_key_id) = 32),
    root_generation                  INTEGER NOT NULL
        CHECK (root_generation BETWEEN 0 AND 9223372036854775807),
    grant_capability                 TEXT    NOT NULL CHECK (grant_capability = 'root.custody'),
    subject_account_id               BLOB    NOT NULL CHECK (length(subject_account_id) = 16),
    subject_device_id                BLOB    NOT NULL CHECK (length(subject_device_id) = 16),
    subject_signing_key_id           BLOB    NOT NULL CHECK (length(subject_signing_key_id) = 32),
    -- Constant, so the approval link can be a foreign key.
    subject_device_approval_payload_domain TEXT NOT NULL
        CHECK (subject_device_approval_payload_domain = 'shardx.auth.device-approval.v2'),
    subject_device_approval_replay_id BLOB   NOT NULL
        CHECK (length(subject_device_approval_replay_id) = 16),
    recipient_hpke_key_id            BLOB    NOT NULL CHECK (length(recipient_hpke_key_id) = 32),
    hpke_suite_id                    INTEGER NOT NULL CHECK (hpke_suite_id = 1),
    hpke_mode_id                     INTEGER NOT NULL CHECK (hpke_mode_id = 0),
    hpke_kem_id                      INTEGER NOT NULL CHECK (hpke_kem_id = 32),
    hpke_kdf_id                      INTEGER NOT NULL CHECK (hpke_kdf_id = 1),
    hpke_aead_id                     INTEGER NOT NULL CHECK (hpke_aead_id = 3),
    hpke_info_bytes                  BLOB    NOT NULL CHECK (length(hpke_info_bytes) BETWEEN 1 AND 1024),
    hpke_encapped_key_bytes          BLOB    NOT NULL CHECK (length(hpke_encapped_key_bytes) = 32),
    hpke_wrapped_trk_bytes           BLOB    NOT NULL CHECK (length(hpke_wrapped_trk_bytes) = 48),
    previous_root_key_id             BLOB    CHECK (length(previous_root_key_id) = 32),
    previous_root_generation         INTEGER
        CHECK (previous_root_generation BETWEEN 0 AND 9223372036854775807),
    issued_at_ms                     INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
    not_before_ms                    INTEGER NOT NULL CHECK (not_before_ms BETWEEN 0 AND 9223372036854775807),
    not_after_ms                     INTEGER NOT NULL CHECK (not_after_ms BETWEEN 0 AND 9223372036854775807),
    restore_epoch                    INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    canonical_payload_bytes          BLOB    NOT NULL CHECK (length(canonical_payload_bytes) BETWEEN 1 AND 65536),
    payload_sha256                   BLOB    NOT NULL CHECK (length(payload_sha256) = 32),
    signature_suite_id               INTEGER NOT NULL CHECK (signature_suite_id = 1),
    signature_version                INTEGER NOT NULL CHECK (signature_version = 1),
    issuer_signing_key_id            BLOB    NOT NULL CHECK (length(issuer_signing_key_id) = 32),
    signature_bytes                  BLOB    NOT NULL CHECK (length(signature_bytes) = 64),
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
    FOREIGN KEY (server_instance_id, tenant_id, root_generation, root_key_id)
        REFERENCES v2_root_key_generations (server_instance_id, tenant_id, generation, root_key_id),
    FOREIGN KEY (tenant_id, subject_account_id) REFERENCES v2_accounts(tenant_id, id),
    FOREIGN KEY (tenant_id, subject_device_id) REFERENCES v2_devices(tenant_id, id),
    FOREIGN KEY (server_instance_id, tenant_id, subject_device_approval_payload_domain,
                 subject_device_approval_replay_id)
        REFERENCES v2_device_approvals (server_instance_id, tenant_id, payload_domain, replay_id),
    -- The previous-root pair exists iff the grant is a rotation, and a
    -- rotation targets previous + 1 under another key; bootstrap is 0.
    -- Every required column is named IS NOT NULL where a NULL would pass.
    CHECK ((grant_variant = 'RotationGrant') = (previous_root_key_id IS NOT NULL)),
    CHECK ((grant_variant = 'RotationGrant') = (previous_root_generation IS NOT NULL)),
    CHECK (grant_variant <> 'RotationGrant' OR (
        root_generation = previous_root_generation + 1
        AND previous_root_key_id <> root_key_id)),
    CHECK (grant_variant <> 'FirstRootSelfGrant' OR (
        root_generation = 0 AND issuer_signing_key_id = subject_signing_key_id)),
    CHECK (subject_signing_key_id <> recipient_hpke_key_id),
    CHECK (issued_at_ms <= not_before_ms AND not_before_ms < not_after_ms)
);

-- One first self-grant per tenant, ever (plan 5.6.4 rule 1).
CREATE UNIQUE INDEX idx_v2_tenant_root_key_grants_one_self_grant
    ON v2_tenant_root_key_grants (tenant_id)
 WHERE grant_variant = 'FirstRootSelfGrant';
CREATE INDEX idx_v2_tenant_root_key_grants_subject
    ON v2_tenant_root_key_grants (tenant_id, subject_device_id, revoked_at);

-- A grant is history: acknowledged once, revoked once, never edited or removed.
CREATE TRIGGER v2_tenant_root_key_grants_no_delete
BEFORE DELETE ON v2_tenant_root_key_grants
BEGIN
    SELECT RAISE(ABORT, 'a root key grant is never deleted');
END;

CREATE TRIGGER v2_tenant_root_key_grants_record_is_fixed
BEFORE UPDATE OF server_instance_id, tenant_id, replay_id, container_domain, container_version,
                 payload_domain, payload_version, grant_variant, root_key_id, root_generation,
                 grant_capability, subject_account_id, subject_device_id, subject_signing_key_id,
                 subject_device_approval_payload_domain, subject_device_approval_replay_id,
                 recipient_hpke_key_id, hpke_suite_id, hpke_mode_id, hpke_kem_id, hpke_kdf_id,
                 hpke_aead_id, hpke_info_bytes, hpke_encapped_key_bytes, hpke_wrapped_trk_bytes,
                 previous_root_key_id, previous_root_generation, issued_at_ms, not_before_ms,
                 not_after_ms, restore_epoch, canonical_payload_bytes, payload_sha256,
                 signature_suite_id, signature_version, issuer_signing_key_id, signature_bytes,
                 signed_container_hash, exact_signed_container_bytes,
                 exact_signed_container_bytes_sha256, created_at
ON v2_tenant_root_key_grants
BEGIN
    SELECT RAISE(ABORT, 'a root key grant record never changes');
END;

-- REPLACE would delete the old row without firing the delete trigger, through
-- the primary key or the one-self-grant index.
CREATE TRIGGER v2_tenant_root_key_grants_no_replace
BEFORE INSERT ON v2_tenant_root_key_grants
WHEN EXISTS (SELECT 1 FROM v2_tenant_root_key_grants g
              WHERE g.tenant_id = NEW.tenant_id
                AND ((g.server_instance_id = NEW.server_instance_id
                      AND g.replay_id = NEW.replay_id)
                  OR (g.grant_variant = 'FirstRootSelfGrant'
                      AND NEW.grant_variant = 'FirstRootSelfGrant')))
BEGIN
    SELECT RAISE(ABORT, 'a root key grant is never replaced');
END;

CREATE TRIGGER v2_tenant_root_key_grants_marks_are_final
BEFORE UPDATE OF acked_at, revoked_at ON v2_tenant_root_key_grants
WHEN (OLD.acked_at IS NOT NULL AND NEW.acked_at IS NOT OLD.acked_at)
  OR (OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at)
BEGIN
    SELECT RAISE(ABORT, 'an acknowledgement or revocation is written once');
END;

-- ------------------------------------------------------------ idempotency ---

-- A stored response is replayed as written, for every kind: 0015 fixed the
-- DEVICE_APPROVE rows, and the mutations that now have writers need the same.
CREATE TRIGGER v2_idempotency_succeeded_is_fixed
BEFORE UPDATE ON v2_idempotency
WHEN OLD.status = 'succeeded'
BEGIN
    SELECT RAISE(ABORT, 'a stored idempotent response never changes');
END;

-- Nor replaced: REPLACE would delete it without firing the update trigger.
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

-- The root create commits with its response, as 0015 holds DEVICE_APPROVE;
-- a CHECK cannot change without a rebuild, so a trigger states it. Each
-- column is compared with IS NOT, which a NULL does not pass.
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
