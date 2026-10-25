-- Plan 7.2 and ADR 0002 D-2: the exact `TenantCapabilityGrantV2` table. Its
-- first writer is `POST /v2/capability-grants`, filed by an ACTIVE root
-- custodian (ADR 0001 D2).
--
-- Rows of the earlier spike shape (no subject kind, a device on every row, no
-- signature metadata) cannot be restated in the exact table, so they stay as
-- they are under `v2_legacy_capability_grants`: read-only, never used to
-- authorize anything, and still history for every "has this tenant ever"
-- check.

ALTER TABLE v2_capability_grants RENAME TO v2_legacy_capability_grants;

CREATE TRIGGER v2_legacy_capability_grants_no_insert
BEFORE INSERT ON v2_legacy_capability_grants
BEGIN
    SELECT RAISE(ABORT, 'legacy capability grants are read-only');
END;

CREATE TRIGGER v2_legacy_capability_grants_no_update
BEFORE UPDATE ON v2_legacy_capability_grants
BEGIN
    SELECT RAISE(ABORT, 'legacy capability grants are read-only');
END;

-- Deleting a tenant may still remove them through the cascade.

CREATE TABLE v2_capability_grants (
    server_instance_id               BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id                        BLOB    NOT NULL REFERENCES v2_tenants(id),
    replay_id                        BLOB    NOT NULL CHECK (length(replay_id) = 16),
    payload_domain                   TEXT    NOT NULL
        CHECK (payload_domain = 'shardx.auth.tenant-capability-grant.v2'),
    payload_version                  INTEGER NOT NULL CHECK (payload_version = 2),
    subject_kind                     TEXT    NOT NULL CHECK (subject_kind IN ('account', 'device')),
    subject_account_id               BLOB    NOT NULL CHECK (length(subject_account_id) = 16),
    subject_device_id                BLOB    CHECK (length(subject_device_id) = 16),
    subject_signing_key_id           BLOB    CHECK (length(subject_signing_key_id) = 32),
    subject_hpke_key_id              BLOB    CHECK (length(subject_hpke_key_id) = 32),
    scope_kind                       TEXT    NOT NULL CHECK (scope_kind IN ('tenant', 'fleet', 'profile')),
    scope_id                         BLOB    NOT NULL CHECK (length(scope_id) = 16),
    -- The D-2 values a capability grant may carry, with their scope kinds;
    -- `root.custody` comes only from root grants (Q-2).
    capability                       TEXT    NOT NULL CHECK (
        (capability IN ('tenant.manage', 'membership.manage', 'recovery.manage')
            AND scope_kind = 'tenant')
        OR (capability IN ('fleet.manage', 'device.approve', 'device.revoke', 'key.rotate',
                           'profile.publish')
            AND scope_kind IN ('tenant', 'fleet'))
        OR (capability IN ('lease.force_expire', 'profile.checkout', 'profile.commit'))),
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
    revoked_at                       TEXT,
    created_at                       TEXT    NOT NULL,
    -- Plan 5.6.1: the replay scope is (tenant, payload domain, replay ID).
    PRIMARY KEY (tenant_id, payload_domain, replay_id),
    FOREIGN KEY (tenant_id, subject_account_id) REFERENCES v2_accounts(tenant_id, id),
    FOREIGN KEY (tenant_id, subject_device_id) REFERENCES v2_devices(tenant_id, id),
    -- Device fields are all present iff the subject is a device, and a device
    -- signs and receives under different keys.
    CHECK ((subject_kind = 'device') = (subject_device_id IS NOT NULL)),
    CHECK ((subject_kind = 'device') = (subject_signing_key_id IS NOT NULL)),
    CHECK ((subject_kind = 'device') = (subject_hpke_key_id IS NOT NULL)),
    CHECK (subject_signing_key_id IS NOT subject_hpke_key_id OR subject_kind = 'account'),
    CHECK (scope_kind <> 'tenant' OR scope_id = tenant_id),
    CHECK (issued_at_ms <= not_before_ms AND not_before_ms < not_after_ms),
    -- ADR 0002 D-6: a capability grant lives at most 365 days.
    CHECK (not_after_ms - not_before_ms <= 31536000000)
);

CREATE INDEX idx_v2_capability_grants_subject
    ON v2_capability_grants (tenant_id, subject_account_id, subject_device_id, revoked_at);

-- A grant is history: revoked once, never edited or removed.
CREATE TRIGGER v2_capability_grants_no_delete
BEFORE DELETE ON v2_capability_grants
BEGIN
    SELECT RAISE(ABORT, 'a capability grant is never deleted');
END;

CREATE TRIGGER v2_capability_grants_record_is_fixed
BEFORE UPDATE OF server_instance_id, tenant_id, replay_id, payload_domain, payload_version,
                 subject_kind, subject_account_id, subject_device_id, subject_signing_key_id,
                 subject_hpke_key_id, scope_kind, scope_id, capability, issued_at_ms,
                 not_before_ms, not_after_ms, restore_epoch, canonical_payload_bytes,
                 payload_sha256, signature_suite_id, signature_version, signature_bytes,
                 issuer_signing_key_id, signed_container_hash, exact_signed_container_bytes,
                 exact_signed_container_bytes_sha256, created_at
ON v2_capability_grants
BEGIN
    SELECT RAISE(ABORT, 'a capability grant record never changes');
END;

CREATE TRIGGER v2_capability_grants_revocation_is_final
BEFORE UPDATE OF revoked_at ON v2_capability_grants
WHEN OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at
BEGIN
    SELECT RAISE(ABORT, 'a revocation is written once');
END;

-- REPLACE would delete the old row without firing the delete trigger; and a
-- replay ID a legacy row holds is spent too.
CREATE TRIGGER v2_capability_grants_no_replace
BEFORE INSERT ON v2_capability_grants
WHEN EXISTS (SELECT 1 FROM v2_capability_grants g
              WHERE g.tenant_id = NEW.tenant_id AND g.payload_domain = NEW.payload_domain
                AND g.replay_id = NEW.replay_id)
  OR EXISTS (SELECT 1 FROM v2_legacy_capability_grants g
              WHERE g.tenant_id = NEW.tenant_id AND g.payload_domain = NEW.payload_domain
                AND g.replay_id = NEW.replay_id)
BEGIN
    SELECT RAISE(ABORT, 'a capability grant replay ID is never reused');
END;
