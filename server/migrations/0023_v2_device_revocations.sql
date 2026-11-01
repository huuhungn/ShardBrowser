-- ADR 0002 Q-13: signed device revocations.
--
-- A `DeviceRevocationV2` is filed through DEVICE_REVOKE and is permanent:
-- never edited, removed or replaced. One device may hold several, so a
-- current custodian can re-file one when every earlier issuer has lost
-- custody. A device that has one stays revoked.

CREATE TABLE v2_device_revocations (
    server_instance_id                  BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id                           BLOB    NOT NULL REFERENCES v2_tenants(id)
        CHECK (length(tenant_id) = 16),
    replay_id                           BLOB    NOT NULL CHECK (length(replay_id) = 16),
    payload_domain                      TEXT    NOT NULL
        CHECK (payload_domain = 'shardx.authz.device-revocation.v2'),
    payload_version                     INTEGER NOT NULL CHECK (payload_version = 2),
    subject_account_id                  BLOB    NOT NULL CHECK (length(subject_account_id) = 16),
    subject_device_id                   BLOB    NOT NULL CHECK (length(subject_device_id) = 16),
    subject_signing_key_id              BLOB    NOT NULL CHECK (length(subject_signing_key_id) = 32),
    subject_hpke_key_id                 BLOB    NOT NULL CHECK (length(subject_hpke_key_id) = 32),
    reason_code                         TEXT    NOT NULL
        CHECK (reason_code IN ('lost', 'compromised', 'retired', 'rekeyed')),
    issuer_signing_key_id               BLOB    NOT NULL CHECK (length(issuer_signing_key_id) = 32),
    issued_at_ms                        INTEGER NOT NULL
        CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
    not_before_ms                       INTEGER NOT NULL
        CHECK (not_before_ms BETWEEN 0 AND 9223372036854775807),
    not_after_ms                        INTEGER NOT NULL
        CHECK (not_after_ms BETWEEN 0 AND 9223372036854775807),
    restore_epoch                       INTEGER NOT NULL
        CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    canonical_payload_bytes             BLOB    NOT NULL,
    payload_sha256                      BLOB    NOT NULL CHECK (length(payload_sha256) = 32),
    signature_suite_id                  INTEGER NOT NULL CHECK (signature_suite_id = 1),
    signature_version                   INTEGER NOT NULL CHECK (signature_version = 1),
    signature_bytes                     BLOB    NOT NULL CHECK (length(signature_bytes) = 64),
    signed_container_hash               BLOB    NOT NULL CHECK (length(signed_container_hash) = 32),
    exact_signed_container_bytes        BLOB    NOT NULL
        CHECK (length(exact_signed_container_bytes) BETWEEN 1 AND 131072),
    exact_signed_container_bytes_sha256 BLOB    NOT NULL
        CHECK (length(exact_signed_container_bytes_sha256) = 32),
    filed_at_ms                         INTEGER NOT NULL
        CHECK (filed_at_ms BETWEEN 0 AND 9223372036854775807),
    PRIMARY KEY (server_instance_id, tenant_id, replay_id),
    CHECK (issued_at_ms <= not_before_ms AND not_before_ms < not_after_ms),
    -- D-6: the 30-day window is checked at filing only, so it bounds the
    -- record, and the server's clock is inside it when the row is written.
    CHECK (not_after_ms - not_before_ms <= 2592000000),
    CHECK (not_before_ms <= filed_at_ms AND filed_at_ms < not_after_ms)
);

CREATE INDEX v2_device_revocations_by_subject
    ON v2_device_revocations (server_instance_id, tenant_id, subject_device_id);

CREATE TRIGGER v2_device_revocations_no_delete
BEFORE DELETE ON v2_device_revocations
BEGIN
    SELECT RAISE(ABORT, 'a device revocation is never deleted');
END;

CREATE TRIGGER v2_device_revocations_no_update
BEFORE UPDATE ON v2_device_revocations
BEGIN
    SELECT RAISE(ABORT, 'a device revocation never changes');
END;

CREATE TRIGGER v2_device_revocations_no_replace
BEFORE INSERT ON v2_device_revocations
WHEN EXISTS (SELECT 1 FROM v2_device_revocations r
              WHERE r.server_instance_id = NEW.server_instance_id
                AND r.tenant_id = NEW.tenant_id AND r.replay_id = NEW.replay_id)
BEGIN
    SELECT RAISE(ABORT, 'a device revocation is never replaced');
END;

-- A revoked device never becomes usable again, whatever its row says.
CREATE TRIGGER v2_devices_revocation_is_final
BEFORE UPDATE OF status ON v2_devices
WHEN NEW.status <> 'revoked'
 AND EXISTS (SELECT 1 FROM v2_device_revocations r
              WHERE r.tenant_id = OLD.tenant_id AND r.subject_device_id = OLD.id)
BEGIN
    SELECT RAISE(ABORT, 'a device with a revocation stays revoked');
END;

-- REPLACE, or a row removed with its account, would otherwise bring the
-- revoked keys back as a fresh device.
CREATE TRIGGER v2_devices_revocation_no_reinsert
BEFORE INSERT ON v2_devices
WHEN NEW.status <> 'revoked'
 AND EXISTS (SELECT 1 FROM v2_device_revocations r
              WHERE r.tenant_id = NEW.tenant_id
                AND (r.subject_device_id = NEW.id
                     OR r.subject_signing_key_id = NEW.signing_key_id))
BEGIN
    SELECT RAISE(ABORT, 'a device with a revocation stays revoked');
END;

CREATE TRIGGER v2_idempotency_device_revoke_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'DEVICE_REVOKE' OR NEW.operation_scope = 'device.revoke.v2')
 AND (NEW.operation_kind IS NOT 'DEVICE_REVOKE'
      OR NEW.operation_scope IS NOT 'device.revoke.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'DeviceRevokedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a device revocation is stored with its response');
END;
