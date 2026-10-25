-- ADR 0001 R3: `v2_idempotency` is the one durable request/response ledger,
-- and the only authority for replaying a device approval's response. Plan
-- 7.3 columns, plus the four R3 columns a `DEVICE_APPROVE` row must carry and
-- every other kind must leave NULL. The other operation kinds get writers in
-- W3; until then only `DEVICE_APPROVE` rows exist.

CREATE TABLE v2_idempotency (
    server_instance_id          BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id                   BLOB    NOT NULL REFERENCES v2_tenants(id),
    actor_device_id             BLOB    NOT NULL CHECK (length(actor_device_id) = 16),
    operation_scope             TEXT    NOT NULL CHECK (length(operation_scope) BETWEEN 1 AND 128),
    idempotency_key             BLOB    NOT NULL CHECK (length(idempotency_key) = 16),
    operation_kind              TEXT    NOT NULL CHECK (operation_kind IN (
        'PROFILE_PUBLISH_CREATE', 'PROFILE_CHECKOUT', 'CREATE_UPLOAD', 'FINALIZE_UPLOAD',
        'RELEASE_LEASE', 'LOCAL_UNBIND', 'ROOT_GENERATION_CREATE', 'ROOT_GRANT_CREATE',
        'ROOT_GRANT_ACK', 'ROOT_GENERATION_ACTIVATE', 'ROOT_GRANT_REVOKE',
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

-- At most one actor/operation row per approval replay ID.
CREATE UNIQUE INDEX v2_idempotency_one_row_per_approval
    ON v2_idempotency (tenant_id, approval_payload_domain, idempotency_key)
 WHERE operation_kind = 'DEVICE_APPROVE';

-- The stored response is replayed as written, never regenerated.
CREATE TRIGGER v2_idempotency_device_approve_is_fixed
BEFORE UPDATE ON v2_idempotency
WHEN OLD.operation_kind = 'DEVICE_APPROVE'
BEGIN
    SELECT RAISE(ABORT, 'a device-approval idempotency row never changes');
END;

-- An approval is history: it can be revoked, never edited or removed.
CREATE TRIGGER v2_device_approvals_no_delete
BEFORE DELETE ON v2_device_approvals
BEGIN
    SELECT RAISE(ABORT, 'a device approval is never deleted');
END;

CREATE TRIGGER v2_device_approvals_record_is_fixed
BEFORE UPDATE OF tenant_id, replay_id, payload_domain, payload_version, subject_account_id,
                 subject_device_id, subject_signing_key_id, subject_hpke_key_id,
                 approval_scope_kind, approval_scope_id, approved_use, issued_at_ms,
                 not_before_ms, not_after_ms, server_instance_id, restore_epoch,
                 canonical_payload_bytes, payload_sha256, signature_suite_id, signature_version,
                 signature_bytes, issuer_signing_key_id, signed_container_hash,
                 exact_signed_container_bytes, exact_signed_container_bytes_sha256, created_at
ON v2_device_approvals
BEGIN
    SELECT RAISE(ABORT, 'a device approval record never changes');
END;

CREATE TRIGGER v2_device_approvals_revocation_is_final
BEFORE UPDATE OF revoked_at ON v2_device_approvals
WHEN OLD.revoked_at IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'a revoked device approval stays revoked');
END;

-- D1 promotes the approving session from pending_setup to root_setup; no
-- other class change exists yet, and none goes back.
CREATE TRIGGER v2_sessions_class_moves_forward
BEFORE UPDATE OF class ON v2_sessions
WHEN NOT (OLD.class = NEW.class OR (OLD.class = 'pending_setup' AND NEW.class = 'root_setup'))
BEGIN
    SELECT RAISE(ABORT, 'a v2 session class only moves from pending_setup to root_setup');
END;
