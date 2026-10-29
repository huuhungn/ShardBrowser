-- ADR 0002 D-1, replays after a restore (L377-L389): the merge keeps every
-- ledger row and marks the commit, upload and publish rows whose result the
-- restore rolled back with the epoch it moves to. The mark is set once, from
-- NULL, to the next epoch, and is the only change a stored response takes.
ALTER TABLE v2_idempotency ADD COLUMN superseded_by_restore_epoch INTEGER
    CHECK (superseded_by_restore_epoch BETWEEN 1 AND 9223372036854775807);

-- 0020's trigger refused every update of a stored response; it now names
-- every column but the mark.
DROP TRIGGER v2_idempotency_succeeded_is_fixed;
CREATE TRIGGER v2_idempotency_succeeded_is_fixed
BEFORE UPDATE OF server_instance_id, tenant_id, actor_device_id, operation_scope,
    idempotency_key, operation_kind, canonical_request_hash, exact_request_bytes,
    exact_request_bytes_sha256, status, response_record_type, exact_response_bytes,
    exact_response_bytes_sha256, retained_until, approval_payload_domain, restore_epoch,
    actor_account_id, subject_device_id
ON v2_idempotency
WHEN OLD.status = 'succeeded'
BEGIN
    SELECT RAISE(ABORT, 'a stored idempotent response never changes');
END;

CREATE TRIGGER v2_idempotency_superseded_once
BEFORE UPDATE OF superseded_by_restore_epoch ON v2_idempotency
WHEN OLD.superseded_by_restore_epoch IS NOT NULL
  OR NEW.superseded_by_restore_epoch IS NOT (SELECT restore_epoch + 1 FROM v2_server_state)
  OR OLD.operation_kind NOT IN ('COMMIT', 'CREATE_UPLOAD', 'FINALIZE_UPLOAD',
                                'PROFILE_PUBLISH_CREATE')
BEGIN
    SELECT RAISE(ABORT, 'a ledger row is superseded once, by the next restore epoch');
END;
