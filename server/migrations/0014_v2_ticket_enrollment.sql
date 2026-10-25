-- Enrollment runs on the pre-device ticket (ADR 0001 R2).
--
-- A challenge is now the exact `EnrollmentBindingV2` bytes the server issued
-- to one ticket: instance, epoch, tenant, account, ticket, nonce, both suites,
-- both keys and their IDs, and the expiry. The candidate signs those bytes, so
-- the row needs no nonce hash or key commitment of its own. Old challenges
-- live 120 seconds and bind nothing the new proof covers, so they are dropped;
-- a client caught mid-enrollment asks for a new one.

DROP TABLE v2_enrollment_challenges;

CREATE TABLE v2_enrollment_challenges (
    id                    BLOB    PRIMARY KEY CHECK (length(id) = 16),
    pre_device_session_id BLOB    NOT NULL REFERENCES v2_pre_device_sessions(id) ON DELETE CASCADE,
    tenant_id             BLOB    NOT NULL,
    account_id            BLOB    NOT NULL,
    binding_bytes         BLOB    NOT NULL CHECK (length(binding_bytes) BETWEEN 1 AND 4096),
    created_at_ms         INTEGER NOT NULL CHECK (created_at_ms BETWEEN 0 AND 9223372036854775807),
    expires_at_ms         INTEGER NOT NULL CHECK (expires_at_ms BETWEEN 0 AND 9223372036854775807),
    consumed_at_ms        INTEGER CHECK (consumed_at_ms BETWEEN 0 AND 9223372036854775807),
    revoked_at_ms         INTEGER CHECK (revoked_at_ms BETWEEN 0 AND 9223372036854775807),
    FOREIGN KEY (tenant_id, account_id) REFERENCES v2_accounts(tenant_id, id) ON DELETE CASCADE,
    CHECK (created_at_ms < expires_at_ms AND expires_at_ms - created_at_ms <= 120000),
    CHECK (consumed_at_ms IS NULL OR revoked_at_ms IS NULL)
);
CREATE INDEX v2_enrollment_challenges_by_ticket
    ON v2_enrollment_challenges (pre_device_session_id);

CREATE TRIGGER v2_enrollment_challenges_settled_is_final
BEFORE UPDATE ON v2_enrollment_challenges
WHEN OLD.consumed_at_ms IS NOT NULL OR OLD.revoked_at_ms IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'a settled enrollment challenge never changes');
END;

CREATE TRIGGER v2_enrollment_challenges_binding_is_fixed
BEFORE UPDATE OF id, pre_device_session_id, tenant_id, account_id, binding_bytes,
                 created_at_ms, expires_at_ms
ON v2_enrollment_challenges
BEGIN
    SELECT RAISE(ABORT, 'an enrollment challenge binding never changes');
END;
