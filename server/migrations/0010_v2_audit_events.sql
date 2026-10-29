-- Structured v2 audit trail (plan 7.3, L1091).
--
-- Unlike the v1 `audit_log`, a row here is written inside the mutation's own
-- transaction, so a failed audit insert rolls the mutation back instead of
-- being swallowed.
--
-- Actor columns are NULL only for offline operator CLI actions (ADR 0001 D3):
-- no account or device exists for the operator, and no synthetic one is made.
-- The CHECK ties NULL actors to that reason code, so a network action cannot
-- record an anonymous actor and an offline one cannot claim an account.
--
-- `tenant_id` deliberately does not cascade: deleting a tenant must not erase
-- the record of what was done to it.

CREATE TABLE v2_audit_events (
    tenant_id        BLOB NOT NULL REFERENCES v2_tenants(id),
    id               BLOB NOT NULL CHECK (length(id) = 16),
    actor_account_id BLOB CHECK (actor_account_id IS NULL OR length(actor_account_id) = 16),
    actor_device_id  BLOB CHECK (actor_device_id IS NULL OR length(actor_device_id) = 16),
    action           TEXT NOT NULL,
    target_type      TEXT NOT NULL,
    target_id        BLOB NOT NULL,
    outcome          TEXT NOT NULL,
    reason_code      TEXT,
    request_id       BLOB NOT NULL CHECK (length(request_id) = 16),
    created_at       TEXT NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT v2_audit_events_offline_actor CHECK (
        (actor_account_id IS NULL) = (reason_code IS 'offline_operator_cli')
        AND (actor_device_id IS NULL) = (reason_code IS 'offline_operator_cli')
    )
);
