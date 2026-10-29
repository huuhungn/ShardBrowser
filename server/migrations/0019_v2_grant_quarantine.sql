-- Plan 5.6.1, 5.6.4: a stored grant whose row disagrees with its signed
-- container is quarantined. Every path refuses it from then on, and the
-- record of it is never removed or changed; only an audited operator
-- reconciliation may supersede it, in a transition of its own.
CREATE TABLE v2_grant_quarantine (
    kind               TEXT NOT NULL CHECK (kind IN ('root_grant', 'capability_grant')),
    server_instance_id BLOB NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id          BLOB NOT NULL REFERENCES v2_tenants(id),
    replay_id          BLOB NOT NULL CHECK (length(replay_id) = 16),
    reason             TEXT NOT NULL CHECK (reason IN ('container_mismatch')),
    created_at         TEXT NOT NULL,
    PRIMARY KEY (kind, server_instance_id, tenant_id, replay_id)
);

CREATE TRIGGER v2_grant_quarantine_no_delete
BEFORE DELETE ON v2_grant_quarantine
BEGIN
    SELECT RAISE(ABORT, 'a grant quarantine is never removed');
END;

CREATE TRIGGER v2_grant_quarantine_no_update
BEFORE UPDATE ON v2_grant_quarantine
BEGIN
    SELECT RAISE(ABORT, 'a grant quarantine never changes');
END;

-- REPLACE would delete the old row without firing the delete trigger.
CREATE TRIGGER v2_grant_quarantine_no_replace
BEFORE INSERT ON v2_grant_quarantine
WHEN EXISTS (SELECT 1 FROM v2_grant_quarantine q
              WHERE q.kind = NEW.kind AND q.server_instance_id = NEW.server_instance_id
                AND q.tenant_id = NEW.tenant_id AND q.replay_id = NEW.replay_id)
BEGIN
    SELECT RAISE(ABORT, 'a grant is quarantined once');
END;
