-- Plan L507: a fleet key grant whose row disagrees with its signed container
-- is quarantined like a root or capability grant. The kinds are a CHECK, so
-- the table is rebuilt with its rows and triggers; foreign keys are off while
-- migrations run.
CREATE TABLE v2_grant_quarantine_new (
    kind               TEXT NOT NULL CHECK (kind IN (
        'root_grant', 'capability_grant', 'fleet_device_hpke_grant',
        'fleet_recovery_grant', 'fleet_rotation_grant')),
    server_instance_id BLOB NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id          BLOB NOT NULL REFERENCES v2_tenants(id),
    replay_id          BLOB NOT NULL CHECK (length(replay_id) = 16),
    reason             TEXT NOT NULL CHECK (reason IN ('container_mismatch')),
    created_at         TEXT NOT NULL,
    PRIMARY KEY (kind, server_instance_id, tenant_id, replay_id)
);
INSERT INTO v2_grant_quarantine_new SELECT * FROM v2_grant_quarantine;
DROP TABLE v2_grant_quarantine;
ALTER TABLE v2_grant_quarantine_new RENAME TO v2_grant_quarantine;

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
