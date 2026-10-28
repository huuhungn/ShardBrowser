-- G2: the startup upload reconciler (plan 8.1 L1180-L1216).
--
-- L1203-L1205: a READY upload can quarantine. A COMMITTED one keeps its
-- state, which 0026 binds to its exact receipt, and is quarantined by its row
-- here alone (L1209-L1211). Every reconciler quarantine records its reason
-- code (L1216) and whether it is a security incident. No row is ever removed
-- or changed: quarantined evidence is kept (L1185, L1214).

DROP TRIGGER v2_uploads_state_moves_forward;

CREATE TRIGGER v2_uploads_state_moves_forward
BEFORE UPDATE OF state ON v2_uploads
WHEN NEW.state IS NOT OLD.state
 AND OLD.state || '>' || NEW.state NOT IN (
     'OPEN>FINALIZING', 'FINALIZING>READY', 'READY>COMMITTED',
     'OPEN>QUARANTINED', 'FINALIZING>QUARANTINED', 'READY>QUARANTINED',
     'OPEN>ABORTED', 'FINALIZING>ABORTED', 'READY>ABORTED')
BEGIN
    SELECT RAISE(ABORT, 'an upload state moves forward only');
END;

CREATE TABLE v2_upload_quarantine (
    server_instance_id BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id          BLOB    NOT NULL CHECK (length(tenant_id) = 16),
    upload_id          BLOB    NOT NULL CHECK (length(upload_id) = 16),
    from_state         TEXT    NOT NULL
        CHECK (from_state IN ('OPEN', 'FINALIZING', 'READY', 'COMMITTED')),
    reason             TEXT    NOT NULL CHECK (length(reason) BETWEEN 1 AND 64),
    security_incident  INTEGER NOT NULL CHECK (security_incident IN (0, 1)),
    created_at_ms      INTEGER NOT NULL CHECK (created_at_ms BETWEEN 0 AND 9223372036854775807),
    PRIMARY KEY (server_instance_id, tenant_id, upload_id)
);

CREATE TRIGGER v2_upload_quarantine_no_delete
BEFORE DELETE ON v2_upload_quarantine
BEGIN
    SELECT RAISE(ABORT, 'an upload quarantine is never removed');
END;

CREATE TRIGGER v2_upload_quarantine_no_update
BEFORE UPDATE ON v2_upload_quarantine
BEGIN
    SELECT RAISE(ABORT, 'an upload quarantine never changes');
END;
