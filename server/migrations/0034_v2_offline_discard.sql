-- ADR 0002 Q-60: the offline `fleet|root discard-preparing` command archives
-- a stuck PREPARING generation and its grants, then deletes them, so the
-- number can be created again. Generations and grants stay append-only for
-- everything else: a delete is allowed only while the command's marker row
-- for that tenant, kind and generation exists, and only the command writes
-- one (inside its transaction, removed before it commits). A generation that
-- is not PREPARING is never deleted, marker or not.

CREATE TABLE v2_offline_discard (
    tenant_id  BLOB    NOT NULL CHECK (length(tenant_id) = 16),
    kind       TEXT    NOT NULL CHECK (kind IN ('fleet', 'root')),
    generation INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
    PRIMARY KEY (tenant_id, kind, generation)
);

-- What a discard removed, each row as JSON (blobs as hex), kept forever.
CREATE TABLE v2_discarded_records (
    id           INTEGER PRIMARY KEY,
    tenant_id    BLOB    NOT NULL CHECK (length(tenant_id) = 16),
    kind         TEXT    NOT NULL CHECK (kind IN ('fleet', 'root')),
    generation   INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
    source_table TEXT    NOT NULL,
    row_json     TEXT    NOT NULL,
    discarded_at TEXT    NOT NULL
);

CREATE TRIGGER v2_discarded_records_no_delete
BEFORE DELETE ON v2_discarded_records
BEGIN
    SELECT RAISE(ABORT, 'a discarded record is never removed');
END;

CREATE TRIGGER v2_discarded_records_no_update
BEFORE UPDATE ON v2_discarded_records
BEGIN
    SELECT RAISE(ABORT, 'a discarded record never changes');
END;

-- ------------------------------------------------------------ generations ---

DROP TRIGGER v2_fleet_key_generations_no_delete;
CREATE TRIGGER v2_fleet_key_generations_no_delete
BEFORE DELETE ON v2_fleet_key_generations
WHEN NOT EXISTS (SELECT 1 FROM v2_offline_discard m
                  WHERE m.tenant_id = OLD.tenant_id AND m.kind = 'fleet'
                    AND m.generation = OLD.generation)
BEGIN
    SELECT RAISE(ABORT, 'a fleet key generation is never deleted');
END;

CREATE TRIGGER v2_fleet_key_generations_only_preparing_is_discarded
BEFORE DELETE ON v2_fleet_key_generations
WHEN OLD.state <> 'PREPARING'
BEGIN
    SELECT RAISE(ABORT, 'only a PREPARING fleet key generation is discarded');
END;

CREATE TRIGGER v2_root_key_generations_no_delete
BEFORE DELETE ON v2_root_key_generations
WHEN NOT EXISTS (SELECT 1 FROM v2_offline_discard m
                  WHERE m.tenant_id = OLD.tenant_id AND m.kind = 'root'
                    AND m.generation = OLD.generation)
BEGIN
    SELECT RAISE(ABORT, 'a root key generation is never deleted');
END;

CREATE TRIGGER v2_root_key_generations_only_preparing_is_discarded
BEFORE DELETE ON v2_root_key_generations
WHEN OLD.state <> 'PREPARING'
BEGIN
    SELECT RAISE(ABORT, 'only a PREPARING root key generation is discarded');
END;

-- ----------------------------------------------------------------- grants ---

DROP TRIGGER v2_tenant_root_key_grants_no_delete;
CREATE TRIGGER v2_tenant_root_key_grants_no_delete
BEFORE DELETE ON v2_tenant_root_key_grants
WHEN NOT EXISTS (SELECT 1 FROM v2_offline_discard m
                  WHERE m.tenant_id = OLD.tenant_id AND m.kind = 'root'
                    AND m.generation = OLD.root_generation)
BEGIN
    SELECT RAISE(ABORT, 'a root key grant is never deleted');
END;

DROP TRIGGER v2_fleet_device_hpke_grants_no_delete;
CREATE TRIGGER v2_fleet_device_hpke_grants_no_delete
BEFORE DELETE ON v2_fleet_device_hpke_grants
WHEN NOT EXISTS (SELECT 1 FROM v2_offline_discard m
                  WHERE m.tenant_id = OLD.tenant_id AND m.kind = 'fleet'
                    AND m.generation = OLD.generation)
BEGIN
    SELECT RAISE(ABORT, 'a fleet device grant is never deleted');
END;

-- A recovery grant goes with its fleet generation, or with the root
-- generation it is wrapped under.
DROP TRIGGER v2_fleet_recovery_grants_no_delete;
CREATE TRIGGER v2_fleet_recovery_grants_no_delete
BEFORE DELETE ON v2_fleet_recovery_grants
WHEN NOT EXISTS (SELECT 1 FROM v2_offline_discard m
                  WHERE m.tenant_id = OLD.tenant_id
                    AND ((m.kind = 'fleet' AND m.generation = OLD.generation)
                      OR (m.kind = 'root' AND m.generation = OLD.recipient_root_generation)))
BEGIN
    SELECT RAISE(ABORT, 'a fleet recovery grant is never deleted');
END;

DROP TRIGGER v2_fleet_rotation_grants_no_delete;
CREATE TRIGGER v2_fleet_rotation_grants_no_delete
BEFORE DELETE ON v2_fleet_rotation_grants
WHEN NOT EXISTS (SELECT 1 FROM v2_offline_discard m
                  WHERE m.tenant_id = OLD.tenant_id AND m.kind = 'fleet'
                    AND m.generation = OLD.generation)
BEGIN
    SELECT RAISE(ABORT, 'a fleet rotation grant is never deleted');
END;

-- A quarantine mark of a discarded grant goes with it, deleted while its
-- grant row still names the marker's generation.
DROP TRIGGER v2_grant_quarantine_no_delete;
CREATE TRIGGER v2_grant_quarantine_no_delete
BEFORE DELETE ON v2_grant_quarantine
WHEN NOT EXISTS (SELECT 1 FROM v2_offline_discard m
                  WHERE m.tenant_id = OLD.tenant_id AND (
    (m.kind = 'fleet' AND OLD.kind = 'fleet_device_hpke_grant' AND EXISTS (
        SELECT 1 FROM v2_fleet_device_hpke_grants g
         WHERE g.server_instance_id = OLD.server_instance_id AND g.tenant_id = OLD.tenant_id
           AND g.replay_id = OLD.replay_id AND g.generation = m.generation))
 OR (m.kind = 'fleet' AND OLD.kind = 'fleet_recovery_grant' AND EXISTS (
        SELECT 1 FROM v2_fleet_recovery_grants g
         WHERE g.server_instance_id = OLD.server_instance_id AND g.tenant_id = OLD.tenant_id
           AND g.replay_id = OLD.replay_id AND g.generation = m.generation))
 OR (m.kind = 'fleet' AND OLD.kind = 'fleet_rotation_grant' AND EXISTS (
        SELECT 1 FROM v2_fleet_rotation_grants g
         WHERE g.server_instance_id = OLD.server_instance_id AND g.tenant_id = OLD.tenant_id
           AND g.replay_id = OLD.replay_id AND g.generation = m.generation))
 OR (m.kind = 'root' AND OLD.kind = 'fleet_recovery_grant' AND EXISTS (
        SELECT 1 FROM v2_fleet_recovery_grants g
         WHERE g.server_instance_id = OLD.server_instance_id AND g.tenant_id = OLD.tenant_id
           AND g.replay_id = OLD.replay_id AND g.recipient_root_generation = m.generation))
 OR (m.kind = 'root' AND OLD.kind = 'root_grant' AND EXISTS (
        SELECT 1 FROM v2_tenant_root_key_grants g
         WHERE g.server_instance_id = OLD.server_instance_id AND g.tenant_id = OLD.tenant_id
           AND g.replay_id = OLD.replay_id AND g.root_generation = m.generation))))
BEGIN
    SELECT RAISE(ABORT, 'a grant quarantine is never removed');
END;
