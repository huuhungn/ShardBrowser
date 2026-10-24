-- Bind root and fleet key generations to the server instance, and reconcile
-- each tenant's active root pointer with its root rows (ADR 0001 Q3).
--
-- Plan 7.2/7.4 key root generations, their grants and fleet generations by
-- `server_instance_id + tenant_id`; until now these rows and references were
-- keyed by tenant alone. Generation rows take the instance from the
-- `v2_server_state` mirror, the only instance a database belongs to; grants
-- already carry theirs, and the new composite foreign keys reject any grant
-- or fleet generation that names another instance's generation.
--
-- 0009 made the pointer nullable without touching values. Here each tenant is
-- reconciled: a matching ACTIVE generation is kept, an empty or PREPARING-only
-- setup becomes NULL, and anything else stops the migration for operator
-- review. Nothing is activated or erased to make the data fit.
--
-- Like 0009 this rebuilds tables, so it needs foreign-key enforcement off
-- (the application runner arranges that) and revalidates every foreign key
-- before committing.

CREATE TEMP TABLE m0011_fk_off (
    ok INTEGER NOT NULL
        CONSTRAINT m0011_requires_foreign_keys_off CHECK (ok = 1)
);
INSERT INTO temp.m0011_fk_off
SELECT foreign_keys = 0 FROM pragma_foreign_keys;

-- Without a mirror row there is no instance to bind existing generations to.
CREATE TEMP TABLE m0011_instance (
    ok INTEGER NOT NULL
        CONSTRAINT m0011_generations_need_server_identity CHECK (ok = 1)
);
INSERT INTO temp.m0011_instance
SELECT EXISTS (SELECT 1 FROM v2_server_state)
    OR NOT (EXISTS (SELECT 1 FROM v2_root_key_generations)
            OR EXISTS (SELECT 1 FROM v2_fleet_key_generations));

-- One row per tenant; any 0 fails the CHECK and rolls the migration back.
CREATE TEMP TABLE m0011_pointer (
    ok INTEGER NOT NULL
        CONSTRAINT m0011_root_pointer_disagrees_with_root_rows CHECK (ok = 1)
);
INSERT INTO temp.m0011_pointer
SELECT CASE
    WHEN EXISTS (SELECT 1 FROM v2_root_key_generations g
                  WHERE g.tenant_id = t.id AND g.state = 'ACTIVE')
        THEN t.active_root_generation IS
             (SELECT g.generation FROM v2_root_key_generations g
               WHERE g.tenant_id = t.id AND g.state = 'ACTIVE')
    -- No ACTIVE row: only an empty or PREPARING-only setup is consistent.
    ELSE NOT EXISTS (SELECT 1 FROM v2_root_key_generations g
                      WHERE g.tenant_id = t.id AND g.state <> 'PREPARING')
END
FROM v2_tenants t;

-- A fleet key must rest on a root that was activated.
CREATE TEMP TABLE m0011_fleet_anchor (
    ok INTEGER NOT NULL
        CONSTRAINT m0011_fleet_generation_needs_an_activated_root CHECK (ok = 1)
);
INSERT INTO temp.m0011_fleet_anchor
SELECT EXISTS (SELECT 1 FROM v2_root_key_generations g
                WHERE g.tenant_id = f.tenant_id
                  AND g.generation = f.root_generation
                  AND g.state IN ('ACTIVE', 'RETIRED'))
FROM v2_fleet_key_generations f;

CREATE TABLE v2_root_key_generations_new (
    server_instance_id BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id     BLOB    NOT NULL REFERENCES v2_tenants(id) ON DELETE CASCADE,
    generation    INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
    root_key_id   BLOB    NOT NULL CHECK (length(root_key_id) = 32),
    state         TEXT    NOT NULL CHECK (state IN ('PREPARING', 'ACTIVE', 'RETIRED')),
    created_at    TEXT    NOT NULL,
    activated_at  TEXT,
    retired_at    TEXT,
    PRIMARY KEY (server_instance_id, tenant_id, generation),
    UNIQUE (server_instance_id, tenant_id, root_key_id),
    -- Target of the grant foreign key: a grant names a generation and the key
    -- it wraps, and both must belong to the same row.
    UNIQUE (server_instance_id, tenant_id, generation, root_key_id)
);
INSERT INTO v2_root_key_generations_new (
    server_instance_id, tenant_id, generation, root_key_id, state,
    created_at, activated_at, retired_at
)
SELECT
    (SELECT server_instance_id FROM v2_server_state WHERE singleton = 1),
    tenant_id, generation, root_key_id, state, created_at, activated_at, retired_at
FROM v2_root_key_generations;
DROP TABLE v2_root_key_generations;
ALTER TABLE v2_root_key_generations_new RENAME TO v2_root_key_generations;

CREATE INDEX idx_v2_root_key_generations_state
    ON v2_root_key_generations (server_instance_id, tenant_id, state);
-- Kept per tenant, stricter than per instance: the pointer it must agree with
-- lives on the tenant row.
CREATE UNIQUE INDEX idx_v2_root_key_generations_one_active
    ON v2_root_key_generations (tenant_id)
 WHERE state = 'ACTIVE';

CREATE TABLE v2_tenant_root_key_grants_new (
    tenant_id                        BLOB    NOT NULL REFERENCES v2_tenants(id) ON DELETE CASCADE,
    replay_id                        BLOB    NOT NULL CHECK (length(replay_id) = 16),
    payload_domain                   TEXT    NOT NULL,
    grant_variant                    TEXT    NOT NULL CHECK (grant_variant IN ('FirstRootSelfGrant', 'CustodianIssued')),
    root_key_id                      BLOB    NOT NULL CHECK (length(root_key_id) = 32),
    root_generation                  INTEGER NOT NULL CHECK (root_generation BETWEEN 0 AND 9223372036854775807),
    grant_capability                 TEXT    NOT NULL,
    subject_account_id               BLOB    NOT NULL CHECK (length(subject_account_id) = 16),
    subject_device_id                BLOB    NOT NULL CHECK (length(subject_device_id) = 16),
    subject_signing_key_id           BLOB    NOT NULL CHECK (length(subject_signing_key_id) = 32),
    recipient_hpke_key_id            BLOB    NOT NULL CHECK (length(recipient_hpke_key_id) = 32),
    subject_device_approval_replay_id BLOB   NOT NULL CHECK (length(subject_device_approval_replay_id) = 16),
    hpke_suite_id                    INTEGER NOT NULL CHECK (hpke_suite_id BETWEEN 0 AND 9223372036854775807),
    hpke_mode_id                     INTEGER NOT NULL CHECK (hpke_mode_id BETWEEN 0 AND 9223372036854775807),
    hpke_kem_id                      INTEGER NOT NULL CHECK (hpke_kem_id BETWEEN 0 AND 9223372036854775807),
    hpke_kdf_id                      INTEGER NOT NULL CHECK (hpke_kdf_id BETWEEN 0 AND 9223372036854775807),
    hpke_aead_id                     INTEGER NOT NULL CHECK (hpke_aead_id BETWEEN 0 AND 9223372036854775807),
    hpke_info_bytes                  BLOB    NOT NULL,
    hpke_encapped_key_bytes          BLOB    NOT NULL,
    hpke_wrapped_trk_bytes           BLOB    NOT NULL,
    server_instance_id               BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    restore_epoch                    INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    signature_bytes                  BLOB    NOT NULL CHECK (length(signature_bytes) = 64),
    issuer_signing_key_id            BLOB    NOT NULL CHECK (length(issuer_signing_key_id) = 32),
    signed_container_hash            BLOB    NOT NULL CHECK (length(signed_container_hash) = 32),
    exact_signed_container_bytes     BLOB    NOT NULL,
    exact_signed_container_bytes_sha256 BLOB NOT NULL CHECK (length(exact_signed_container_bytes_sha256) = 32),
    revoked_at                       TEXT,
    created_at                       TEXT    NOT NULL,
    PRIMARY KEY (tenant_id, payload_domain, replay_id),
    FOREIGN KEY (tenant_id, subject_device_id) REFERENCES v2_devices(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (server_instance_id, tenant_id, root_generation, root_key_id)
        REFERENCES v2_root_key_generations (server_instance_id, tenant_id, generation, root_key_id)
);
INSERT INTO v2_tenant_root_key_grants_new SELECT * FROM v2_tenant_root_key_grants;
DROP TABLE v2_tenant_root_key_grants;
ALTER TABLE v2_tenant_root_key_grants_new RENAME TO v2_tenant_root_key_grants;

CREATE UNIQUE INDEX idx_v2_tenant_root_key_grants_one_self_grant
    ON v2_tenant_root_key_grants (tenant_id)
 WHERE grant_variant = 'FirstRootSelfGrant';

CREATE TABLE v2_fleet_key_generations_new (
    server_instance_id BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id     BLOB    NOT NULL REFERENCES v2_tenants(id) ON DELETE CASCADE,
    fleet_id      BLOB    NOT NULL,
    generation    INTEGER NOT NULL CHECK (generation BETWEEN 0 AND 9223372036854775807),
    fkek_key_id   BLOB    NOT NULL CHECK (length(fkek_key_id) = 32),
    root_generation INTEGER NOT NULL CHECK (root_generation BETWEEN 0 AND 9223372036854775807),
    state         TEXT    NOT NULL CHECK (state IN ('PREPARING', 'ACTIVE', 'RETIRED')),
    created_at    TEXT    NOT NULL,
    activated_at  TEXT,
    retired_at    TEXT,
    PRIMARY KEY (server_instance_id, tenant_id, fleet_id, generation),
    UNIQUE (tenant_id, fkek_key_id),
    UNIQUE (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id),
    FOREIGN KEY (tenant_id, fleet_id) REFERENCES v2_fleets(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (server_instance_id, tenant_id, root_generation)
        REFERENCES v2_root_key_generations (server_instance_id, tenant_id, generation)
);
INSERT INTO v2_fleet_key_generations_new (
    server_instance_id, tenant_id, fleet_id, generation, fkek_key_id, root_generation,
    state, created_at, activated_at, retired_at
)
SELECT
    (SELECT server_instance_id FROM v2_server_state WHERE singleton = 1),
    tenant_id, fleet_id, generation, fkek_key_id, root_generation,
    state, created_at, activated_at, retired_at
FROM v2_fleet_key_generations;
DROP TABLE v2_fleet_key_generations;
ALTER TABLE v2_fleet_key_generations_new RENAME TO v2_fleet_key_generations;

CREATE INDEX idx_v2_fleet_key_generations_state
    ON v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, state);
CREATE UNIQUE INDEX idx_v2_fleet_key_generations_one_active
    ON v2_fleet_key_generations (tenant_id, fleet_id)
    WHERE state = 'ACTIVE';

CREATE TABLE v2_fleet_key_grants_new (
    tenant_id                        BLOB    NOT NULL REFERENCES v2_tenants(id) ON DELETE CASCADE,
    replay_id                        BLOB    NOT NULL CHECK (length(replay_id) = 16),
    payload_domain                   TEXT    NOT NULL,
    grant_variant                    TEXT    NOT NULL CHECK (grant_variant IN ('FirstFleetSelfGrant', 'DeviceHpkeGrant')),
    fleet_id                         BLOB    NOT NULL,
    fkek_key_id                      BLOB    NOT NULL CHECK (length(fkek_key_id) = 32),
    fleet_generation                       INTEGER NOT NULL CHECK (fleet_generation BETWEEN 0 AND 9223372036854775807),
    grant_capability                 TEXT    NOT NULL,
    subject_account_id               BLOB    CHECK (subject_account_id IS NULL OR length(subject_account_id) = 16),
    subject_device_id                BLOB    CHECK (subject_device_id IS NULL OR length(subject_device_id) = 16),
    subject_signing_key_id           BLOB    CHECK (subject_signing_key_id IS NULL OR length(subject_signing_key_id) = 32),
    recipient_hpke_key_id            BLOB    CHECK (recipient_hpke_key_id IS NULL OR length(recipient_hpke_key_id) = 32),
    hpke_suite_id                    INTEGER CHECK (hpke_suite_id IS NULL OR hpke_suite_id BETWEEN 0 AND 9223372036854775807),
    hpke_info_bytes                  BLOB,
    hpke_encapped_key_bytes          BLOB,
    hpke_wrapped_fkek_bytes          BLOB,
    server_instance_id               BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    restore_epoch                    INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    issued_at_ms                     INTEGER NOT NULL CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
    not_before_ms                    INTEGER NOT NULL CHECK (not_before_ms BETWEEN 0 AND 9223372036854775807),
    not_after_ms                     INTEGER NOT NULL CHECK (not_after_ms BETWEEN 0 AND 9223372036854775807),
    signature_bytes                  BLOB    NOT NULL CHECK (length(signature_bytes) = 64),
    issuer_signing_key_id            BLOB    NOT NULL CHECK (length(issuer_signing_key_id) = 32),
    signed_container_hash            BLOB    NOT NULL CHECK (length(signed_container_hash) = 32),
    exact_signed_container_bytes     BLOB    NOT NULL,
    exact_signed_container_bytes_sha256 BLOB NOT NULL CHECK (length(exact_signed_container_bytes_sha256) = 32),
    revoked_at                       TEXT,
    created_at                       TEXT    NOT NULL,
    PRIMARY KEY (tenant_id, payload_domain, replay_id),
    UNIQUE (tenant_id, fleet_id, fleet_generation, subject_device_id),
    FOREIGN KEY (server_instance_id, tenant_id, fleet_id, fleet_generation, fkek_key_id)
        REFERENCES v2_fleet_key_generations (server_instance_id, tenant_id, fleet_id, generation, fkek_key_id)
);
INSERT INTO v2_fleet_key_grants_new SELECT * FROM v2_fleet_key_grants;
DROP TABLE v2_fleet_key_grants;
ALTER TABLE v2_fleet_key_grants_new RENAME TO v2_fleet_key_grants;

CREATE INDEX idx_v2_fleet_key_grants_device
    ON v2_fleet_key_grants (tenant_id, subject_device_id, revoked_at);
CREATE INDEX idx_v2_fleet_key_grants_generation
    ON v2_fleet_key_grants (server_instance_id, tenant_id, fleet_id, fleet_generation);

UPDATE v2_tenants SET active_root_generation = NULL
 WHERE NOT EXISTS (SELECT 1 FROM v2_root_key_generations g
                    WHERE g.tenant_id = v2_tenants.id AND g.state = 'ACTIVE');

-- Enforcement was off for the rebuild; prove every reference still holds,
-- in these tables and in every other one, before the migration commits.
CREATE TEMP TABLE m0011_foreign_keys (
    ok INTEGER NOT NULL
        CONSTRAINT m0011_foreign_key_violation CHECK (ok = 1)
);
INSERT INTO temp.m0011_foreign_keys
SELECT NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check);

DROP TABLE m0011_fk_off;
DROP TABLE m0011_instance;
DROP TABLE m0011_pointer;
DROP TABLE m0011_fleet_anchor;
DROP TABLE m0011_foreign_keys;
