-- Allow an uninitialised tenant to have no active root generation.
--
-- This is a schema-only rebuild. The application runner disables foreign-key
-- enforcement on the migration connection before SQLx opens its transaction;
-- the guard below fails closed if this file is run through a normal FK-on path.

CREATE TEMP TABLE m0009_fk_off (
    ok INTEGER NOT NULL
        CONSTRAINT m0009_requires_foreign_keys_off CHECK (ok = 1)
);
INSERT INTO temp.m0009_fk_off
SELECT foreign_keys = 0 FROM pragma_foreign_keys;

CREATE TABLE v2_tenants_new (
    id                     BLOB PRIMARY KEY CHECK (length(id) = 16),
    slug                   TEXT NOT NULL UNIQUE,
    status                 TEXT NOT NULL CHECK (status IN ('active', 'suspended')),
    active_root_generation INTEGER CHECK (active_root_generation BETWEEN 0 AND 9223372036854775807),
    created_at             TEXT NOT NULL
);

INSERT INTO v2_tenants_new (
    id, slug, status, active_root_generation, created_at
)
SELECT
    id, slug, status, active_root_generation, created_at
FROM v2_tenants;

DROP TABLE v2_tenants;
ALTER TABLE v2_tenants_new RENAME TO v2_tenants;

DROP TABLE m0009_fk_off;
