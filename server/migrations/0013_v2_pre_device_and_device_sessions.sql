-- Account login, pre-device tickets and proof-bound device sessions
-- (ADR 0001 R2).
--
-- `/v2/auth/login` issues an account-only ticket: a row in
-- `v2_pre_device_sessions`, never in `v2_sessions`. A ticket becomes a session
-- for one device only through a device-session challenge, which the device
-- answers by decrypting a secret sealed to its HPKE key and signing it with
-- its Ed25519 key. Only token and secret hashes are stored.
--
-- `v2_sessions` is rebuilt with the binding R2 requires: instance, epoch,
-- account, device, both key IDs, account token version, class, both token
-- hashes and the three expiries. No code ever issued a row of the old shape,
-- so the rebuild refuses a live row instead of guessing a class for it, and
-- drops revoked ones: they carry no token a client could present. A dev or
-- test database that stops here has rows a test seeded by hand; set their
-- `revoked_at` (or delete them) and start the server again.

CREATE TEMP TABLE m0013_fk_off (
    ok INTEGER NOT NULL
        CONSTRAINT m0013_requires_foreign_keys_off CHECK (ok = 1)
);
INSERT INTO temp.m0013_fk_off
SELECT foreign_keys = 0 FROM pragma_foreign_keys;

CREATE TEMP TABLE m0013_no_live_sessions (
    ok INTEGER NOT NULL
        CONSTRAINT m0013_live_v2_session_found CHECK (ok = 1)
);
INSERT INTO temp.m0013_no_live_sessions
SELECT NOT EXISTS (SELECT 1 FROM v2_sessions WHERE revoked_at IS NULL);

-- ------------------------------------------------------ pre-device tickets ---

-- Ten minutes, never refreshed. Consumed by the device-session proof that
-- promotes it, revoked by logout.
CREATE TABLE v2_pre_device_sessions (
    id                    BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
    token_hash            BLOB    NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    server_instance_id    BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    restore_epoch         INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    tenant_id             BLOB    NOT NULL,
    account_id            BLOB    NOT NULL,
    account_token_version INTEGER NOT NULL
        CHECK (account_token_version BETWEEN 0 AND 9223372036854775807),
    created_at_ms         INTEGER NOT NULL CHECK (created_at_ms BETWEEN 0 AND 9223372036854775807),
    expires_at_ms         INTEGER NOT NULL CHECK (expires_at_ms BETWEEN 0 AND 9223372036854775807),
    consumed_at_ms        INTEGER CHECK (consumed_at_ms BETWEEN 0 AND 9223372036854775807),
    revoked_at_ms         INTEGER CHECK (revoked_at_ms BETWEEN 0 AND 9223372036854775807),
    FOREIGN KEY (tenant_id, account_id) REFERENCES v2_accounts(tenant_id, id) ON DELETE CASCADE,
    CHECK (created_at_ms < expires_at_ms AND expires_at_ms - created_at_ms <= 600000),
    CHECK (consumed_at_ms IS NULL OR revoked_at_ms IS NULL)
);
CREATE INDEX v2_pre_device_sessions_by_account
    ON v2_pre_device_sessions (tenant_id, account_id);

-- --------------------------------------------- device-session challenges ---

-- One HPKE proof-of-possession attempt: the exact binding the server issued
-- and the hash of the secret it sealed. 120 seconds, used at most once.
CREATE TABLE v2_device_session_challenges (
    id                    BLOB    NOT NULL PRIMARY KEY CHECK (length(id) = 16),
    pre_device_session_id BLOB    NOT NULL REFERENCES v2_pre_device_sessions(id) ON DELETE CASCADE,
    tenant_id             BLOB    NOT NULL,
    account_id            BLOB    NOT NULL,
    device_id             BLOB    NOT NULL,
    binding_bytes         BLOB    NOT NULL CHECK (length(binding_bytes) BETWEEN 1 AND 4096),
    secret_hash           BLOB    NOT NULL CHECK (length(secret_hash) = 32),
    created_at_ms         INTEGER NOT NULL CHECK (created_at_ms BETWEEN 0 AND 9223372036854775807),
    expires_at_ms         INTEGER NOT NULL CHECK (expires_at_ms BETWEEN 0 AND 9223372036854775807),
    consumed_at_ms        INTEGER CHECK (consumed_at_ms BETWEEN 0 AND 9223372036854775807),
    revoked_at_ms         INTEGER CHECK (revoked_at_ms BETWEEN 0 AND 9223372036854775807),
    FOREIGN KEY (tenant_id, account_id) REFERENCES v2_accounts(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, device_id) REFERENCES v2_devices(tenant_id, id) ON DELETE CASCADE,
    CHECK (created_at_ms < expires_at_ms AND expires_at_ms - created_at_ms <= 120000),
    CHECK (consumed_at_ms IS NULL OR revoked_at_ms IS NULL)
);
CREATE INDEX v2_device_session_challenges_by_ticket
    ON v2_device_session_challenges (pre_device_session_id);
CREATE INDEX v2_device_session_challenges_by_device
    ON v2_device_session_challenges (tenant_id, device_id);

-- ------------------------------------------------------------ v2_sessions ---

DROP TABLE v2_sessions;
CREATE TABLE v2_sessions (
    id                          BLOB    NOT NULL CHECK (length(id) = 16),
    tenant_id                   BLOB    NOT NULL,
    account_id                  BLOB    NOT NULL,
    device_id                   BLOB    NOT NULL,
    server_instance_id          BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    restore_epoch               INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    signing_key_id              BLOB    NOT NULL CHECK (length(signing_key_id) = 32),
    hpke_key_id                 BLOB    NOT NULL CHECK (length(hpke_key_id) = 32),
    account_token_version       INTEGER NOT NULL
        CHECK (account_token_version BETWEEN 0 AND 9223372036854775807),
    class                       TEXT    NOT NULL
        CHECK (class IN ('pending_setup', 'root_setup', 'ordinary')),
    -- PoP evidence: the ticket and the challenge this session was proven with.
    pre_device_session_id       BLOB    NOT NULL REFERENCES v2_pre_device_sessions(id),
    device_session_challenge_id BLOB    NOT NULL UNIQUE
        REFERENCES v2_device_session_challenges(id),
    pop_at_ms                   INTEGER NOT NULL CHECK (pop_at_ms BETWEEN 0 AND 9223372036854775807),
    access_token_hash           BLOB    NOT NULL UNIQUE CHECK (length(access_token_hash) = 32),
    access_expires_at_ms        INTEGER NOT NULL
        CHECK (access_expires_at_ms BETWEEN 0 AND 9223372036854775807),
    refresh_token_hash          BLOB    NOT NULL UNIQUE CHECK (length(refresh_token_hash) = 32),
    -- The token the last rotation replaced: presenting it again means two
    -- holders, so the session ends.
    previous_refresh_token_hash BLOB    UNIQUE CHECK (length(previous_refresh_token_hash) = 32),
    refresh_expires_at_ms       INTEGER NOT NULL
        CHECK (refresh_expires_at_ms BETWEEN 0 AND 9223372036854775807),
    absolute_expires_at_ms      INTEGER NOT NULL
        CHECK (absolute_expires_at_ms BETWEEN 0 AND 9223372036854775807),
    revoked_at_ms               INTEGER CHECK (revoked_at_ms BETWEEN 0 AND 9223372036854775807),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES v2_accounts(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, device_id) REFERENCES v2_devices(tenant_id, id) ON DELETE CASCADE,
    CHECK (signing_key_id <> hpke_key_id),
    CHECK (access_expires_at_ms <= absolute_expires_at_ms),
    CHECK (refresh_expires_at_ms <= absolute_expires_at_ms),
    -- Setup sessions are bounded at 30 minutes from the proof (R2).
    CHECK (class <> 'pending_setup' OR absolute_expires_at_ms - pop_at_ms <= 1800000)
);
CREATE INDEX v2_sessions_by_device ON v2_sessions (tenant_id, device_id);
CREATE INDEX v2_sessions_by_account ON v2_sessions (tenant_id, account_id);
-- A consumed ticket or challenge stays while a session names it.
CREATE INDEX v2_sessions_by_ticket ON v2_sessions (pre_device_session_id);

-- Neither refresh nor credentials can change what a session is bound to.
CREATE TRIGGER v2_sessions_binding_is_fixed
BEFORE UPDATE OF id, tenant_id, account_id, device_id, server_instance_id, restore_epoch,
                 signing_key_id, hpke_key_id, account_token_version, pre_device_session_id,
                 device_session_challenge_id, pop_at_ms, absolute_expires_at_ms
ON v2_sessions
BEGIN
    SELECT RAISE(ABORT, 'a v2 session binding never changes');
END;

CREATE TRIGGER v2_sessions_revocation_is_final
BEFORE UPDATE ON v2_sessions
WHEN OLD.revoked_at_ms IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'a revoked v2 session never changes');
END;

-- A used or revoked ticket or challenge stays that way.
CREATE TRIGGER v2_pre_device_sessions_settled_is_final
BEFORE UPDATE ON v2_pre_device_sessions
WHEN OLD.consumed_at_ms IS NOT NULL OR OLD.revoked_at_ms IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'a settled pre-device ticket never changes');
END;

CREATE TRIGGER v2_device_session_challenges_settled_is_final
BEFORE UPDATE ON v2_device_session_challenges
WHEN OLD.consumed_at_ms IS NOT NULL OR OLD.revoked_at_ms IS NOT NULL
BEGIN
    SELECT RAISE(ABORT, 'a settled device-session challenge never changes');
END;

CREATE TRIGGER v2_pre_device_sessions_binding_is_fixed
BEFORE UPDATE OF id, token_hash, server_instance_id, restore_epoch, tenant_id, account_id,
                 account_token_version, created_at_ms, expires_at_ms
ON v2_pre_device_sessions
BEGIN
    SELECT RAISE(ABORT, 'a pre-device ticket binding never changes');
END;

CREATE TRIGGER v2_device_session_challenges_binding_is_fixed
BEFORE UPDATE OF id, pre_device_session_id, tenant_id, account_id, device_id, binding_bytes,
                 secret_hash, created_at_ms, expires_at_ms
ON v2_device_session_challenges
BEGIN
    SELECT RAISE(ABORT, 'a device-session challenge binding never changes');
END;

-- Enforcement was off for the rebuild; prove every reference still holds.
CREATE TEMP TABLE m0013_foreign_keys (
    ok INTEGER NOT NULL
        CONSTRAINT m0013_foreign_key_violation CHECK (ok = 1)
);
INSERT INTO temp.m0013_foreign_keys
SELECT NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check);

DROP TABLE m0013_fk_off;
DROP TABLE m0013_no_live_sessions;
DROP TABLE m0013_foreign_keys;
