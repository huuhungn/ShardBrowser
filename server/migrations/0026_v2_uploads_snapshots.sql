-- G2-23, G2-24: CREATE_UPLOAD, chunk upload, FINALIZE_UPLOAD and COMMIT of a
-- published profile (plan 7.3 L1087-L1089, 7.4 L1099-L1105, 8.1 L1145-L1176).
--
-- `snapshot_id` and `manifest_replay_id` are bound once per upload, unique per
-- profile, and carried into the snapshot through the composite FK (C6.5).
-- Both tables carry the instance/fleet/generation/key identity of their FKEK
-- generation through a composite FK to its candidate key (C6.7, L1101).
-- Times are server milliseconds (L1111). Additive to L1087:
-- `upload_id`-scoped chunk rows carry `server_instance_id` for their FK.

CREATE TABLE v2_uploads (
    server_instance_id  BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id           BLOB    NOT NULL CHECK (length(tenant_id) = 16),
    upload_id           BLOB    NOT NULL CHECK (length(upload_id) = 16),
    fleet_id            BLOB    NOT NULL CHECK (length(fleet_id) = 16),
    profile_id          BLOB    NOT NULL CHECK (length(profile_id) = 16),
    snapshot_id         BLOB    NOT NULL CHECK (length(snapshot_id) = 16),
    manifest_replay_id  BLOB    NOT NULL CHECK (length(manifest_replay_id) = 16),
    lease_id            BLOB    NOT NULL CHECK (length(lease_id) = 16),
    fencing_token       INTEGER NOT NULL CHECK (fencing_token BETWEEN 1 AND 9223372036854775807),
    base_version        INTEGER NOT NULL CHECK (base_version BETWEEN 0 AND 9223372036854775807),
    restore_epoch       INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    operation_scope     TEXT    NOT NULL CHECK (operation_scope = 'profile.create-upload.v2'),
    idempotency_key     BLOB    NOT NULL CHECK (length(idempotency_key) = 16),
    canonical_request_hash BLOB NOT NULL CHECK (length(canonical_request_hash) = 32),
    intent_hash         BLOB    NOT NULL CHECK (length(intent_hash) = 32),
    preamble_sha256     BLOB    NOT NULL CHECK (length(preamble_sha256) = 32),
    dek_slot_sha256     BLOB    NOT NULL CHECK (length(dek_slot_sha256) = 32),
    fkek_key_id         BLOB    NOT NULL CHECK (length(fkek_key_id) = 32),
    key_generation      INTEGER NOT NULL CHECK (key_generation BETWEEN 0 AND 9223372036854775807),
    expected_ciphertext_size   INTEGER NOT NULL
        CHECK (expected_ciphertext_size BETWEEN 1 AND 536870912),
    expected_ciphertext_sha256 BLOB NOT NULL CHECK (length(expected_ciphertext_sha256) = 32),
    committed_offset    INTEGER NOT NULL DEFAULT 0
        CHECK (committed_offset BETWEEN 0 AND expected_ciphertext_size),
    staging_path        TEXT    NOT NULL,
    immutable_path      TEXT,
    state               TEXT    NOT NULL CHECK (state IN
        ('OPEN', 'FINALIZING', 'READY', 'COMMITTED', 'ABORTED', 'QUARANTINED')),
    signed_manifest_container_bytes        BLOB
        CHECK (length(signed_manifest_container_bytes) BETWEEN 1 AND 131072),
    signed_manifest_container_hash         BLOB CHECK (length(signed_manifest_container_hash) = 32),
    signed_manifest_container_bytes_sha256 BLOB
        CHECK (length(signed_manifest_container_bytes_sha256) = 32),
    exact_commit_request_bytes             BLOB
        CHECK (length(exact_commit_request_bytes) BETWEEN 1 AND 262144),
    exact_commit_request_bytes_sha256      BLOB
        CHECK (length(exact_commit_request_bytes_sha256) = 32),
    exact_finalize_response_bytes          BLOB,
    exact_commit_receipt_binding_bytes     BLOB,
    commit_receipt_binding_bytes_sha256    BLOB
        CHECK (length(commit_receipt_binding_bytes_sha256) = 32),
    expires_at_ms       INTEGER NOT NULL CHECK (expires_at_ms BETWEEN 0 AND 9223372036854775807),
    created_at_ms       INTEGER NOT NULL CHECK (created_at_ms BETWEEN 0 AND 9223372036854775807),
    PRIMARY KEY (server_instance_id, tenant_id, upload_id),
    UNIQUE (server_instance_id, tenant_id, profile_id, snapshot_id),
    UNIQUE (server_instance_id, tenant_id, profile_id, manifest_replay_id),
    UNIQUE (server_instance_id, tenant_id, upload_id, fleet_id, snapshot_id, manifest_replay_id),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES v2_profiles(tenant_id, id),
    FOREIGN KEY (server_instance_id, tenant_id, fleet_id, key_generation, fkek_key_id)
        REFERENCES v2_fleet_key_generations(server_instance_id, tenant_id, fleet_id, generation,
                                            fkek_key_id),
    -- L1104: the exact manifest and request are durable before READY, the
    -- exact receipt before COMMITTED.
    CHECK (state NOT IN ('READY', 'COMMITTED') OR (
        immutable_path IS NOT NULL
        AND signed_manifest_container_bytes IS NOT NULL
        AND signed_manifest_container_hash IS NOT NULL
        AND signed_manifest_container_bytes_sha256 IS NOT NULL
        AND exact_commit_request_bytes IS NOT NULL
        AND exact_commit_request_bytes_sha256 IS NOT NULL
        AND exact_finalize_response_bytes IS NOT NULL
        AND committed_offset = expected_ciphertext_size)),
    CHECK ((state = 'COMMITTED') = (exact_commit_receipt_binding_bytes IS NOT NULL)),
    CHECK ((state = 'COMMITTED') = (commit_receipt_binding_bytes_sha256 IS NOT NULL))
);

-- An upload keeps the terms it was created with.
CREATE TRIGGER v2_uploads_terms_are_fixed
BEFORE UPDATE OF server_instance_id, tenant_id, upload_id, fleet_id, profile_id, snapshot_id,
                 manifest_replay_id, lease_id, fencing_token, base_version, restore_epoch,
                 operation_scope, idempotency_key, canonical_request_hash, intent_hash,
                 preamble_sha256, dek_slot_sha256, fkek_key_id, key_generation,
                 expected_ciphertext_size, expected_ciphertext_sha256, staging_path,
                 expires_at_ms, created_at_ms
ON v2_uploads
BEGIN
    SELECT RAISE(ABORT, 'an upload keeps the terms it was created with');
END;

-- L1104: exact bytes are the replay authority, written once.
CREATE TRIGGER v2_uploads_artifacts_are_written_once
BEFORE UPDATE ON v2_uploads
WHEN (OLD.signed_manifest_container_bytes IS NOT NULL
      AND (NEW.signed_manifest_container_bytes IS NOT OLD.signed_manifest_container_bytes
           OR NEW.signed_manifest_container_hash IS NOT OLD.signed_manifest_container_hash
           OR NEW.signed_manifest_container_bytes_sha256
              IS NOT OLD.signed_manifest_container_bytes_sha256
           OR NEW.exact_commit_request_bytes IS NOT OLD.exact_commit_request_bytes
           OR NEW.exact_commit_request_bytes_sha256 IS NOT OLD.exact_commit_request_bytes_sha256
           OR NEW.exact_finalize_response_bytes IS NOT OLD.exact_finalize_response_bytes
           OR NEW.immutable_path IS NOT OLD.immutable_path))
  OR (OLD.exact_commit_receipt_binding_bytes IS NOT NULL
      AND (NEW.exact_commit_receipt_binding_bytes IS NOT OLD.exact_commit_receipt_binding_bytes
           OR NEW.commit_receipt_binding_bytes_sha256
              IS NOT OLD.commit_receipt_binding_bytes_sha256))
BEGIN
    SELECT RAISE(ABORT, 'upload artifacts are written once');
END;

-- L1157: OPEN -> FINALIZING -> READY -> COMMITTED, or a terminal error state.
CREATE TRIGGER v2_uploads_state_moves_forward
BEFORE UPDATE OF state ON v2_uploads
WHEN NEW.state IS NOT OLD.state
 AND OLD.state || '>' || NEW.state NOT IN (
     'OPEN>FINALIZING', 'FINALIZING>READY', 'READY>COMMITTED',
     'OPEN>QUARANTINED', 'FINALIZING>QUARANTINED',
     'OPEN>ABORTED', 'FINALIZING>ABORTED', 'READY>ABORTED')
BEGIN
    SELECT RAISE(ABORT, 'an upload state moves forward only');
END;

CREATE TRIGGER v2_uploads_offset_moves_forward
BEFORE UPDATE OF committed_offset ON v2_uploads
WHEN NEW.committed_offset < OLD.committed_offset
BEGIN
    SELECT RAISE(ABORT, 'an upload offset never moves back');
END;

-- L1088, L1160: one durable receipt per chunk, at the offset it was written.
CREATE TABLE v2_upload_chunks (
    server_instance_id BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id          BLOB    NOT NULL CHECK (length(tenant_id) = 16),
    upload_id          BLOB    NOT NULL CHECK (length(upload_id) = 16),
    chunk_offset       INTEGER NOT NULL CHECK (chunk_offset BETWEEN 0 AND 536870911),
    chunk_length       INTEGER NOT NULL CHECK (chunk_length BETWEEN 1 AND 536870912),
    chunk_sha256       BLOB    NOT NULL CHECK (length(chunk_sha256) = 32),
    PRIMARY KEY (server_instance_id, tenant_id, upload_id, chunk_offset),
    FOREIGN KEY (server_instance_id, tenant_id, upload_id)
        REFERENCES v2_uploads(server_instance_id, tenant_id, upload_id) ON DELETE CASCADE
);

-- L1089: one row per committed version, through the upload that carried it.
CREATE TABLE v2_snapshots (
    server_instance_id  BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id           BLOB    NOT NULL CHECK (length(tenant_id) = 16),
    fleet_id            BLOB    NOT NULL CHECK (length(fleet_id) = 16),
    profile_id          BLOB    NOT NULL CHECK (length(profile_id) = 16),
    version             INTEGER NOT NULL CHECK (version BETWEEN 1 AND 9223372036854775807),
    snapshot_id         BLOB    NOT NULL CHECK (length(snapshot_id) = 16),
    manifest_replay_id  BLOB    NOT NULL CHECK (length(manifest_replay_id) = 16),
    upload_id           BLOB    NOT NULL CHECK (length(upload_id) = 16),
    fkek_key_id         BLOB    NOT NULL CHECK (length(fkek_key_id) = 32),
    key_generation      INTEGER NOT NULL CHECK (key_generation BETWEEN 0 AND 9223372036854775807),
    envelope_version    INTEGER NOT NULL CHECK (envelope_version = 2),
    intent_hash         BLOB    NOT NULL CHECK (length(intent_hash) = 32),
    preamble_sha256     BLOB    NOT NULL CHECK (length(preamble_sha256) = 32),
    dek_slot_sha256     BLOB    NOT NULL CHECK (length(dek_slot_sha256) = 32),
    immutable_blob_path TEXT    NOT NULL,
    ciphertext_sha256   BLOB    NOT NULL CHECK (length(ciphertext_sha256) = 32),
    ciphertext_size     INTEGER NOT NULL CHECK (ciphertext_size BETWEEN 1 AND 536870912),
    signed_manifest_container_bytes        BLOB NOT NULL
        CHECK (length(signed_manifest_container_bytes) BETWEEN 1 AND 131072),
    signed_manifest_container_hash         BLOB NOT NULL
        CHECK (length(signed_manifest_container_hash) = 32),
    signed_manifest_container_bytes_sha256 BLOB NOT NULL
        CHECK (length(signed_manifest_container_bytes_sha256) = 32),
    previous_head_hash  BLOB    CHECK (length(previous_head_hash) = 32),
    head_hash           BLOB    NOT NULL CHECK (length(head_hash) = 32),
    signing_key_id      BLOB    NOT NULL CHECK (length(signing_key_id) = 32),
    signature_suite_id  INTEGER NOT NULL CHECK (signature_suite_id = 1),
    signature_version   INTEGER NOT NULL CHECK (signature_version = 1),
    signature_bytes     BLOB    NOT NULL CHECK (length(signature_bytes) = 64),
    restore_epoch       INTEGER NOT NULL CHECK (restore_epoch BETWEEN 0 AND 9223372036854775807),
    created_by_device   BLOB    NOT NULL CHECK (length(created_by_device) = 16),
    created_at_ms       INTEGER NOT NULL CHECK (created_at_ms BETWEEN 0 AND 9223372036854775807),
    PRIMARY KEY (server_instance_id, tenant_id, profile_id, version),
    UNIQUE (server_instance_id, tenant_id, profile_id, snapshot_id),
    UNIQUE (server_instance_id, tenant_id, profile_id, manifest_replay_id),
    FOREIGN KEY (server_instance_id, tenant_id, upload_id, fleet_id, snapshot_id,
                 manifest_replay_id)
        REFERENCES v2_uploads(server_instance_id, tenant_id, upload_id, fleet_id, snapshot_id,
                              manifest_replay_id),
    FOREIGN KEY (server_instance_id, tenant_id, fleet_id, key_generation, fkek_key_id)
        REFERENCES v2_fleet_key_generations(server_instance_id, tenant_id, fleet_id, generation,
                                            fkek_key_id),
    -- L521: the genesis manifest names no previous head.
    CHECK ((version = 1) = (previous_head_hash IS NULL))
);

CREATE TRIGGER v2_snapshots_are_immutable
BEFORE UPDATE ON v2_snapshots
BEGIN
    SELECT RAISE(ABORT, 'a snapshot row never changes');
END;

-- The two mutations and COMMIT commit with their responses, like 0025's.
CREATE TRIGGER v2_idempotency_create_upload_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'CREATE_UPLOAD' OR NEW.operation_scope = 'profile.create-upload.v2')
 AND (NEW.operation_kind IS NOT 'CREATE_UPLOAD'
      OR NEW.operation_scope IS NOT 'profile.create-upload.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'CreateUploadResponseV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'an upload is created with its response');
END;

CREATE TRIGGER v2_idempotency_finalize_upload_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'FINALIZE_UPLOAD' OR NEW.operation_scope = 'profile.finalize-upload.v2')
 AND (NEW.operation_kind IS NOT 'FINALIZE_UPLOAD'
      OR NEW.operation_scope IS NOT 'profile.finalize-upload.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'FinalizeUploadResponseV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'an upload is finalized with its response');
END;

-- L1105: a commit's response is its exact CommitReceiptBindingV2. A row with
-- approval columns is left to the 0015 CHECKs, which refuse it.
CREATE TRIGGER v2_idempotency_commit_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'COMMIT' OR NEW.operation_scope = 'profile.commit.v2')
 AND NEW.approval_payload_domain IS NULL
 AND (NEW.operation_kind IS NOT 'COMMIT'
      OR NEW.operation_scope IS NOT 'profile.commit.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'CommitReceiptBindingV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a commit is stored with its receipt');
END;
