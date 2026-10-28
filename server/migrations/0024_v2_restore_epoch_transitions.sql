-- Plan 7.2 L1078-L1079, 5.6.3: tenant-scoped restore-epoch transitions and
-- one inclusion proof per covered profile.
--
-- A row holds the exact signed `SignedRestoreEpochTransitionV2` bytes and the
-- columns derived from them; a proof row holds the exact
-- `RestoreEpochInclusionProofV2` bytes of one leaf. The exact bytes are the
-- authority: readback returns them unchanged.

CREATE TABLE v2_restore_epoch_transitions (
    server_instance_id                   BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id                            BLOB    NOT NULL REFERENCES v2_tenants(id)
        CHECK (length(tenant_id) = 16),
    previous_epoch                       INTEGER NOT NULL
        CHECK (previous_epoch BETWEEN 0 AND 9223372036854775807),
    new_epoch                            INTEGER NOT NULL
        CHECK (new_epoch BETWEEN 0 AND 9223372036854775807 AND new_epoch > previous_epoch),
    transition_replay_id                 BLOB    NOT NULL CHECK (length(transition_replay_id) = 16),
    mapping_codec                        TEXT    NOT NULL
        CHECK (mapping_codec = 'PROFILE_HEAD_SET_MERKLE_V2'),
    mapping_count                        INTEGER NOT NULL CHECK (mapping_count BETWEEN 1 AND 1000000),
    profile_head_mapping_root            BLOB    NOT NULL
        CHECK (length(profile_head_mapping_root) = 32),
    reason_code                          TEXT    NOT NULL
        CHECK (reason_code IN ('operator_restore', 'disaster_recovery', 'verified_backup_rollback')),
    approver_account_id                  BLOB    NOT NULL CHECK (length(approver_account_id) = 16),
    approver_device_id                   BLOB    NOT NULL CHECK (length(approver_device_id) = 16),
    approver_signing_key_id              BLOB    NOT NULL CHECK (length(approver_signing_key_id) = 32),
    issued_at_ms                         INTEGER NOT NULL
        CHECK (issued_at_ms BETWEEN 0 AND 9223372036854775807),
    nonce                                BLOB    NOT NULL CHECK (length(nonce) = 16),
    canonical_transition_payload_bytes   BLOB    NOT NULL
        CHECK (length(canonical_transition_payload_bytes) BETWEEN 1 AND 131072),
    transition_payload_sha256            BLOB    NOT NULL CHECK (length(transition_payload_sha256) = 32),
    signature_suite_id                   INTEGER NOT NULL CHECK (signature_suite_id BETWEEN 0 AND 65535),
    signature_version                    INTEGER NOT NULL CHECK (signature_version = 1),
    signature_bytes                      BLOB    NOT NULL CHECK (length(signature_bytes) BETWEEN 1 AND 4096),
    signed_transition_container_hash     BLOB    NOT NULL
        CHECK (length(signed_transition_container_hash) = 32),
    exact_signed_transition_bytes        BLOB    NOT NULL
        CHECK (length(exact_signed_transition_bytes) BETWEEN 1 AND 262144),
    exact_signed_transition_bytes_sha256 BLOB    NOT NULL
        CHECK (length(exact_signed_transition_bytes_sha256) = 32),
    created_at                           TEXT    NOT NULL,
    PRIMARY KEY (server_instance_id, tenant_id, previous_epoch, new_epoch),
    UNIQUE (server_instance_id, tenant_id, transition_replay_id),
    UNIQUE (server_instance_id, tenant_id, nonce)
);

CREATE TABLE v2_restore_epoch_transition_proofs (
    server_instance_id              BLOB    NOT NULL CHECK (length(server_instance_id) = 16),
    tenant_id                       BLOB    NOT NULL CHECK (length(tenant_id) = 16),
    previous_epoch                  INTEGER NOT NULL
        CHECK (previous_epoch BETWEEN 0 AND 9223372036854775807),
    new_epoch                       INTEGER NOT NULL
        CHECK (new_epoch BETWEEN 0 AND 9223372036854775807 AND new_epoch > previous_epoch),
    profile_id                      BLOB    NOT NULL CHECK (length(profile_id) = 16),
    previous_signed_head_hash       BLOB    NOT NULL CHECK (length(previous_signed_head_hash) = 32),
    new_signed_head_hash            BLOB    NOT NULL CHECK (length(new_signed_head_hash) = 32),
    leaf_index                      INTEGER NOT NULL CHECK (leaf_index BETWEEN 0 AND 999999),
    leaf_count                      INTEGER NOT NULL
        CHECK (leaf_count BETWEEN 1 AND 1000000 AND leaf_index < leaf_count),
    canonical_leaf_bytes            BLOB    NOT NULL CHECK (length(canonical_leaf_bytes) BETWEEN 1 AND 1024),
    leaf_hash                       BLOB    NOT NULL CHECK (length(leaf_hash) = 32),
    canonical_inclusion_proof_bytes BLOB    NOT NULL
        CHECK (length(canonical_inclusion_proof_bytes) BETWEEN 1 AND 65536),
    proof_sha256                    BLOB    NOT NULL CHECK (length(proof_sha256) = 32),
    created_at                      TEXT    NOT NULL,
    PRIMARY KEY (server_instance_id, tenant_id, previous_epoch, new_epoch, profile_id),
    UNIQUE (server_instance_id, tenant_id, previous_epoch, new_epoch, leaf_index),
    FOREIGN KEY (server_instance_id, tenant_id, previous_epoch, new_epoch)
        REFERENCES v2_restore_epoch_transitions (server_instance_id, tenant_id, previous_epoch, new_epoch)
);
