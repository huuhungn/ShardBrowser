-- Plan L401, L2045 (V5.3): an unsigned wire integer is stored as an INTEGER,
-- never coerced through REAL or TEXT. The upper-bound CHECKs admit an
-- in-range REAL such as 1.5 (or '1.5', which INTEGER affinity turns into
-- one), so every INTEGER column of every v2 table also refuses any value
-- that is not an integer once affinity applied. The tables are not rebuilt:
-- each gets an insert and an update trigger. Generated from the schema
-- 0001-0029 leave; a later rebuild of a table must recreate its two.

CREATE TRIGGER v2_accounts_integers_on_insert
BEFORE INSERT ON v2_accounts
WHEN typeof(NEW.token_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_accounts_integers_on_update
BEFORE UPDATE OF token_version ON v2_accounts
WHEN typeof(NEW.token_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_capability_grants_integers_on_insert
BEFORE INSERT ON v2_capability_grants
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_capability_grants_integers_on_update
BEFORE UPDATE OF payload_version, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, signature_suite_id, signature_version ON v2_capability_grants
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_device_approvals_integers_on_insert
BEFORE INSERT ON v2_device_approvals
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_device_approvals_integers_on_update
BEFORE UPDATE OF payload_version, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, signature_suite_id, signature_version ON v2_device_approvals
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_device_revocations_integers_on_insert
BEFORE INSERT ON v2_device_revocations
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
   OR typeof(NEW.filed_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_device_revocations_integers_on_update
BEFORE UPDATE OF payload_version, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, signature_suite_id, signature_version, filed_at_ms ON v2_device_revocations
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
   OR typeof(NEW.filed_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_device_session_challenges_integers_on_insert
BEFORE INSERT ON v2_device_session_challenges
WHEN typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.consumed_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.revoked_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_device_session_challenges_integers_on_update
BEFORE UPDATE OF created_at_ms, expires_at_ms, consumed_at_ms, revoked_at_ms ON v2_device_session_challenges
WHEN typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.consumed_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.revoked_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_devices_integers_on_insert
BEFORE INSERT ON v2_devices
WHEN typeof(NEW.signing_suite) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_devices_integers_on_update
BEFORE UPDATE OF signing_suite, hpke_suite ON v2_devices
WHEN typeof(NEW.signing_suite) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_enrollment_challenges_integers_on_insert
BEFORE INSERT ON v2_enrollment_challenges
WHEN typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.consumed_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.revoked_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_enrollment_challenges_integers_on_update
BEFORE UPDATE OF created_at_ms, expires_at_ms, consumed_at_ms, revoked_at_ms ON v2_enrollment_challenges
WHEN typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.consumed_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.revoked_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_first_device_confirmations_integers_on_insert
BEFORE INSERT ON v2_first_device_confirmations
WHEN typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.confirmed_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.signing_suite) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite) NOT IN ('integer', 'null')
   OR typeof(NEW.consumed_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.terminal_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_first_device_confirmations_integers_on_update
BEFORE UPDATE OF restore_epoch, confirmed_at_ms, signing_suite, hpke_suite, consumed_at_ms, terminal_at_ms ON v2_first_device_confirmations
WHEN typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.confirmed_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.signing_suite) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite) NOT IN ('integer', 'null')
   OR typeof(NEW.consumed_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.terminal_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_fleet_device_hpke_grants_integers_on_insert
BEFORE INSERT ON v2_fleet_device_hpke_grants
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.generation) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_fleet_device_hpke_grants_integers_on_update
BEFORE UPDATE OF payload_version, generation, hpke_suite_id, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, signature_suite_id, signature_version ON v2_fleet_device_hpke_grants
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.generation) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_fleet_key_generations_integers_on_insert
BEFORE INSERT ON v2_fleet_key_generations
WHEN typeof(NEW.generation) NOT IN ('integer', 'null')
   OR typeof(NEW.root_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.required_device_grant_count) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_fleet_key_generations_integers_on_update
BEFORE UPDATE OF generation, root_generation, required_device_grant_count ON v2_fleet_key_generations
WHEN typeof(NEW.generation) NOT IN ('integer', 'null')
   OR typeof(NEW.root_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.required_device_grant_count) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_fleet_key_grants_integers_on_insert
BEFORE INSERT ON v2_fleet_key_grants
WHEN typeof(NEW.fleet_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_fleet_key_grants_integers_on_update
BEFORE UPDATE OF fleet_generation, hpke_suite_id, restore_epoch, issued_at_ms, not_before_ms, not_after_ms ON v2_fleet_key_grants
WHEN typeof(NEW.fleet_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_fleet_recovery_grants_integers_on_insert
BEFORE INSERT ON v2_fleet_recovery_grants
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.generation) NOT IN ('integer', 'null')
   OR typeof(NEW.recipient_root_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.root_wrap_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_fleet_recovery_grants_integers_on_update
BEFORE UPDATE OF payload_version, generation, recipient_root_generation, root_wrap_suite_id, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, signature_suite_id, signature_version ON v2_fleet_recovery_grants
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.generation) NOT IN ('integer', 'null')
   OR typeof(NEW.recipient_root_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.root_wrap_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_fleet_rotation_grants_integers_on_insert
BEFORE INSERT ON v2_fleet_rotation_grants
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.generation) NOT IN ('integer', 'null')
   OR typeof(NEW.previous_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.required_device_grant_count) NOT IN ('integer', 'null')
   OR typeof(NEW.activation_not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_fleet_rotation_grants_integers_on_update
BEFORE UPDATE OF payload_version, generation, previous_generation, required_device_grant_count, activation_not_before_ms, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, signature_suite_id, signature_version ON v2_fleet_rotation_grants
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.generation) NOT IN ('integer', 'null')
   OR typeof(NEW.previous_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.required_device_grant_count) NOT IN ('integer', 'null')
   OR typeof(NEW.activation_not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_idempotency_integers_on_insert
BEFORE INSERT ON v2_idempotency
WHEN typeof(NEW.retained_until) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_idempotency_integers_on_update
BEFORE UPDATE OF retained_until, restore_epoch ON v2_idempotency
WHEN typeof(NEW.retained_until) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_leases_integers_on_insert
BEFORE INSERT ON v2_leases
WHEN typeof(NEW.fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.base_version) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_leases_integers_on_update
BEFORE UPDATE OF fencing_token, base_version, restore_epoch ON v2_leases
WHEN typeof(NEW.fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.base_version) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_legacy_capability_grants_integers_on_insert
BEFORE INSERT ON v2_legacy_capability_grants
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_legacy_capability_grants_integers_on_update
BEFORE UPDATE OF payload_version, issued_at_ms, not_before_ms, not_after_ms, restore_epoch ON v2_legacy_capability_grants
WHEN typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_legacy_tenant_root_key_grants_integers_on_insert
BEFORE INSERT ON v2_legacy_tenant_root_key_grants
WHEN typeof(NEW.root_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_mode_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_kem_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_kdf_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_aead_id) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_legacy_tenant_root_key_grants_integers_on_update
BEFORE UPDATE OF root_generation, hpke_suite_id, hpke_mode_id, hpke_kem_id, hpke_kdf_id, hpke_aead_id, restore_epoch ON v2_legacy_tenant_root_key_grants
WHEN typeof(NEW.root_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_mode_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_kem_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_kdf_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_aead_id) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_operations_integers_on_insert
BEFORE INSERT ON v2_operations
WHEN typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.response_status_code) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_operations_integers_on_update
BEFORE UPDATE OF restore_epoch, response_status_code ON v2_operations
WHEN typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.response_status_code) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_pre_device_sessions_integers_on_insert
BEFORE INSERT ON v2_pre_device_sessions
WHEN typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.account_token_version) NOT IN ('integer', 'null')
   OR typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.consumed_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.revoked_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_pre_device_sessions_integers_on_update
BEFORE UPDATE OF restore_epoch, account_token_version, created_at_ms, expires_at_ms, consumed_at_ms, revoked_at_ms ON v2_pre_device_sessions
WHEN typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.account_token_version) NOT IN ('integer', 'null')
   OR typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.consumed_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.revoked_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_profile_leases_integers_on_insert
BEFORE INSERT ON v2_profile_leases
WHEN typeof(NEW.fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.base_version) NOT IN ('integer', 'null')
   OR typeof(NEW.acquired_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.expires_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_profile_leases_integers_on_update
BEFORE UPDATE OF fencing_token, base_version, acquired_at_ms, expires_at_ms ON v2_profile_leases
WHEN typeof(NEW.fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.base_version) NOT IN ('integer', 'null')
   OR typeof(NEW.acquired_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.expires_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_profiles_integers_on_insert
BEFORE INSERT ON v2_profiles
WHEN typeof(NEW.current_version) NOT IN ('integer', 'null')
   OR typeof(NEW.last_fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.current_key_generation) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_profiles_integers_on_update
BEFORE UPDATE OF current_version, last_fencing_token, current_key_generation ON v2_profiles
WHEN typeof(NEW.current_version) NOT IN ('integer', 'null')
   OR typeof(NEW.last_fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.current_key_generation) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_replay_ledger_integers_on_insert
BEFORE INSERT ON v2_replay_ledger
WHEN typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_replay_ledger_integers_on_update
BEFORE UPDATE OF not_before_ms, not_after_ms ON v2_replay_ledger
WHEN typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_restore_epoch_transition_proofs_integers_on_insert
BEFORE INSERT ON v2_restore_epoch_transition_proofs
WHEN typeof(NEW.previous_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.new_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.leaf_index) NOT IN ('integer', 'null')
   OR typeof(NEW.leaf_count) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_restore_epoch_transition_proofs_integers_on_update
BEFORE UPDATE OF previous_epoch, new_epoch, leaf_index, leaf_count ON v2_restore_epoch_transition_proofs
WHEN typeof(NEW.previous_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.new_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.leaf_index) NOT IN ('integer', 'null')
   OR typeof(NEW.leaf_count) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_restore_epoch_transitions_integers_on_insert
BEFORE INSERT ON v2_restore_epoch_transitions
WHEN typeof(NEW.previous_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.new_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.mapping_count) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_restore_epoch_transitions_integers_on_update
BEFORE UPDATE OF previous_epoch, new_epoch, mapping_count, issued_at_ms, signature_suite_id, signature_version ON v2_restore_epoch_transitions
WHEN typeof(NEW.previous_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.new_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.mapping_count) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_root_key_generations_integers_on_insert
BEFORE INSERT ON v2_root_key_generations
WHEN typeof(NEW.generation) NOT IN ('integer', 'null')
   OR typeof(NEW.required_custodian_grant_count) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_root_key_generations_integers_on_update
BEFORE UPDATE OF generation, required_custodian_grant_count ON v2_root_key_generations
WHEN typeof(NEW.generation) NOT IN ('integer', 'null')
   OR typeof(NEW.required_custodian_grant_count) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_server_state_integers_on_insert
BEFORE INSERT ON v2_server_state
WHEN typeof(NEW.singleton) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_server_state_integers_on_update
BEFORE UPDATE OF singleton, restore_epoch ON v2_server_state
WHEN typeof(NEW.singleton) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_sessions_integers_on_insert
BEFORE INSERT ON v2_sessions
WHEN typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.account_token_version) NOT IN ('integer', 'null')
   OR typeof(NEW.pop_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.access_expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.refresh_expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.absolute_expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.revoked_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_sessions_integers_on_update
BEFORE UPDATE OF restore_epoch, account_token_version, pop_at_ms, access_expires_at_ms, refresh_expires_at_ms, absolute_expires_at_ms, revoked_at_ms ON v2_sessions
WHEN typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.account_token_version) NOT IN ('integer', 'null')
   OR typeof(NEW.pop_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.access_expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.refresh_expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.absolute_expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.revoked_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_snapshot_manifests_integers_on_insert
BEFORE INSERT ON v2_snapshot_manifests
WHEN typeof(NEW.version) NOT IN ('integer', 'null')
   OR typeof(NEW.base_version) NOT IN ('integer', 'null')
   OR typeof(NEW.key_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.container_size) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_snapshot_manifests_integers_on_update
BEFORE UPDATE OF version, base_version, key_generation, restore_epoch, fencing_token, container_size ON v2_snapshot_manifests
WHEN typeof(NEW.version) NOT IN ('integer', 'null')
   OR typeof(NEW.base_version) NOT IN ('integer', 'null')
   OR typeof(NEW.key_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.container_size) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_snapshots_integers_on_insert
BEFORE INSERT ON v2_snapshots
WHEN typeof(NEW.version) NOT IN ('integer', 'null')
   OR typeof(NEW.key_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.envelope_version) NOT IN ('integer', 'null')
   OR typeof(NEW.ciphertext_size) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_snapshots_integers_on_update
BEFORE UPDATE OF version, key_generation, envelope_version, ciphertext_size, signature_suite_id, signature_version, restore_epoch, created_at_ms ON v2_snapshots
WHEN typeof(NEW.version) NOT IN ('integer', 'null')
   OR typeof(NEW.key_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.envelope_version) NOT IN ('integer', 'null')
   OR typeof(NEW.ciphertext_size) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_tenant_root_key_grants_integers_on_insert
BEFORE INSERT ON v2_tenant_root_key_grants
WHEN typeof(NEW.container_version) NOT IN ('integer', 'null')
   OR typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.root_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_mode_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_kem_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_kdf_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_aead_id) NOT IN ('integer', 'null')
   OR typeof(NEW.previous_root_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_tenant_root_key_grants_integers_on_update
BEFORE UPDATE OF container_version, payload_version, root_generation, hpke_suite_id, hpke_mode_id, hpke_kem_id, hpke_kdf_id, hpke_aead_id, previous_root_generation, issued_at_ms, not_before_ms, not_after_ms, restore_epoch, signature_suite_id, signature_version ON v2_tenant_root_key_grants
WHEN typeof(NEW.container_version) NOT IN ('integer', 'null')
   OR typeof(NEW.payload_version) NOT IN ('integer', 'null')
   OR typeof(NEW.root_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_mode_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_kem_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_kdf_id) NOT IN ('integer', 'null')
   OR typeof(NEW.hpke_aead_id) NOT IN ('integer', 'null')
   OR typeof(NEW.previous_root_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.issued_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_before_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.not_after_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_suite_id) NOT IN ('integer', 'null')
   OR typeof(NEW.signature_version) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_tenants_integers_on_insert
BEFORE INSERT ON v2_tenants
WHEN typeof(NEW.active_root_generation) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_tenants_integers_on_update
BEFORE UPDATE OF active_root_generation ON v2_tenants
WHEN typeof(NEW.active_root_generation) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_upload_chunks_integers_on_insert
BEFORE INSERT ON v2_upload_chunks
WHEN typeof(NEW.chunk_offset) NOT IN ('integer', 'null')
   OR typeof(NEW.chunk_length) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_upload_chunks_integers_on_update
BEFORE UPDATE OF chunk_offset, chunk_length ON v2_upload_chunks
WHEN typeof(NEW.chunk_offset) NOT IN ('integer', 'null')
   OR typeof(NEW.chunk_length) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_upload_quarantine_integers_on_insert
BEFORE INSERT ON v2_upload_quarantine
WHEN typeof(NEW.security_incident) NOT IN ('integer', 'null')
   OR typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_upload_quarantine_integers_on_update
BEFORE UPDATE OF security_incident, created_at_ms ON v2_upload_quarantine
WHEN typeof(NEW.security_incident) NOT IN ('integer', 'null')
   OR typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_upload_sessions_integers_on_insert
BEFORE INSERT ON v2_upload_sessions
WHEN typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.target_version) NOT IN ('integer', 'null')
   OR typeof(NEW.declared_size) NOT IN ('integer', 'null')
   OR typeof(NEW.received_size) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_upload_sessions_integers_on_update
BEFORE UPDATE OF restore_epoch, fencing_token, target_version, declared_size, received_size ON v2_upload_sessions
WHEN typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.target_version) NOT IN ('integer', 'null')
   OR typeof(NEW.declared_size) NOT IN ('integer', 'null')
   OR typeof(NEW.received_size) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_uploads_integers_on_insert
BEFORE INSERT ON v2_uploads
WHEN typeof(NEW.fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.base_version) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.key_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.expected_ciphertext_size) NOT IN ('integer', 'null')
   OR typeof(NEW.committed_offset) NOT IN ('integer', 'null')
   OR typeof(NEW.expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;

CREATE TRIGGER v2_uploads_integers_on_update
BEFORE UPDATE OF fencing_token, base_version, restore_epoch, key_generation, expected_ciphertext_size, committed_offset, expires_at_ms, created_at_ms ON v2_uploads
WHEN typeof(NEW.fencing_token) NOT IN ('integer', 'null')
   OR typeof(NEW.base_version) NOT IN ('integer', 'null')
   OR typeof(NEW.restore_epoch) NOT IN ('integer', 'null')
   OR typeof(NEW.key_generation) NOT IN ('integer', 'null')
   OR typeof(NEW.expected_ciphertext_size) NOT IN ('integer', 'null')
   OR typeof(NEW.committed_offset) NOT IN ('integer', 'null')
   OR typeof(NEW.expires_at_ms) NOT IN ('integer', 'null')
   OR typeof(NEW.created_at_ms) NOT IN ('integer', 'null')
BEGIN
    SELECT RAISE(ABORT, 'an integer column holds only integers');
END;
