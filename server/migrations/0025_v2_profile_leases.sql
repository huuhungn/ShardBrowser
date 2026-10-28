-- G2-21, G2-22, G2-25: profiles published through PROFILE_PUBLISH_CREATE and
-- the one current lease each holds (plan 7.3 L1085-L1086, 7.4 L1096-L1098).
--
-- Numbered 0025 so it does not collide with the restore epoch migration
-- (0024) of a parallel branch; a base without 0024 applies it unchanged.
--
-- `v2_profiles` gains the L1085 columns. A published profile has a label
-- ciphertext and a key generation; a row of the legacy JSON fleet routes has
-- neither. `name` stays NOT NULL and UNIQUE per fleet, so a published profile
-- stores its lowercase hex ID there: its label exists only as ciphertext.

ALTER TABLE v2_profiles ADD COLUMN label_ciphertext BLOB
    CHECK (label_ciphertext IS NULL OR length(label_ciphertext) BETWEEN 1 AND 4096);
ALTER TABLE v2_profiles ADD COLUMN last_fencing_token INTEGER NOT NULL DEFAULT 0
    CHECK (last_fencing_token BETWEEN 0 AND 9223372036854775807);
ALTER TABLE v2_profiles ADD COLUMN current_key_generation INTEGER
    CHECK (current_key_generation IS NULL
           OR current_key_generation BETWEEN 0 AND 9223372036854775807);

-- L1097: exactly one current row per profile while held. Checkout replaces an
-- expired row; release, force-expire and commit delete it. History is in
-- v2_audit_events only. Times are server milliseconds (L1111).
CREATE TABLE v2_profile_leases (
    tenant_id           BLOB    NOT NULL CHECK (length(tenant_id) = 16),
    profile_id          BLOB    NOT NULL CHECK (length(profile_id) = 16),
    lease_id            BLOB    NOT NULL CHECK (length(lease_id) = 16),
    owner_account_id    BLOB    NOT NULL CHECK (length(owner_account_id) = 16),
    owner_device_id     BLOB    NOT NULL CHECK (length(owner_device_id) = 16),
    fencing_token       INTEGER NOT NULL CHECK (fencing_token BETWEEN 1 AND 9223372036854775807),
    base_version        INTEGER NOT NULL CHECK (base_version BETWEEN 0 AND 9223372036854775807),
    acquired_at_ms      INTEGER NOT NULL CHECK (acquired_at_ms BETWEEN 0 AND 9223372036854775807),
    expires_at_ms       INTEGER NOT NULL CHECK (expires_at_ms BETWEEN 0 AND 9223372036854775807),
    -- The idempotency key of the publish or checkout that granted the lease.
    checkout_request_id BLOB    NOT NULL CHECK (length(checkout_request_id) = 16),
    PRIMARY KEY (tenant_id, profile_id),
    UNIQUE (tenant_id, lease_id),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES v2_profiles(tenant_id, id) ON DELETE CASCADE
);

-- L1098: the fence is monotonic, and a lease is granted under the fence its
-- own transaction just took.
CREATE TRIGGER v2_profiles_fence_moves_forward
BEFORE UPDATE OF last_fencing_token ON v2_profiles
WHEN NEW.last_fencing_token < OLD.last_fencing_token
BEGIN
    SELECT RAISE(ABORT, 'a profile fence never moves back');
END;

CREATE TRIGGER v2_profile_leases_hold_the_newest_fence
BEFORE INSERT ON v2_profile_leases
WHEN NEW.fencing_token IS NOT (SELECT last_fencing_token FROM v2_profiles
                                WHERE tenant_id = NEW.tenant_id AND id = NEW.profile_id)
BEGIN
    SELECT RAISE(ABORT, 'a lease holds its profile''s newest fence');
END;

-- Renew moves only the expiry.
CREATE TRIGGER v2_profile_leases_terms_are_fixed
BEFORE UPDATE OF tenant_id, profile_id, lease_id, owner_account_id, owner_device_id,
                 fencing_token, base_version, acquired_at_ms, checkout_request_id
ON v2_profile_leases
BEGIN
    SELECT RAISE(ABORT, 'a lease keeps the terms it was granted with');
END;

-- The three mutations commit with their responses, like those of 0020-0023.
CREATE TRIGGER v2_idempotency_profile_publish_create_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'PROFILE_PUBLISH_CREATE' OR NEW.operation_scope = 'profile.publish-create.v2')
 AND (NEW.operation_kind IS NOT 'PROFILE_PUBLISH_CREATE'
      OR NEW.operation_scope IS NOT 'profile.publish-create.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'ProfilePublishCreateResponseV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a profile publish is stored with its response');
END;

CREATE TRIGGER v2_idempotency_profile_checkout_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'PROFILE_CHECKOUT' OR NEW.operation_scope = 'profile.checkout.v2')
 AND (NEW.operation_kind IS NOT 'PROFILE_CHECKOUT'
      OR NEW.operation_scope IS NOT 'profile.checkout.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'ProfileCheckoutResponseV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a profile checkout is stored with its response');
END;

CREATE TRIGGER v2_idempotency_release_lease_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'RELEASE_LEASE' OR NEW.operation_scope = 'profile.release-lease.v2')
 AND (NEW.operation_kind IS NOT 'RELEASE_LEASE'
      OR NEW.operation_scope IS NOT 'profile.release-lease.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'ReleaseLeaseResponseV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a lease release is stored with its response');
END;
