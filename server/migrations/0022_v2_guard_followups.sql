-- Review follow-ups for #166/#167/#168.
--
-- The five mutations added after 0020 commit with their responses, like the
-- ones 0020 guards, and a fleet key generation is history: never removed or
-- replaced, only moved forward by 0021's state trigger. Like the grant tables
-- (0020), this means a tenant or fleet that has a generation is never deleted
-- by cascade.

CREATE TRIGGER v2_idempotency_root_grant_create_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'ROOT_GRANT_CREATE' OR NEW.operation_scope = 'tenant.root-grant-create.v2')
 AND (NEW.operation_kind IS NOT 'ROOT_GRANT_CREATE'
      OR NEW.operation_scope IS NOT 'tenant.root-grant-create.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'TenantRootGrantCreatedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a root grant filing is stored with its response');
END;

CREATE TRIGGER v2_idempotency_root_grant_revoke_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'ROOT_GRANT_REVOKE' OR NEW.operation_scope = 'tenant.root-grant-revoke.v2')
 AND (NEW.operation_kind IS NOT 'ROOT_GRANT_REVOKE'
      OR NEW.operation_scope IS NOT 'tenant.root-grant-revoke.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'TenantRootGrantRevokedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a root grant revocation is stored with its response');
END;

CREATE TRIGGER v2_idempotency_fleet_grant_ack_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'FLEET_GRANT_ACK' OR NEW.operation_scope = 'fleet.key-grant-ack.v2')
 AND (NEW.operation_kind IS NOT 'FLEET_GRANT_ACK'
      OR NEW.operation_scope IS NOT 'fleet.key-grant-ack.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'FleetKeyGrantAckedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a fleet grant acknowledgement is stored with its response');
END;

CREATE TRIGGER v2_idempotency_fleet_generation_activate_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'FLEET_GENERATION_ACTIVATE' OR NEW.operation_scope = 'fleet.key-generation-activate.v2')
 AND (NEW.operation_kind IS NOT 'FLEET_GENERATION_ACTIVATE'
      OR NEW.operation_scope IS NOT 'fleet.key-generation-activate.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'FleetKeyGenerationActivatedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a fleet generation activation is stored with its response');
END;

CREATE TRIGGER v2_idempotency_fleet_grant_revoke_is_complete
BEFORE INSERT ON v2_idempotency
WHEN (NEW.operation_kind = 'FLEET_GRANT_REVOKE' OR NEW.operation_scope = 'fleet.key-grant-revoke.v2')
 AND (NEW.operation_kind IS NOT 'FLEET_GRANT_REVOKE'
      OR NEW.operation_scope IS NOT 'fleet.key-grant-revoke.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'FleetGrantRevokedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a fleet grant revocation is stored with its response');
END;

CREATE TRIGGER v2_fleet_key_generations_no_delete
BEFORE DELETE ON v2_fleet_key_generations
BEGIN
    SELECT RAISE(ABORT, 'a fleet key generation is never deleted');
END;

CREATE TRIGGER v2_fleet_key_generations_no_replace
BEFORE INSERT ON v2_fleet_key_generations
WHEN EXISTS (SELECT 1 FROM v2_fleet_key_generations g
              WHERE g.server_instance_id = NEW.server_instance_id
                AND g.tenant_id = NEW.tenant_id AND g.fleet_id = NEW.fleet_id
                AND g.generation = NEW.generation)
BEGIN
    SELECT RAISE(ABORT, 'a fleet key generation is never replaced');
END;
