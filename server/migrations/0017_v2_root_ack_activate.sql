-- Plan 5.6.4 and 5.6.5: the root grant acknowledgement and the generation
-- activation, written by `POST .../grants/{replay_id}/ack` and
-- `POST .../root-key-generations/{generation}/activate`.

-- Each commits with its response, as 0016 holds ROOT_GENERATION_CREATE.
CREATE TRIGGER v2_idempotency_root_grant_ack_is_complete
BEFORE INSERT ON v2_idempotency
WHEN NEW.operation_kind = 'ROOT_GRANT_ACK'
 AND (NEW.operation_scope IS NOT 'tenant.root-grant-ack.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'TenantRootGrantAckedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a root grant acknowledgement is stored with its response');
END;

CREATE TRIGGER v2_idempotency_root_generation_activate_is_complete
BEFORE INSERT ON v2_idempotency
WHEN NEW.operation_kind = 'ROOT_GENERATION_ACTIVATE'
 AND (NEW.operation_scope IS NOT 'tenant.root-generation-activate.v2'
      OR NEW.status IS NOT 'succeeded'
      OR NEW.response_record_type IS NOT 'TenantRootGenerationActivatedV2'
      OR NEW.exact_response_bytes IS NULL
      OR NEW.exact_response_bytes_sha256 IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'a root generation activation is stored with its response');
END;

-- A generation only moves forward, PREPARING to ACTIVE to RETIRED; it is
-- ACTIVE only with the time it became so, and each time is written once.
CREATE TRIGGER v2_root_key_generations_state_moves_forward
BEFORE UPDATE OF state, activated_at, retired_at ON v2_root_key_generations
WHEN (CASE NEW.state WHEN 'PREPARING' THEN 0 WHEN 'ACTIVE' THEN 1 ELSE 2 END)
   < (CASE OLD.state WHEN 'PREPARING' THEN 0 WHEN 'ACTIVE' THEN 1 ELSE 2 END)
  OR (NEW.state = 'ACTIVE' AND NEW.activated_at IS NULL)
  OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS NOT OLD.activated_at)
  OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS NOT OLD.retired_at)
BEGIN
    SELECT RAISE(ABORT, 'a root generation only moves forward, and its times are written once');
END;
