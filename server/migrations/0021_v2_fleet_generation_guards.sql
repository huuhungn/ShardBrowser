-- ADR 0002 D-9: the database keeps what the fleet lifecycle routes check.
--
-- 0020 added the D-9 terms to v2_fleet_key_generations but left them, and the
-- generation state, writable. Activation compares the acknowledged grants with
-- these terms, so a later write could change what activation accepts. This
-- migration mirrors the root generation triggers (0016, 0017), bounds each
-- fleet grant table by its D-6 window, and keeps the legacy self-grant path out
-- of D-9 generations.

-- ------------------------------------------------------------- generations ---

CREATE TRIGGER v2_fleet_key_generations_terms_are_fixed
BEFORE UPDATE OF server_instance_id, tenant_id, fleet_id, generation, fkek_key_id,
                 root_generation, required_device_grant_count, required_grant_set_hash,
                 recovery_grant_hash, previous_fkek_key_id, rotation_grant_hash
ON v2_fleet_key_generations
BEGIN
    SELECT RAISE(ABORT, 'a fleet generation keeps the terms it was created with');
END;

CREATE TRIGGER v2_fleet_key_generations_state_moves_forward
BEFORE UPDATE OF state, activated_at, retired_at ON v2_fleet_key_generations
WHEN (CASE NEW.state WHEN 'PREPARING' THEN 0 WHEN 'ACTIVE' THEN 1 ELSE 2 END)
   < (CASE OLD.state WHEN 'PREPARING' THEN 0 WHEN 'ACTIVE' THEN 1 ELSE 2 END)
  OR (NEW.state = 'ACTIVE' AND NEW.activated_at IS NULL)
  OR (NEW.state = 'PREPARING' AND NEW.activated_at IS NOT NULL)
  OR (NEW.state = 'RETIRED' AND NEW.retired_at IS NULL)
  OR (NEW.state <> 'RETIRED' AND NEW.retired_at IS NOT NULL)
  OR (OLD.activated_at IS NOT NULL AND NEW.activated_at IS NOT OLD.activated_at)
  OR (OLD.retired_at IS NOT NULL AND NEW.retired_at IS NOT OLD.retired_at)
BEGIN
    SELECT RAISE(ABORT, 'a fleet generation only moves forward, and its times are written once');
END;

-- A legacy row carries no D-9 terms. A D-9 row carries all three, and the
-- rotation pair exactly when it is not generation 0.
CREATE TRIGGER v2_fleet_key_generations_terms_are_complete
BEFORE INSERT ON v2_fleet_key_generations
WHEN (NEW.required_device_grant_count IS NULL) <> (NEW.required_grant_set_hash IS NULL)
  OR (NEW.required_device_grant_count IS NULL) <> (NEW.recovery_grant_hash IS NULL)
  OR (NEW.previous_fkek_key_id IS NULL) <> (NEW.rotation_grant_hash IS NULL)
  OR (NEW.required_device_grant_count IS NULL AND NEW.previous_fkek_key_id IS NOT NULL)
  OR (NEW.required_device_grant_count IS NOT NULL
      AND (NEW.previous_fkek_key_id IS NULL) <> (NEW.generation = 0))
BEGIN
    SELECT RAISE(ABORT, 'a fleet generation carries all of its D-9 terms or none');
END;

-- A D-9 generation activates only through FLEET_GENERATION_ACTIVATE, which the
-- legacy self-grant would bypass.
CREATE TRIGGER v2_fleet_key_grants_not_for_d9_generations
BEFORE INSERT ON v2_fleet_key_grants
WHEN EXISTS (SELECT 1 FROM v2_fleet_key_generations g
              WHERE g.server_instance_id = NEW.server_instance_id
                AND g.tenant_id = NEW.tenant_id
                AND g.fleet_id = NEW.fleet_id
                AND g.generation = NEW.fleet_generation
                AND g.required_device_grant_count IS NOT NULL)
BEGIN
    SELECT RAISE(ABORT, 'a D-9 fleet generation takes no legacy grant');
END;

-- -------------------------------------------------- D-6 grant windows ---

CREATE TRIGGER v2_fleet_device_hpke_grants_window_is_bounded
BEFORE INSERT ON v2_fleet_device_hpke_grants
WHEN NEW.not_after_ms - NEW.not_before_ms > 31536000000
BEGIN
    SELECT RAISE(ABORT, 'a device grant window is at most 365 days');
END;

CREATE TRIGGER v2_fleet_recovery_grants_window_is_bounded
BEFORE INSERT ON v2_fleet_recovery_grants
WHEN NEW.not_after_ms - NEW.not_before_ms > 315360000000
BEGIN
    SELECT RAISE(ABORT, 'a recovery grant window is at most 3650 days');
END;

CREATE TRIGGER v2_fleet_rotation_grants_window_is_bounded
BEFORE INSERT ON v2_fleet_rotation_grants
WHEN NEW.not_after_ms - NEW.not_before_ms > 2592000000
BEGIN
    SELECT RAISE(ABORT, 'a rotation grant window is at most 30 days');
END;
