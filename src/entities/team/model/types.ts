/** Fleet enrolment and key-custody state, as `team_status` reports it. */
export type TeamStatus = {
  server_url: string;
  tenant_id: string;
  device_id: string;
  has_token: boolean;
  is_enrolled: boolean;
  /**
   * Whether profile sync can run. False for a device enrolled before sync
   * existed, which needs re-enrolling to learn its account id.
   */
  can_sync: boolean;
  /**
   * Whether this device can receive key custody. False for a device enrolled
   * before the HPKE seed was persisted: the server holds its public key, but
   * the private half was discarded, so grants sealed to it can never be
   * opened. Such a device must re-enroll.
   */
  can_receive_custody: boolean;
  /**
   * Always false: push seals under the team passphrase, never a fleet key
   * cached from the server, until verified key distribution ships.
   */
  has_fleet_key: boolean;
};

/** What `team_collect_custody` found waiting on the server. */
export type CustodyResult = {
  /** Grants the server holds for this device. */
  grants: number;
  /** Of those, how many this device could actually open. */
  opened: number;
  /** How many failed to open — a key mismatch, not a transport error. */
  failed: number;
  /** Highest root generation among the opened grants, if any. */
  newest_generation: number | null;
  /** Always 0: fleet key grants from the server are counted, not opened. */
  fleet_opened: number;
  /** Always 0, for the same reason. */
  fleet_failed: number;
  /** Always null, for the same reason. */
  newest_fleet_generation: number | null;
  /**
   * Fleet key grants the server holds for this device. They are not accepted
   * until verified key distribution ships; sync uses the team passphrase.
   */
  fleet_grants_waiting: number;
  /** Always false, for the same reason. */
  can_sync_without_passphrase: boolean;
};
