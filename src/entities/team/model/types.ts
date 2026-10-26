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
  /** True when this device holds a fleet key, so sync needs no passphrase. */
  has_fleet_key: boolean;
  /**
   * Whether every key this device holds is in the OS credential store. False
   * while a key is still in plaintext on disk because no store was usable.
   */
  keys_protected: boolean;
  /** Whether this device has a passphrase-protected key file. */
  has_key_file: boolean;
  /**
   * Whether that file was not opened in this run yet: keys kept in it cannot
   * be used until the passphrase is entered.
   */
  keys_locked: boolean;
};

/** How far `team_bootstrap_custody` got; none of its secrets. */
export type CustodyBootstrapStatus = {
  /** Some step ran, so the next attempt resumes rather than starts over. */
  started: boolean;
  activated: boolean;
  /** Where the recovery bundle was written; empty until it was. */
  recovery_path: string;
  /** The bootstrap anchor the trust evidence verified to; empty until then. */
  anchor: string;
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
  /** Fleet key grants opened. These hold the key sync actually uses. */
  fleet_opened: number;
  /** Fleet grants that failed to open. */
  fleet_failed: number;
  /** Highest fleet generation among the opened fleet grants, if any. */
  newest_fleet_generation: number | null;
  /** True once this device holds a fleet key, so sync needs no passphrase. */
  can_sync_without_passphrase: boolean;
};
