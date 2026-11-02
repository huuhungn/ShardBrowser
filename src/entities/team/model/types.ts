/** Fleet enrolment and key-custody state, as `team_status` reports it. */
export type TeamStatus = {
  server_url: string;
  tenant_id: string;
  device_id: string;
  has_token: boolean;
  /** False when the stored keys cannot be opened, so enrollment is offered. */
  is_enrolled: boolean;
  /** The stored keys were protected by another Windows account or machine. */
  keys_unreadable: boolean;
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

/** A `profile_bindings` sync state. */
export type TeamSyncState =
  | "LOCAL"
  | "AVAILABLE"
  | "CHECKED_OUT"
  | "LEASE_AT_RISK"
  | "OFFLINE_FORK"
  | "UPLOADING"
  | "RESTORE_REQUIRED"
  | "CONFLICT"
  | "QUARANTINED";

/** One bound profile, as `team_profiles_status` reports it. A profile with no entry is local. */
export type TeamProfileStatus = {
  profile_id: string;
  sync_state: TeamSyncState;
  remote_version: number;
  dirty: boolean;
  lease_expires_at: string | null;
  /** Why a quarantined binding is quarantined. */
  last_error_code: string | null;
  /** `LEASE_AT_RISK`, or a lease whose expiry has passed. */
  lease_at_risk: boolean;
  /** An unresolved proven-revoked run can be reverted. */
  revert_available: boolean;
  /** A revert holds the lease. */
  revert_in_progress: boolean;
};

/** A tenant-wide custodian alert. */
export type TeamCustodianAlert = {
  kind: "custodian.renewed_after_revocation";
  signing_key_id: string;
  raised_at_ms: number;
};

/** What `team_profiles_status` reads from this device's team database. */
export type TeamProfilesStatus = {
  profiles: TeamProfileStatus[];
  /** Newest first. */
  alerts: TeamCustodianAlert[];
};

/** One profile the fleet lists, as `team_fleet_profiles` reports it. */
export type TeamFleetProfile = {
  remote_profile_id: string;
  current_version: number;
  /** Null when no fleet key this device holds opens it. */
  label: string | null;
  /** The local profile bound to it on this device, if any. */
  bound_to: string | null;
};
