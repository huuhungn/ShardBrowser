/** Fleet enrolment and key-custody state, as `team_status` reports it. */
export type TeamStatus = {
  server_url: string;
  tenant_id: string;
  device_id: string;
  /**
   * This device's own signing and HPKE key IDs, which `confirm-first-device`
   * asks the operator to compare. Empty while its seeds cannot be read.
   */
  signing_key_id: string;
  hpke_key_id: string;
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
   * Whether this device holds a fleet key whose grant still verifies against
   * the anchor it pinned, the key published profiles sync under.
   */
  has_fleet_key: boolean;
  /**
   * Whether this device holds such a key but Q-18 blocks sealing under it,
   * so push is refused until a custodian rotates the fleet key.
   */
  fleet_key_blocked: boolean;
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
  /**
   * An enrolled seed is gone for good: the device can only be reset, or for
   * the root custodian, restored by importing its recovery bundle.
   */
  keys_lost: boolean;
  /** The OS credential store did not answer for an enrolled seed; try again before resetting. */
  key_store_unavailable: boolean;
};

/** How far `team_bootstrap_custody` got; none of its secrets. */
export type CustodyBootstrapStatus = {
  /** Some step ran, so the next attempt resumes rather than starts over. */
  started: boolean;
  /** The started state is this device's in its saved tenant: only then is it the root custodian. */
  this_device: boolean;
  activated: boolean;
  /** Where the recovery bundle was written; empty until it was. */
  recovery_path: string;
  /** The bootstrap anchor the trust evidence verified to; empty until then. */
  anchor: string;
  /** The recovery fingerprint, the activated root's key ID; empty until then. */
  root_key_id: string;
};

/** What `team_collect_custody` found waiting on the server. */
export type CustodyResult = {
  /** Root key grants the server holds for this device. */
  grants: number;
  /** Of those, how many this device could actually open. */
  opened: number;
  /** How many failed to open — a key mismatch, not a transport error. */
  failed: number;
  /** Highest root generation among the opened grants, if any. */
  newest_generation: number | null;
  /** 1 when the fleet key grant verified, opened and was kept. */
  fleet_opened: number;
  /** 1 when a filed fleet key grant did not verify, open or fetch its evidence. */
  fleet_failed: number;
  /** The generation of the kept fleet key, if one was kept. */
  newest_fleet_generation: number | null;
  /**
   * 1 when a fleet key grant is filed but was not kept: this device pins no
   * anchor yet (confirm its join code first), or the grant was refused.
   */
  fleet_grants_waiting: number;
  /** `KEY_SUBSTITUTION_DETECTED` when this device already holds another key for that generation. */
  fleet_refusal: string | null;
  /** The grant is more than one generation above the newest kept: this device missed rotations and must enroll again. */
  fleet_enroll_again: boolean;
  /** Always false: the passphrase path is legacy only. */
  can_sync_without_passphrase: boolean;
};

/** How far Create fleet key got, as `team_fleet_custody_status` reports it; no secret. */
export type FleetCustodyStatus = {
  /** Some step ran, so a new attempt resumes rather than starts over. */
  started: boolean;
  /** Generation 0 was built; it is done once its setup key is released. */
  created: boolean;
  setup_key_held: boolean;
  /** The public id of the fleet key, once it was made. */
  fkek_key_id: string;
  /** The latest fleet key rotation, if any. */
  rotation: FleetRotationStatus | null;
  /** A revocation of a device that held the current fleet key asks for a rotation (ADR 0002 Q-20). */
  rotation_required: "urgent" | "routine" | null;
  /** A finished rotation asks for the recovery bundle to be exported again. */
  export_due: boolean;
};

/** How far the latest fleet key rotation got; no secret. */
export type FleetRotationStatus = {
  generation: number;
  /** `preparing` and `activated` are unfinished; `expired` can no longer activate. */
  phase: "preparing" | "activated" | "done" | "expired";
  /** When the rotation can no longer activate, once known. */
  deadline_ms: number | null;
  members_filed: number;
  members_refused: number;
  members_skipped: number;
  /** An activated rotation's member whose grant keeps failing, which Skip member leaves out. */
  failing_member: string | null;
};

/** A bound profile whose head here is still sealed under an older fleet key. */
export type OlderKeyProfile = {
  profile_id: string;
  key_generation: number;
};

/** A device of the tenant, as `team_devices` lists it for the root custodian. */
export type TeamDevice = {
  device_id: string;
  account_id: string;
  /** The server's status: `pending`, `active` or `revoked`. */
  status: string;
  label: string;
  signing_key_id: string;
  hpke_key_id: string;
  /** The code the joining device must show, computed from this custodian's pin. */
  sas: string;
  /** For a pending device: until when it may be approved, by this computer's clock. */
  approve_until_ms: number | null;
  /** This custodian's trust ledger counts the row's key as a root custodian: no `compromised`. */
  custodian: boolean;
};

/** What `team_join_code` shows on a joining device while its window is open. */
export type TeamJoinCode = {
  sas: string;
  /** The bootstrap anchor A0 the tenant's evidence verifies to. */
  anchor: string;
  signing_key_id: string;
  hpke_key_id: string;
  /** The end of this device's join window, by its own clock. */
  expires_at_ms: number;
};

/** The reasons Revoke offers. */
export type TeamRevokeReason = "retired" | "lost" | "compromised";

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
