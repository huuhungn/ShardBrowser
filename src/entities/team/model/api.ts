import { invoke } from "@tauri-apps/api/core";
import type {
  TeamStatus, CustodyResult, CustodyBootstrapStatus, TeamProfilesStatus, TeamFleetProfile,
  FleetCustodyStatus, TeamDevice, TeamJoinCode, TeamRevokeReason,
} from "./types";

export const teamStatus = () => invoke<TeamStatus>("team_status");

/**
 * Save the connection. Changing server or tenant clears the device identity,
 * because keys enrolled against one fleet mean nothing to another.
 */
export const teamSetConnection = (
  serverUrl: string,
  token: string,
  tenantId: string,
) => invoke<TeamStatus>("team_set_connection", { serverUrl, token, tenantId });

/**
 * Ask the server who it is with a ticket of the given v2 account; returns its
 * identity. The password is used for one login and never stored.
 */
export const teamTestConnection = (username: string, password: string) =>
  invoke<string>("team_test_connection", { username, password });

/**
 * Enrol this device as the given v2 account, keeping its signing and HPKE keys
 * locally. The password is used for one login and never stored.
 */
export const teamEnrollDevice = (label: string, username: string, password: string) =>
  invoke<TeamStatus>("team_enroll_device", { label, username, password });

/**
 * Collect the root key grants issued to this device. Reports whether custody
 * is in place; the key itself never leaves the backend. A fleet grant is read
 * through this device's own session, so the password is used for one login
 * and never stored.
 */
export const teamCollectCustody = (username: string, password: string) =>
  invoke<CustodyResult>("team_collect_custody", { username, password });

/**
 * Create the passphrase-protected key file for a device whose OS credential
 * store cannot hold its keys, and move the keys into it.
 */
export const teamKeysCreateFile = (passphrase: string) =>
  invoke<TeamStatus>("team_keys_create_file", { passphrase });

/** Open the key file for this run, so the keys in it can be used. */
export const teamKeysUnlock = (passphrase: string) =>
  invoke<TeamStatus>("team_keys_unlock", { passphrase });

/** How far this device's first-device custody setup got. */
export const teamCustodyBootstrapStatus = () =>
  invoke<CustodyBootstrapStatus>("team_custody_bootstrap_status");

/**
 * Set up root custody as the tenant's first device, or resume it. The
 * recovery bundle is written to `recoveryPath` under `passphrase`; a resumed
 * run keeps the bundle it already wrote and needs the same passphrase.
 */
export const teamBootstrapCustody = (
  username: string,
  password: string,
  recoveryPath: string,
  passphrase: string,
) =>
  invoke<CustodyBootstrapStatus>("team_bootstrap_custody", {
    username, password, recoveryPath, passphrase,
  });

/** How far this device's Create fleet key got. */
export const teamFleetCustodyStatus = () =>
  invoke<FleetCustodyStatus>("team_fleet_custody_status");

/**
 * Create the fleet key as the tenant's root custodian, or resume it. The
 * password is used for one login and never stored.
 */
export const teamFleetKeySetup = (username: string, password: string) =>
  invoke<FleetCustodyStatus>("team_fleet_key_setup", { username, password });

/** The tenant's devices with the code each must show, for the root custodian. */
export const teamDevices = (username: string, password: string) =>
  invoke<TeamDevice[]>("team_devices", { username, password });

/** Approve the pending device once the user confirmed it shows `sas`. */
export const teamApproveDevice = (username: string, password: string, deviceId: string, sas: string) =>
  invoke<void>("team_approve_device", { username, password, deviceId, sas });

/** Revoke the tenant's device as retired or lost. */
export const teamRevokeDevice = (
  username: string,
  password: string,
  deviceId: string,
  reason: TeamRevokeReason,
) => invoke<void>("team_revoke_device", { username, password, deviceId, reason });

/** This device's join code, while its join window is open. */
export const teamJoinCode = (username: string, password: string) =>
  invoke<TeamJoinCode>("team_join_code", { username, password });

/** Pin the anchor shown beside the code the user confirmed matches, inside the join window. */
export const teamJoinConfirm = (username: string, password: string, anchor: string, sas: string) =>
  invoke<void>("team_join_confirm", { username, password, anchor, sas });

/** Clear this device's identity so it can enroll again, as the server allows. */
export const teamEnrollAgain = (username: string, password: string) =>
  invoke<TeamStatus>("team_enroll_again", { username, password });

/** Every bound profile's sync state and every custodian alert; no server is asked. */
export const teamProfilesStatus = () => invoke<TeamProfilesStatus>("team_profiles_status");

/** Every profile this device's fleet lists, with its label; nothing is written. */
export const teamFleetProfiles = (username: string, password: string) =>
  invoke<TeamFleetProfile[]>("team_fleet_profiles", { username, password });

/**
 * Bind the stopped, unbound local profile to a fleet profile and pull it.
 * Returns the bytes restored. The password is used for one login and never stored.
 */
export const teamJoinProfile = (
  remoteProfileId: string,
  localProfileId: string,
  username: string,
  password: string,
) =>
  invoke<number>("team_join_profile", {
    remoteProfileId, localProfileId, username, password,
  });

/**
 * Publish the local profile as a new fleet profile, listed under its name.
 * The password is used for one login and never stored.
 */
export const teamPublishProfile = (profileId: string, username: string, password: string) =>
  invoke<unknown>("profile_sync_publish", { profileId, label: null, username, password });

/** End an unfinished publish that keeps being refused; nothing is sent. */
export const teamCancelPublish = (profileId: string) =>
  invoke<void>("profile_sync_cancel_publish", { profileId });

// A published profile ignores the passphrase and base version: it seals under
// the fleet key and takes its base from the binding (sync_cmd.rs).
/** Check in (push) a published profile. */
export const teamCheckIn = (profileId: string, username: string, password: string) =>
  invoke<unknown>("profile_sync_push", { profileId, passphrase: "", baseVersion: 0, username, password });

/** Pull a published profile's current snapshot over the local one. */
export const teamPull = (profileId: string, username: string, password: string) =>
  invoke<number>("profile_sync_pull", { profileId, passphrase: "", username, password });

/** Commit the last valid snapshot over a run of heads whose signers are proven revoked. */
export const teamRevert = (profileId: string, username: string, password: string) =>
  invoke<unknown>("profile_sync_revert", { profileId, username, password });

/** Unbind the stopped profile from its fleet profile; it stays a local profile. */
export const teamUnbindProfile = (profileId: string) =>
  invoke<unknown>("team_unbind_profile", { profileId });
