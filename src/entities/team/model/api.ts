import { invoke } from "@tauri-apps/api/core";
import type { TeamStatus, CustodyResult, CustodyBootstrapStatus } from "./types";

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

/** Ask the server who it is; returns its identity. */
export const teamTestConnection = () => invoke<string>("team_test_connection");

/**
 * Enrol this device as the given v2 account, keeping its signing and HPKE keys
 * locally. The password is used for one login and never stored.
 */
export const teamEnrollDevice = (label: string, username: string, password: string) =>
  invoke<TeamStatus>("team_enroll_device", { label, username, password });

/**
 * Collect the root key grants issued to this device. Reports whether custody
 * is in place; the key itself never leaves the backend.
 */
export const teamCollectCustody = () =>
  invoke<CustodyResult>("team_collect_custody");

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
