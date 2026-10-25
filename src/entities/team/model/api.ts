import { invoke } from "@tauri-apps/api/core";
import type { TeamStatus, CustodyResult } from "./types";

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
