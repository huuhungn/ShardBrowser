import { invoke } from "@tauri-apps/api/core";
import type { ProfileMeta } from "./types";

export const profileList = () => invoke<ProfileMeta[]>("profile_list");
export const profileGet = (id: string) => invoke<any>("profile_get", { id });
export const profileSave = (payload: any) => invoke<ProfileMeta>("profile_save", { payload });
/// Rejects names the profile directory cannot hold, before anything persists.
export const profileValidateName = (name: string, id?: string | null) =>
  invoke<string>("profile_validate_name", { name, id: id || null });
export const profileDelete = (id: string) => invoke("profile_delete", { id });
export const profileClone = (id: string) => invoke<ProfileMeta>("profile_clone", { id });
export const profileSetPin = (id: string, pinned: boolean) => invoke("profile_set_pin", { id, pinned });
export const profileSetFolder = (id: string, folder: string) => invoke("profile_set_folder", { id, folder });
export const profileBindProxy = (profileId: string, proxyId: string | null) => invoke("profile_bind_proxy", { profileId, proxyId });
export const profileImport = (payloads: any[]) => invoke<number>("profile_import", { payloads });
export const profileCreateFromTemplate = (templateId: string) => invoke<ProfileMeta>("profile_create_from_template", { templateId });
export type CdpInfo = { port: number; http_url: string; ws_url: string | null };
export type DevtoolsTarget = { devtools_frontend_url: string | null };
export type DevtoolsContext = {
  cdp: CdpInfo;
  targets: DevtoolsTarget[];
  current: DevtoolsTarget | null;
};

export const processList = () =>
  invoke<{ profile_id: string; pid: number; uptime_ms: number; cdp?: CdpInfo }[]>("process_list");
export const devtoolsContext = (profileId: string) =>
  invoke<DevtoolsContext>("devtools_context", { profileId });
/** Raises the profile's current page — used to surface a verification prompt. */
export const devtoolsActivate = (profileId: string) =>
  invoke<DevtoolsTarget>("devtools_activate", { profileId });
export const processKill = (profileId: string) => invoke<boolean>("process_kill", { profileId });
export const launch = (profileId: string) => invoke<number>("launch", { profileId });
/** Stop a launch that has not started its browser yet. */
export const launchCancel = (profileId: string) => invoke("launch_cancel", { profileId });

/** A group of profiles that mirror each other's input. Returns the group name. */
export const syncLaunch = (profileIds: string[], group?: string) =>
  invoke<string>("sync_launch", { profileIds, group });

export type SyncMember = { profile: string; excluded: boolean; driving: boolean };
export type SyncStatus = { group: string; members: SyncMember[]; paused: boolean };
export type SyncLayout = "row" | "grid" | "cascade";

export const syncStatus = (group: string) => invoke<SyncStatus>("sync_status", { group });
export const syncSetPaused = (group: string, paused: boolean) =>
  invoke<void>("sync_set_paused", { group, paused });
export const syncArrange = (group: string, layout: SyncLayout) =>
  invoke<void>("sync_arrange", { group, layout });
export const syncStop = (group: string) => invoke<void>("sync_stop", { group });
export const syncSetExcluded = (group: string, profile: string, excluded: boolean) =>
  invoke<void>("sync_set_excluded", { group, profile, excluded });
export const syncClosePanel = () => invoke<void>("sync_close_panel");

export type HelperField = { kind: string; select: boolean; x: number; y: number };
export type HelperReport = { fields: HelperField[] } | null;

export const helperProfiles = () => invoke<string[]>("helper_profiles");
export const helperFields = (profile: string) => invoke<HelperReport>("helper_fields", { profile });
/** Returns how many windows were told to fill — the whole group, when in one. */
export const helperFill = (profile: string) => invoke<number>("helper_fill", { profile });
export const helperShow = (profile: string) => invoke<void>("helper_show", { profile });
export const helperClose = () => invoke<void>("helper_close");
/** The operator closed the panel — a refusal about this page only. */
export const helperDismiss = (profile: string) => invoke<void>("helper_dismiss", { profile });
export const folderDelete = (folder: string, deleteProfiles: boolean) => invoke<number>("folder_delete", { folder, deleteProfiles });
export const cookiesExportToFile = (profileId: string, path: string) => invoke<number>("cookies_export_to_file", { profileId, path });
export const cookiesImport = (profileId: string, cookies: any[]) => invoke<number>("cookies_import", { profileId, cookies });
export const enrichPicksForPreset = (presetId: string) => invoke<{ hardware_concurrency?: number; device_memory?: number; platform_version?: string }>("enrich_picks_for_preset", { presetId });
export const hostPlatform = () => invoke<string>("host_platform");

/** What the team server holds for a profile, or null if it has nothing. */
export type RemoteSnapshot = { version: number; container_bytes: number; sha256?: string };
export type PushResult = { version: number; container_bytes: number; sha256: string };

export const profileSyncStatus = (profileId: string) =>
  invoke<RemoteSnapshot | null>("profile_sync_status", { profileId });
/** `baseVersion` is the version being replaced; the server refuses a stale base. */
export const profileSyncPush = (profileId: string, passphrase: string, baseVersion: number) =>
  invoke<PushResult>("profile_sync_push", { profileId, passphrase, baseVersion });
export const profileSyncPull = (profileId: string, passphrase: string) =>
  invoke<number>("profile_sync_pull", { profileId, passphrase });

export type BackupResult = { file_bytes: number; sha256: string };

export const profileBackupCreate = (profileId: string, destPath: string, passphrase: string) =>
  invoke<BackupResult>("profile_backup_create", { profileId, destPath, passphrase });
/** Validates the container before a passphrase is asked for. */
export const profileBackupInspect = (srcPath: string) =>
  invoke<unknown>("profile_backup_inspect", { srcPath });
export const profileBackupRestore = (profileId: string, srcPath: string, passphrase: string) =>
  invoke<number>("profile_backup_restore", { profileId, srcPath, passphrase });
