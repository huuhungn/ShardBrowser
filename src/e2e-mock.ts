import { mockIPC, mockWindows } from "@tauri-apps/api/mocks";
import type { InvokeArgs } from "@tauri-apps/api/core";
import type {
  TeamFleetProfile, TeamProfileStatus, TeamProfilesStatus, HandoverStatus,
} from "./entities/team/model/types";

type Profile = {
  id: string;
  name: string;
  notes: string;
  proxy_id: string | null;
  last_launched_at: string | null;
  created_at: string | null;
  pinned: boolean;
  folder: string;
  total_runtime_ms: number;
  tags: string[];
};

type Proxy = {
  id: string;
  name: string;
  kind: "socks5" | "http" | "https";
  host: string;
  port: number;
  username: string;
  password: string;
  country: string;
  notes: string;
};

const params = new URLSearchParams(location.search);
const scenario = params.get("e2e") ?? "default";
const wait = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
// "slow-launch": a launch that sits in Starting until it is cancelled, the way
// one behind a slow proxy does.
let cancelPendingLaunch: (() => void) | null = null;

const fixtureProfiles: Profile[] = [
  {
    id: "profile-alpha",
    name: "VN Automation 001 - No Proxy",
    notes: "sanitized fixture",
    proxy_id: "proxy-us",
    last_launched_at: "2026-07-01T00:00:00Z",
    created_at: "2026-06-01T00:00:00Z",
    pinned: true,
    folder: "QA",
    total_runtime_ms: 120_000,
    tags: [],
  },
  {
    id: "profile-beta",
    name: "Beta Research",
    notes: "keyboard regression target",
    proxy_id: null,
    last_launched_at: null,
    created_at: "2026-06-02T00:00:00Z",
    pinned: false,
    folder: "",
    total_runtime_ms: 0,
    tags: [],
  },
];
// A second team device starts with nothing but what it joins.
const profiles = scenario === "profiles-empty" || scenario === "team-device-b" ? [] : fixtureProfiles;

// Tags behave like the launcher's: names on each profile, colors on the side,
// kept in sessionStorage so a reload shows what was saved.
type TagState = { byProfile: Record<string, string[]>; colors: Record<string, string> };
const TAGS_KEY = "e2e-tags";
const tagState: TagState = JSON.parse(sessionStorage.getItem(TAGS_KEY) ?? '{"byProfile":{},"colors":{}}');
const saveTags = () => sessionStorage.setItem(TAGS_KEY, JSON.stringify(tagState));
const same = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
const clean = (name: string) => [...name.trim().replace(/\s+/g, " ")].slice(0, 32).join("").trimEnd();
for (const profile of profiles) profile.tags = tagState.byProfile[profile.id] ?? [];
function setProfileTags(id: string, tags: string[]) {
  const known = [...profiles.flatMap((p) => p.tags), ...Object.keys(tagState.colors)];
  const out: string[] = [];
  for (const raw of tags) {
    const name = clean(raw);
    if (!name || out.some((x) => same(x, name))) continue;
    out.push(known.find((k) => same(k, name)) ?? name);
  }
  const profile = profiles.find((p) => p.id === id);
  if (profile) profile.tags = out;
  tagState.byProfile[id] = out;
  saveTags();
  return out;
}
function takeColor(name: string) {
  const key = Object.keys(tagState.colors).find((k) => same(k, name));
  if (!key) return undefined;
  const color = tagState.colors[key];
  delete tagState.colors[key];
  return color;
}
function listTags() {
  const out: { name: string; color: string | null; count: number }[] = [];
  for (const name of profiles.flatMap((p) => p.tags)) {
    const hit = out.find((x) => same(x.name, name));
    if (hit) hit.count += 1;
    else out.push({ name, color: null, count: 1 });
  }
  for (const name of Object.keys(tagState.colors)) {
    if (!out.some((x) => same(x.name, name))) out.push({ name, color: null, count: 0 });
  }
  for (const x of out) {
    x.color = Object.entries(tagState.colors).find(([k]) => same(k, x.name))?.[1] ?? null;
  }
  return out.sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()));
}

const proxies: Proxy[] = scenario === "proxies-empty" ? [] : [
  {
    id: "proxy-us",
    name: "US Sanitize 1",
    kind: "socks5",
    host: "203.0.113.10",
    port: 1080,
    username: "",
    password: "",
    country: "US",
    notes: "RFC 5737 test-net address",
  },
];

const settings = {
  browser_path: null,
  theme: "dark",
  geo_checker: "ip-api.com",
  screen_resolution_mode: "fingerprint",
  minimize_to_tray: true,
  launch_at_login: false,
  start_minimized: true,
  api_enabled: true,
  api_port: 40325,
  mcp_path: "C:\\Users\\Example\\ShardX-MCP",
};

// "fingerprints": a library where two of three cards claim a GPU this machine lacks.
const fingerprints = scenario === "fingerprints" ? [
  { id: "fp-mac", label: "Mac M2 Air", platform: "macOS", chrome: "131", gpu: "Apple M2", tag_color: "", builtin: false, payload: {} },
  { id: "fp-win", label: "Win RTX 3060", platform: "Windows", chrome: "131", gpu: "NVIDIA GeForce RTX 3060", tag_color: "", builtin: false, payload: {} },
  { id: "fp-ref", label: "Windows reference", platform: "Windows", chrome: "130", gpu: "Intel UHD 620", tag_color: "", builtin: true, payload: {} },
] : [];
const mismatch = (profile_renderer: string) =>
  ({ compatible: false, missing_webgl1: ["WEBGL_compressed_texture_astc"], missing_webgl2: [], missing_webgpu: [], profile_renderer });

// The E2E suite runs the production build, so each one-shot fixture fails once.
// "bookmarks": a stored list the page can save back to and delete from, as the launcher's is.
type Bookmark = { id: string; title: string; url: string; folder: string };
const bookmarks: Bookmark[] = scenario === "bookmarks" ? [
  { id: "bm-1", title: "Ads Manager", url: "https://ads.example.com", folder: "" },
  { id: "bm-2", title: "Shop one", url: "https://shop-one.example.com", folder: "QA" },
  { id: "bm-3", title: "Shop two", url: "https://shop-two.example.com", folder: "QA" },
  { id: "bm-4", title: "Docs", url: "https://docs.example.com", folder: "" },
] : [];

let runtimeFailures = scenario === "runtime-error-once" ? 1 : 0;
let runtimeInstallFailures = scenario === "runtime-install-error-once" ? 1 : 0;
let runtimeNeedsInstall = scenario === "runtime-install-error-once";
let profileFailures = scenario === "profile-error-once" ? 1 : 0;
let profileListsInFlight = 0;
let maxProfileListsInFlight = 0;
let proxyListCalls = 0;
let proxyListsInFlight = 0;
let maxProxyListsInFlight = 0;

// __e2eOpenLinks: what the backend queued for open_link_take, set by a test.
// __e2eStartedElsewhere: profiles a test starts behind the UI's back.
type E2EWindow = Window & {
  __resolveUpdateCheck?: () => void;
  __e2eOpenLinks?: (string | null)[];
  __e2eStartedElsewhere?: string[];
};

function updateInfo() {
  const available = params.get("update") !== "none";
  return {
    current: "0.1.29",
    latest: available ? "v0.1.29" : null,
    update_available: available,
    release_url: "https://github.com/huuhungn/ShardBrowser/releases/tag/v0.1.29",
    notes: "Sanitized update fixture.",
    pub_date: "2026-07-18T00:00:00Z",
  };
}

type MockUpdateChannel = {
  onmessage?: (event: unknown) => void;
};

function updateChannel(payload?: InvokeArgs) {
  return (payload as { onEvent?: MockUpdateChannel } | undefined)?.onEvent;
}

function count(name: string) {
  const key = `e2e${name}`;
  const current = Number(document.documentElement.dataset[key] ?? 0) + 1;
  document.documentElement.dataset[key] = String(current);
}

function mcpStatus() {
  return {
    path: settings.mcp_path,
    installed: true,
    files_downloaded: true,
    lockfile_present: true,
    version: "0.1.29",
    version_current: true,
    required_version: "0.1.29",
    dependencies_installed: true,
    api_reachable: true,
    ready: true,
    state: "ready",
    message: "MCP fixture ready.",
  };
}

mockWindows("main");
localStorage.setItem("shardx-star-prompt", "done");
if (scenario === "folder-empty") {
  localStorage.setItem("shardx-folders", JSON.stringify(["Empty QA"]));
}

// "team-profiles": one binding per Team page badge (profile-beta stays local),
// with a proven run, a reported-only quarantine, a revert in progress and a
// custodian alert. "team-profiles-quiet" keeps the bindings without the alert.
const teamLease = "2099-01-01T00:00:00.000Z";
const teamBinding = (
  profile_id: string,
  sync_state: TeamProfileStatus["sync_state"],
  more: Partial<TeamProfileStatus> = {},
): TeamProfileStatus => ({
  profile_id, sync_state, remote_version: 3, dirty: false, lease_expires_at: null,
  last_error_code: null, lease_at_risk: false, revert_available: false, revert_in_progress: false,
  ...more,
});
const teamProfiles: TeamProfilesStatus = scenario === "team-profiles" || scenario === "team-profiles-quiet"
  ? {
    profiles: [
      teamBinding("profile-alpha", "AVAILABLE"),
      teamBinding("team-checked-out", "CHECKED_OUT", { dirty: true, lease_expires_at: teamLease }),
      teamBinding("team-lease-at-risk", "LEASE_AT_RISK", {
        dirty: true, lease_expires_at: teamLease, lease_at_risk: true,
      }),
      teamBinding("team-expired-lease", "CHECKED_OUT", {
        dirty: true, lease_expires_at: "2000-01-01T00:00:00.000Z", lease_at_risk: true,
      }),
      teamBinding("team-uploading", "UPLOADING", { dirty: true, lease_expires_at: teamLease }),
      teamBinding("team-quarantined", "QUARANTINED", { last_error_code: "HEAD_ROLLBACK_DETECTED" }),
      teamBinding("team-proven-run", "QUARANTINED", {
        last_error_code: "SIGNER_REVOKED", revert_available: true,
      }),
      teamBinding("team-reported-only", "QUARANTINED", { last_error_code: "SIGNER_REVOKED" }),
      teamBinding("team-reverting", "CHECKED_OUT", {
        lease_expires_at: teamLease, last_error_code: "SIGNER_REVOKED",
        revert_available: true, revert_in_progress: true,
      }),
    ],
    alerts: scenario === "team-profiles-quiet" ? [] : [{
      kind: "custodian.renewed_after_revocation",
      signing_key_id: "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdeffedcba9876543210f",
      raised_at_ms: 1_800_000_000_000,
    }],
  }
  : { profiles: [], alerts: [] };
for (const { profile_id } of teamProfiles.profiles) {
  if (!profiles.some((p) => p.id === profile_id)) {
    profiles.push({ ...fixtureProfiles[1], id: profile_id, name: profile_id, tags: [] });
  }
}
// What the fleet lists in "team-profiles": one profile bound here, one to
// join, and one whose label no key this device holds opens.
const teamFleet: TeamFleetProfile[] = scenario === "team-profiles"
  ? [
    { remote_profile_id: "c1".repeat(16), current_version: 3, label: "Alpha", bound_to: "profile-alpha" },
    { remote_profile_id: "c2".repeat(16), current_version: 5, label: "Shop", bound_to: null },
    { remote_profile_id: "c3".repeat(16), current_version: 1, label: null, bound_to: null },
  ]
  : [];

// A device enrolled as a tenant's first, before or part-way through custody
// setup. The bootstrap itself is the backend's; the card only drives it.
// `team-key-blocked` also holds a verified fleet key Q-18 blocks sealing under.
const firstDevice = scenario === "team-first-device" || scenario === "team-first-device-resume"
  || scenario === "team-keys-locked" || scenario === "team-key-blocked";
// The resumed setup also stands for a host whose credential store refused the
// keys; `team-keys-locked` for one whose keys sit in a key file not yet opened.
let keyState = scenario === "team-first-device-resume"
  ? { keys_protected: false, has_key_file: false, keys_locked: false }
  : scenario === "team-keys-locked"
    ? { keys_protected: true, has_key_file: true, keys_locked: true }
    : { keys_protected: true, has_key_file: false, keys_locked: false };
// "team-device-a" and "team-device-b": two devices of one fleet (see below).
// "team-keys-lost" and "team-key-store-unavailable" are B enrolled and joined
// as "b0"x16, whose seeds are lost or whose key store does not answer;
// "team-root-keys-lost" and "team-root-key-store-unavailable" are A, the root
// custodian, with its seeds lost or its key store not answering.
const TEAM_SEEDS: Record<string, "lost" | "unavailable"> = {
  "team-keys-lost": "lost", "team-key-store-unavailable": "unavailable", "team-root-keys-lost": "lost",
  "team-root-key-store-unavailable": "unavailable",
};
let teamSeeds: "lost" | "unavailable" | null = TEAM_SEEDS[scenario] ?? null;
const teamDevice = scenario === "team-device-a" || scenario.startsWith("team-root-") ? "a"
  : scenario === "team-device-b" || teamSeeds ? "b" : null;
// The connection `team_set_connection` saved. A device session needs no token.
let teamConnection = teamDevice
  ? { server_url: "https://team.example.com", tenant_id: "22222222222222222222222222222222", has_token: false }
  : { server_url: "", tenant_id: "", has_token: false };
// This team device's own identity, pin and fleet key, as its team_config,
// trust ledger and fleet key store hold them. A is the root custodian.
type TeamMe = { device_id: string; enrolled_at_ms: number; pinned: boolean; collected: boolean };
// `teamHandover=appointed`: on A, it appointed B ("b1"x16) as the new root
// custodian (v2.10 hand-over); on B, B is that device, enrolled and joined.
const teamHandover = params.get("teamHandover");
let teamMe: TeamMe = teamDevice === "a"
  ? { device_id: "aa".repeat(16), enrolled_at_ms: 0, pinned: true, collected: false }
  : teamSeeds
    ? { device_id: "b0".repeat(16), enrolled_at_ms: 0, pinned: true, collected: true }
    : teamHandover === "appointed"
      ? { device_id: "b1".repeat(16), enrolled_at_ms: 0, pinned: true, collected: true }
      : { device_id: "", enrolled_at_ms: 0, pinned: false, collected: false };
const teamStatusFixture = () => (firstDevice
  ? {
    server_url: "https://team.example.com",
    tenant_id: "11111111-1111-4111-8111-111111111111",
    device_id: "0123456789abcdef0123456789abcdef",
    // As the backend: no IDs when a seed cannot be read, here because it sits in the unopened key file.
    ...(keyState.keys_locked ? teamNoKeyIds : teamKeyIds("0123456789abcdef0123456789abcdef")),
    has_token: true,
    is_enrolled: true,
    keys_unreadable: false,
    can_sync: true,
    can_receive_custody: true,
    has_fleet_key: false,
    fleet_key_blocked: scenario === "team-key-blocked",
    ...keyState,
  }
  : {
    ...teamConnection,
    device_id: teamMe.device_id,
    // As the backend: no key IDs while a seed cannot be read.
    ...(teamMe.device_id && !teamSeeds ? teamKeyIds(teamMe.device_id) : teamNoKeyIds),
    is_enrolled: !!teamMe.device_id,
    keys_unreadable: false,
    can_sync: !!teamMe.device_id,
    can_receive_custody: !!teamMe.device_id,
    has_fleet_key: teamMe.collected,
    fleet_key_blocked: false,
    keys_protected: true,
    has_key_file: false,
    keys_locked: false,
    keys_lost: teamSeeds === "lost",
    key_store_unavailable: teamSeeds === "unavailable",
  });
// `teamRefuse=<command>[,<command>]` makes those team commands refuse the way
// the backend does, before anything changes.
const teamRefusals = new Set((params.get("teamRefuse") ?? "").split(",").filter(Boolean));
// `teamRefuseCode=<code>` makes them refuse with that code instead.
const teamRefusalCode = params.get("teamRefuseCode");
const TEAM_REFUSAL: Record<string, string> = {
  profile_sync_publish: "sync.commitBlockedCompromised",
  profile_sync_push: "sync.remoteAhead",
  team_join_profile: "sync.fleetKeyRecollect",
};
let createdProfiles = 0;
const teamPushResult = (version: number) => ({ version, container_bytes: 4096, sha256: "ab".repeat(32) });
const teamBound = (payload?: InvokeArgs) => {
  const id = String((payload as { profileId?: string } | undefined)?.profileId ?? "");
  const b = teamProfiles.profiles.find((p) => p.profile_id === id);
  if (!b) throw new Error("[[shardx:sync.unbindNotBound]]");
  return b;
};

// The bootstrap anchor A0 of every team fixture.
const TEAM_ANCHOR = "a0".repeat(32);
// The root key ID, the recovery fingerprint, of every team fixture.
const TEAM_ROOT_KEY_ID = "5e".repeat(32);
// Every saved fixture root state is this device's, in its tenant, except with
// `teamRootJournal=foreign` or `foreign-unfinished`: another device's root
// state, finished or not, that a connection change kept.
const foreignRoot = params.get("teamRootJournal");
const DAY_MS = 86_400_000;
// A root custodian's own records as renewal reads them, renewed at `renewed`:
// due half a year later, ending a year later.
const renewalTimes = (renewed: number) => ({
  renewal_due_ms: renewed + 182 * DAY_MS, custody_ends_ms: renewed + 365 * DAY_MS,
  key_age_ends_ms: Date.now() + 900 * DAY_MS,
});
// No root key rotation started or awaiting its fleet rotation.
const noRootRotation = { root_rotation_unfinished: false, root_rotation_path: "", fleet_rotation_due: false };
const noRenewal = { renewal_due_ms: null, custody_ends_ms: null, key_age_ends_ms: null, ...noRootRotation };
let custodyBootstrap: {
  started: boolean; this_device: boolean; activated: boolean; recovery_path: string; anchor: string; root_key_id: string;
  renewal_due_ms: number | null; custody_ends_ms: number | null; key_age_ends_ms: number | null;
  root_rotation_unfinished: boolean; root_rotation_path: string; fleet_rotation_due: boolean;
} = foreignRoot
  ? {
    started: true, this_device: false, activated: foreignRoot === "foreign",
    recovery_path: "C:\\Users\\Example\\old.shxrecovery", anchor: foreignRoot === "foreign" ? "0f".repeat(32) : "",
    root_key_id: "", ...noRenewal,
  }
  : scenario === "team-first-device-resume"
  ? {
    started: true, this_device: true, activated: false, recovery_path: "C:\\Users\\Example\\kept.shxrecovery", anchor: "",
    root_key_id: "", ...noRenewal,
  }
  : teamDevice === "a"
    ? {
      started: true, this_device: true, activated: true, recovery_path: "C:\\Users\\Example\\a.shxrecovery",
      anchor: TEAM_ANCHOR, root_key_id: TEAM_ROOT_KEY_ID,
      // With `teamRenewal=due` its records are past 75% of their life.
      ...noRootRotation,
      ...renewalTimes(Date.now() - (params.get("teamRenewal") === "due" ? 300 : 10) * DAY_MS),
    }
    : { started: false, this_device: false, activated: false, recovery_path: "", anchor: "", root_key_id: "", ...noRenewal };
type FleetRotation = {
  generation: number; phase: "preparing" | "activated" | "done" | "expired"; deadline_ms: number | null;
  members_filed: number; members_refused: number; members_skipped: number; failing_member: string | null;
};
let fleetCustody: {
  started: boolean; created: boolean; setup_key_held: boolean; fkek_key_id: string; rotation: FleetRotation | null;
  rotation_required: "urgent" | "routine" | null; export_due: boolean; export_reason: "rotation" | "renewal";
  reseal: { generation: number; started_ms: number; ended_ms: number | null; profiles: Record<string, string> } | null;
  handed_over_to: string; handover: HandoverStatus | null;
  members_need_server_update: boolean; member_renewal_failed: string;
} = {
  started: false, created: false, setup_key_held: false, fkek_key_id: "", rotation: null, rotation_required: null,
  export_due: false, export_reason: "rotation", reseal: null, handed_over_to: "", handover: null,
  // `teamMembers=server-too-old`: the last member renewal met a 2.10 server.
  members_need_server_update: params.get("teamMembers") === "server-too-old", member_renewal_failed: "",
};
// v2.11 member renewal: each active member's approval window as the last pass saw it;
// with `teamMemberApproval=late` it is past 75% of its life.
const teamMemberWindow = (): [number, number] => {
  const from = Date.now() - (params.get("teamMemberApproval") === "late" ? 300 : 10) * DAY_MS;
  return [from, from + 365 * DAY_MS];
};
// The fleet generation A was at when it appointed B: its cancel is refused once the server is past it.
let teamHandedOverGeneration = 0;
if (teamDevice === "a" && teamHandover === "appointed") {
  fleetCustody = {
    ...fleetCustody, started: true, created: true, fkek_key_id: "fk".repeat(32), handed_over_to: "b1".repeat(16),
  };
  teamMe.collected = true;
}
// The highest fleet key generation this device kept.
let teamGeneration = 0;
// The member whose grant failed in the latest runs of an activated rotation, and in how many in a row.
let teamFailing: { id: string; runs: number } | null = null;
// `teamRotation=unfinished` or `expired`: A created the fleet key and saved a
// rotation to generation 1 that is still preparing, or can no longer activate.
const teamRotation = params.get("teamRotation");
if (teamDevice === "a" && teamRotation) {
  fleetCustody = {
    ...fleetCustody, started: true, created: true, fkek_key_id: "fk".repeat(32),
    rotation: {
      generation: 1, phase: teamRotation === "expired" ? "expired" : "preparing", deadline_ms: Date.UTC(2099, 0, 31),
      members_filed: 0, members_refused: 0, members_skipped: 0, failing_member: null,
    },
  };
  teamMe.collected = true;
}
// The generation of the head each binding here last accepted.
const teamKeyGenOf = new Map<string, number>();

// "team-device-a" and "team-device-b": two devices of one fleet. Each page keeps
// its own bindings, pin and fleet key; the server they share is the
// `e2eTeamServer` binding the team journeys in tests/e2e expose, so a pin is the
// version a device accepted. No device holds a fleet key until it collected one.
type TeamServerHead = {
  remote_profile_id: string; version: number; label: string | null; quarantine: string | null; revert_available: boolean;
  key_generation: number;
};
const teamServer = <T = TeamServerHead>(op: string, args: object) =>
  (window as unknown as { e2eTeamServer: (op: string, device: string, args: object) => Promise<T> })
    .e2eTeamServer(op, String(teamDevice), args);
const teamRemoteOf = new Map<string, string>();
/** Apply a head the server answered with: a quarantine keeps the pin, anything else is accepted. */
const teamSettle = (b: TeamProfileStatus, head: TeamServerHead) => {
  if (!head.quarantine) teamKeyGenOf.set(b.profile_id, head.key_generation);
  const patch: Partial<TeamProfileStatus> = head.quarantine
    ? { sync_state: "QUARANTINED", last_error_code: head.quarantine, revert_available: head.revert_available }
    : {
      sync_state: "AVAILABLE", remote_version: head.version, dirty: false, lease_expires_at: null,
      lease_at_risk: false, last_error_code: null, revert_available: false, revert_in_progress: false,
    };
  return Object.assign(b, patch);
};
// Every row's keys and code derive from its device id, the same way on both pages.
const teamKeyIds = (id: string) => ({ signing_key_id: id + id, hpke_key_id: [...id + id].reverse().join("") });
const teamNoKeyIds = { signing_key_id: "", hpke_key_id: "" };
const teamSas = (id: string) => [...id].reverse().join("").match(/.{4}/g)!.join(" ");
const TEAM_WINDOW_MS = 10 * 60_000;
// When this custodian first saw each pending device, by its own clock; never reset.
const teamFirstSeen = new Map<string, number>();
const teamRefuse = (code: string): never => { throw new Error(`[[shardx:${code}]]`); };
const teamWindowOpen = () => {
  if (!teamMe.enrolled_at_ms || Date.now() > teamMe.enrolled_at_ms + TEAM_WINDOW_MS) teamRefuse("fleet.joinCodeExpired");
};
const teamCustodian = () => { if (!custodyBootstrap.activated) teamRefuse("fleet.notCustodian"); };
/** As the launcher: a root custodian that appointed another device runs no custody command of its own. */
const teamNotHandedOver = () => { if (fleetCustody.handed_over_to) teamRefuse("fleet.custodyHandedOver"); };
/** 4.H step 7's refusal, naming the missing checklist `step` and the blocking `profiles`. */
const teamNotReady = (step: string, profiles: string[] = []): never =>
  teamRefuse(`fleet.handoverNotReady|step=${step}|profiles=${profiles.join(", ")}`);
/**
 * Collect key custody's fleet grant: kept only once this device pins the
 * anchor to verify it against, and only one generation above the newest it
 * kept (Q-27).
 */
async function teamCollect() {
  const { granted, generation } = await teamServer<{ granted: boolean; generation: number }>(
    "collect", { device_id: teamMe.device_id },
  );
  const missed = granted && teamMe.collected && generation > teamGeneration + 1;
  const kept = granted && teamMe.pinned && !missed;
  if (kept) {
    teamMe.collected = true;
    teamGeneration = generation;
  }
  return { granted, generation, missed, kept };
}
const TEAM_SYNC = new Set([
  "team_fleet_profiles", "profile_sync_publish", "team_join_profile", "profile_sync_pull", "profile_sync_push",
  "profile_sync_revert",
]);
async function teamDeviceCommand(cmd: string, payload?: InvokeArgs) {
  const args = (payload ?? {}) as {
    profileId?: string; remoteProfileId?: string; localProfileId?: string; deviceId?: string; sas?: string;
    reason?: string; anchor?: string; label?: string; path?: string; oldDeviceLost?: boolean;
    skipMember?: string | null; asCustodian?: boolean; acceptReverts?: string[] | null; bundlePath?: string;
  };
  const id = String(args.profileId ?? args.localProfileId ?? "");
  const head = () => ({
    remote_profile_id: teamRemoteOf.get(id), pin: teamBound(payload).remote_version, generation: teamGeneration,
  });
  const me = { device_id: teamMe.device_id };
  if (TEAM_SYNC.has(cmd)) {
    await teamServer("live", me);
    if (!teamMe.collected) teamRefuse("sync.noVerifiedFleetKey");
  }
  switch (cmd) {
    case "team_enroll_device": {
      const { device_id } = await teamServer<{ device_id: string }>("enroll", { label: args.label });
      // A pin binds the server, tenant and anchor, not the device, so it stays.
      teamMe = { device_id, enrolled_at_ms: Date.now(), pinned: teamMe.pinned, collected: false };
      teamSeeds = null;
      return teamStatusFixture();
    }
    case "team_fleet_key_setup":
      teamCustodian();
      await teamServer("fleetKey", me);
      fleetCustody = { ...fleetCustody, started: true, created: true, setup_key_held: false, fkek_key_id: "fk".repeat(32) };
      teamMe.collected = true; // the setup ends with the verified collect
      return fleetCustody;
    case "team_devices": {
      teamCustodian();
      const rows = await teamServer<{ device_id: string; label: string; status: string; custodian: boolean }[]>(
        "devices", me,
      );
      return rows.map((r) => {
        if (r.status === "pending" && !teamFirstSeen.has(r.device_id)) teamFirstSeen.set(r.device_id, Date.now());
        const first = r.status === "pending" ? teamFirstSeen.get(r.device_id) : undefined;
        return {
          ...r, account_id: "ac".repeat(16), ...teamKeyIds(r.device_id), sas: teamSas(r.device_id),
          approve_until_ms: first === undefined ? null : first + TEAM_WINDOW_MS,
          approval_window_ms: r.status === "active" && r.device_id !== teamMe.device_id ? teamMemberWindow() : null,
        };
      });
    }
    case "team_approve_device": {
      teamCustodian();
      const target = String(args.deviceId);
      // As the launcher: after an appointment only that appointment resumes.
      if (!(args.asCustodian && fleetCustody.handed_over_to === target)) teamNotHandedOver();
      // As the launcher: no saved Create fleet key, no approval.
      if (!fleetCustody.created) teamRefuse("fleet.notCustodian");
      const first = teamFirstSeen.get(target);
      if (first === undefined || Date.now() - first > TEAM_WINDOW_MS) teamRefuse("fleet.approvalWindowClosed");
      if (args.sas !== teamSas(target)) teamRefuse("fleet.joinCodeMismatch");
      if (!teamMe.collected) teamRefuse("fleet.createFleetKeyFirst");
      if (fleetCustody.rotation?.phase === "preparing" || fleetCustody.rotation?.phase === "activated") {
        teamRefuse("fleet.rotationInProgress");
      }
      // Appoint (4.H step 1): the server refuses it while a head is under an older generation.
      await teamServer("approve", { ...me, target, custodian: !!args.asCustodian });
      if (args.asCustodian) {
        fleetCustody = { ...fleetCustody, handed_over_to: target };
        teamHandedOverGeneration = teamGeneration;
      }
      return null;
    }
    case "team_custody_accept": {
      // As the launcher: Accept needs the pinned anchor, then a root grant naming this device.
      if (!teamMe.pinned) teamRefuse("fleet.handoverNoGrant");
      const { outgoing, generation } = await teamServer<{ outgoing: string; generation: number }>("accept", me);
      custodyBootstrap = {
        started: true, this_device: true, activated: true, recovery_path: "", anchor: TEAM_ANCHOR,
        root_key_id: TEAM_ROOT_KEY_ID, ...noRootRotation, ...renewalTimes(Date.now()),
      };
      fleetCustody = {
        ...fleetCustody, started: true, created: true, setup_key_held: false, fkek_key_id: "fk".repeat(32),
        handover: {
          outgoing, accepted_generation: generation, phase: "granted", first_exported: false, rotated_generation: 0,
          resealed_generation: 0, exported_generation: 0, reverts: {},
        },
      };
      teamMe.collected = true;
      teamGeneration = generation;
      return fleetCustody;
    }
    case "team_revoke_device":
      teamCustodian();
      if (!["retired", "lost", "compromised"].includes(String(args.reason))) teamRefuse("fleet.revokeReasonUnsupported");
      if (args.deviceId === teamMe.device_id) teamRefuse("fleet.cannotRevokeSelf");
      // As the launcher: no saved Create fleet key, no revoke.
      if (!fleetCustody.created) teamRefuse("fleet.notCustodian");
      // As the launcher (D13): after an appointment only the appointee is revoked, which cancels the
      // hand-over, and only until the server is past the appointment's generation.
      if (fleetCustody.handed_over_to) {
        if (args.deviceId !== fleetCustody.handed_over_to) teamRefuse("fleet.custodyHandedOver");
        if (await teamServer<number>("generation", me) > teamHandedOverGeneration) teamRefuse("fleet.handoverPastRotation");
        await teamServer("revoke", { ...me, target: args.deviceId });
        fleetCustody = { ...fleetCustody, handed_over_to: "" };
        return null;
      }
      {
        const h = fleetCustody.handover;
        const rows = await teamServer<{ device_id: string }[]>("devices", me);
        const row = rows.find((r) => r.device_id === args.deviceId);
        if (h && row && teamKeyIds(row.device_id).signing_key_id === h.outgoing) {
          // 4.H step 7: the old root is revoked behind its checklist and the live heads.
          if (args.reason === "compromised") teamRefuse("fleet.revokeOutgoingReason");
          const active = await teamServer<number>("generation", me);
          if (h.phase !== "granted" && h.phase !== "done") teamNotReady("accept");
          if (!h.first_exported) teamNotReady("export");
          if (h.rotated_generation !== active || active <= h.accepted_generation) teamNotReady("rotate");
          if (h.resealed_generation !== active) teamNotReady("reseal");
          if (h.exported_generation !== active) teamNotReady("export-again");
          const blockers = await teamServer<{ profile: string; after_reseal: boolean }[]>("blockers", me);
          const listed = blockers.map((b) => b.profile).sort();
          const accepted = (args.acceptReverts ?? []).map((p) => p.toLowerCase()).sort();
          const ready = args.reason === "retired"
            ? !blockers.length
            : blockers.every((b) => b.after_reseal) && accepted.join() === listed.join();
          if (!ready) teamNotReady("heads", listed);
          await teamServer("revoke", { ...me, target: args.deviceId });
          const reverts: Record<string, string> = {};
          for (const p of listed) reverts[p] = `reverted:${await teamServer<number>("undo", { remote_profile_id: p })}`;
          fleetCustody = { ...fleetCustody, handover: { ...h, phase: "done", reverts } };
          return null;
        }
      }
      // As the launcher (Q-57): fresh evidence counting the row as a custodian refuses `compromised`.
      if (args.reason === "compromised") {
        const rows = await teamServer<{ device_id: string; custodian: boolean }[]>("devices", me);
        if (rows.find((r) => r.device_id === args.deviceId)?.custodian) teamRefuse("fleet.compromisedCustodian");
      }
      {
        // As the launcher: only a revoked holder of the current key asks for a rotation.
        const { held } = await teamServer<{ held: boolean }>("revoke", { ...me, target: args.deviceId });
        if (held && fleetCustody.rotation_required !== "urgent") {
          fleetCustody = { ...fleetCustody, rotation_required: args.reason === "retired" ? "routine" : "urgent" };
        }
      }
      return null;
    case "team_fleet_key_rotate": {
      teamCustodian();
      teamNotHandedOver();
      if (!fleetCustody.created) teamRefuse("fleet.notCustodian");
      // As the launcher (4.H steps 2-3): the new custodian rotates once it exported a bundle after Accept.
      if (fleetCustody.handover && !fleetCustody.handover.first_exported) teamNotReady("export");
      if (fleetCustody.rotation?.phase === "expired") teamRefuse("fleet.rotationStuck");
      if (!teamMe.collected) teamRefuse("fleet.rotationNeedsFleetKey");
      const skip = args.skipMember ?? null;
      // As the launcher: only the member whose grant keeps failing can be skipped.
      if (skip && skip !== fleetCustody.rotation?.failing_member) teamRefuse("fleet.rotationSkipRefused");
      const r = await teamServer<{
        generation: number; filed: number; refused: number; skipped: number; failing: string | null;
      }>("rotate", { ...me, skip });
      teamGeneration = r.generation; // the new key is collected before the members' grants
      const rotation = {
        generation: r.generation, deadline_ms: fleetCustody.rotation?.deadline_ms ?? null,
        members_filed: r.filed, members_refused: r.refused, members_skipped: r.skipped,
      };
      if (r.failing) {
        // A member's grant failed with an error a resend may cure: the rotation stays activated,
        // and the member is offered for Skip only after two runs in a row.
        teamFailing = { id: r.failing, runs: teamFailing?.id === r.failing ? teamFailing.runs + 1 : 1 };
        const failing_member = teamFailing.runs >= 2 ? r.failing : null;
        fleetCustody = { ...fleetCustody, rotation: { ...rotation, phase: "activated", failing_member } };
        teamRefuse("fleet.refusedCustody|status=503|detail=unavailable");
      }
      teamFailing = null;
      // D8: a fleet key under the rotated root ends the root rotation's prompt.
      custodyBootstrap = { ...custodyBootstrap, fleet_rotation_due: false };
      fleetCustody = {
        ...fleetCustody,
        rotation: { ...rotation, phase: "done", failing_member: null },
        rotation_required: null,
        export_due: true,
        export_reason: "rotation",
        handover: fleetCustody.handover && { ...fleetCustody.handover, rotated_generation: r.generation },
      };
      return fleetCustody;
    }
    case "team_reseal_all": {
      // As the launcher: only an activated root custodian holding the active key re-seals.
      if (!custodyBootstrap.activated) teamRefuse("sync.resealNotCustodian");
      teamNotHandedOver();
      if (!teamMe.collected) teamRefuse("sync.noVerifiedFleetKey");
      const r = await teamServer<{ generation: number; profiles: Record<string, string> }>("reseal", me);
      for (const b of teamProfiles.profiles) {
        const remote = teamRemoteOf.get(b.profile_id);
        const outcome = remote ? r.profiles[remote] : undefined;
        // A bound copy re-sealed through its own binding moves with it.
        if (outcome?.startsWith("resealed:")) {
          b.remote_version = Number(outcome.slice("resealed:".length));
          teamKeyGenOf.set(b.profile_id, r.generation);
        }
      }
      fleetCustody = {
        ...fleetCustody,
        reseal: { generation: r.generation, started_ms: Date.now(), ended_ms: Date.now(), profiles: r.profiles },
        // 4.H step 5: a finished run (the mock leaves none pending) records its generation.
        handover: fleetCustody.handover && { ...fleetCustody.handover, resealed_generation: r.generation },
      };
      return fleetCustody;
    }
    case "team_profiles_under_older_key":
      return teamProfiles.profiles
        .filter((b) => b.remote_version > 0 && (teamKeyGenOf.get(b.profile_id) ?? teamGeneration) < teamGeneration)
        .map((b) => ({ profile_id: b.profile_id, key_generation: teamKeyGenOf.get(b.profile_id) }));
    case "team_join_code":
      try { teamWindowOpen(); } catch (e) {
        // As the launcher: an expired code says when Enroll again would be refused,
        // and a device with its own root state, finished or not, is refused unasked.
        if (custodyBootstrap.this_device) teamRefuse("fleet.enrollAgainRefused");
        const status = await teamServer<string | null>("status", me);
        if (!(status === "pending" || status === "revoked" || (status === "active" && !teamMe.pinned))) {
          teamRefuse(status === "active" ? "fleet.joinedCollectKey" : "fleet.enrollAgainRefused");
        }
        throw e;
      }
      await teamServer("live", me);
      return {
        sas: teamSas(teamMe.device_id), anchor: TEAM_ANCHOR, ...teamKeyIds(teamMe.device_id),
        expires_at_ms: teamMe.enrolled_at_ms + TEAM_WINDOW_MS,
      };
    case "team_join_confirm":
      teamWindowOpen();
      await teamServer("live", me);
      if (args.anchor !== TEAM_ANCHOR) teamRefuse("fleet.joinAnchorChanged");
      if (args.sas !== teamSas(teamMe.device_id)) teamRefuse("fleet.joinCodeChanged");
      teamMe.pinned = true;
      return null;
    case "team_enroll_again": {
      const status = await teamServer<string | null>("status", me);
      const allowed = status === "pending" || status === "revoked" || (status === "active" && !teamMe.pinned);
      // As the launcher: this device's root state refuses it, activated or not, unless
      // it handed custody over and the server serves its signed revocation (v2.11).
      if (custodyBootstrap.this_device && fleetCustody.handed_over_to) {
        if (status !== "revoked") teamRefuse("fleet.resetNeedsSignedRevocation");
        custodyBootstrap = { started: false, this_device: false, activated: false, recovery_path: "", anchor: "", root_key_id: "", ...noRenewal };
        fleetCustody = { ...fleetCustody, started: false, created: false, fkek_key_id: "", handed_over_to: "" };
      } else if (custodyBootstrap.this_device || !allowed) teamRefuse("fleet.enrollAgainRefused");
      teamMe = { ...teamMe, device_id: "", enrolled_at_ms: 0, collected: false };
      teamSeeds = null;
      return teamStatusFixture();
    }
    case "team_import_recovery_bundle": {
      // Every bundle restores A, the fixtures' root custodian, as the launcher checks it.
      const bundle = "aa".repeat(16);
      if (!args.oldDeviceLost) teamRefuse("recovery.confirmOldDeviceLost");
      if (teamMe.device_id && teamMe.device_id !== bundle) teamRefuse("recovery.deviceHasIdentity");
      if (await teamServer<string | null>("status", { device_id: bundle }) !== "active") {
        teamRefuse("recovery.deviceNotActive");
      }
      document.documentElement.dataset.e2eImportPath = String(args.path ?? "");
      teamMe = { device_id: bundle, enrolled_at_ms: 0, pinned: true, collected: true };
      teamSeeds = null;
      custodyBootstrap = {
        started: true, this_device: true, activated: true, recovery_path: String(args.path ?? ""), anchor: TEAM_ANCHOR,
        root_key_id: TEAM_ROOT_KEY_ID, ...noRootRotation, ...renewalTimes(Date.now()),
      };
      fleetCustody = { ...fleetCustody, started: true, created: true, setup_key_held: false, fkek_key_id: "fk".repeat(32) };
      return {
        grants: 0, opened: 0, failed: 0, newest_generation: null, fleet_opened: 1, fleet_failed: 0,
        newest_fleet_generation: 0, fleet_grants_waiting: 0, fleet_refusal: null, fleet_enroll_again: false,
        can_sync_without_passphrase: false,
      };
    }
    case "team_renew_custody": {
      // As the launcher: only a due root custodian renews, then asks for the bundle again.
      teamCustodian();
      if (fleetCustody.handed_over_to) return "handed_over";
      await teamServer("live", me);
      if ((custodyBootstrap.renewal_due_ms ?? Infinity) > Date.now()) return "not_due";
      custodyBootstrap = { ...custodyBootstrap, ...renewalTimes(Date.now()) };
      fleetCustody = { ...fleetCustody, export_due: true, export_reason: "renewal" };
      return "renewed";
    }
    case "team_rotate_root": {
      // As the launcher (v2.11 RR): with `teamRootRotation=waits` the first run stops at the activation,
      // which waits for a stuck fleet generation's discard, and stays resumable with its saved bundle path.
      teamCustodian();
      teamNotHandedOver();
      await teamServer("live", me);
      const path = custodyBootstrap.root_rotation_path || String(args.bundlePath ?? "");
      document.documentElement.dataset.e2eRootRotationPath = path;
      if (params.get("teamRootRotation") === "waits" && !custodyBootstrap.root_rotation_unfinished) {
        custodyBootstrap = { ...custodyBootstrap, root_rotation_unfinished: true, root_rotation_path: path };
        teamRefuse("fleet.rootRotationWaitsForFleetDiscard");
      }
      custodyBootstrap = {
        ...custodyBootstrap, recovery_path: path, root_key_id: "6e".repeat(32),
        root_rotation_unfinished: false, root_rotation_path: "", fleet_rotation_due: true,
      };
      return custodyBootstrap;
    }
    case "team_export_recovery_bundle": {
      teamCustodian();
      teamNotHandedOver();
      await teamServer("live", me);
      if (!teamMe.collected) teamRefuse("fleet.recoveryExportNeedsFleetKey");
      document.documentElement.dataset.e2eExportPath = String(args.path ?? "");
      // 4.H steps 3 and 6: the first bundle after Accept, then one holding the re-sealed generation.
      const h = fleetCustody.handover;
      const handover = !h || (h.phase !== "granted" && h.phase !== "done") ? h
        : !h.first_exported ? { ...h, first_exported: true }
        : h.rotated_generation > h.accepted_generation && h.resealed_generation === h.rotated_generation
          ? { ...h, exported_generation: teamGeneration } : h;
      fleetCustody = { ...fleetCustody, export_due: false, export_reason: "rotation", handover };
      return null;
    }
    case "team_collect_custody": {
      const { granted, generation, missed, kept } = await teamCollect();
      return {
        grants: 0, opened: 0, failed: 0, newest_generation: null,
        fleet_opened: kept ? 1 : 0, fleet_failed: missed ? 1 : 0, newest_fleet_generation: kept ? generation : null,
        fleet_grants_waiting: granted && !kept ? 1 : 0, fleet_refusal: null, fleet_enroll_again: missed,
        can_sync_without_passphrase: false,
      };
    }
    case "team_fleet_profiles":
      return (await teamServer<TeamServerHead[]>("list", {})).map((h): TeamFleetProfile => ({
        remote_profile_id: h.remote_profile_id, current_version: h.version, label: h.label,
        bound_to: [...teamRemoteOf].find(([, r]) => r === h.remote_profile_id)?.[0] ?? null,
      }));
    case "profile_sync_publish": {
      const h = await teamServer("publish", {
        label: profiles.find((p) => p.id === id)?.name ?? null, generation: teamGeneration,
      });
      teamRemoteOf.set(id, h.remote_profile_id);
      teamProfiles.profiles.push(teamBinding(id, "CHECKED_OUT", { remote_version: h.version, lease_expires_at: teamLease }));
      return { profile_id: h.remote_profile_id, fencing_token: 1, lease_expires_at_ms: 4_070_908_800_000 };
    }
    case "team_join_profile": {
      const h = await teamServer("pull", { remote_profile_id: args.remoteProfileId, pin: null });
      teamRemoteOf.set(id, h.remote_profile_id);
      teamProfiles.profiles.push(teamSettle(teamBinding(id, "AVAILABLE"), h));
      return 4096;
    }
    case "profile_sync_pull":
      teamSettle(teamBound(payload), await teamServer("pull", head()));
      return 4096;
    case "profile_sync_push":
    case "profile_sync_revert": {
      const op = cmd === "profile_sync_push" ? "push" : "revert";
      let h: TeamServerHead;
      let collected: number | null = null;
      try {
        h = await teamServer(op, head());
      } catch (e) {
        // As the launcher: refused under a rotated key, it collects once and, once a key was kept, runs again once.
        if (!String(e).includes("sync.fleetKeyRotated")) throw e;
        const c = await teamCollect();
        if (!c.kept) throw e;
        collected = c.generation;
        h = await teamServer(op, head());
      }
      const result = teamPushResult(teamSettle(teamBound(payload), h).remote_version);
      return collected === null ? result : { ...result, collected_generation: collected };
    }
  }
  return undefined;
}

mockIPC(async (cmd: string, payload?: InvokeArgs) => {
  if (
    (cmd.startsWith("plugin:") || cmd.startsWith("tauri:"))
    && cmd !== "plugin:dialog|open" && cmd !== "plugin:dialog|save"
  ) {
    return null;
  }
  if (teamRefusals.has(cmd)) {
    throw new Error(`[[shardx:${teamRefusalCode ?? TEAM_REFUSAL[cmd] ?? "sync.remoteAhead"}]]`);
  }
  if (teamDevice) {
    const answer = await teamDeviceCommand(cmd, payload);
    if (answer !== undefined) return answer;
  }
  switch (cmd) {
    case "host_platform":
      return "windows";
    case "runtime_status":
      count("RuntimeChecks");
      if (runtimeFailures-- > 0) throw new Error("fixture runtime check failed");
      return {
        installed: !runtimeNeedsInstall,
        binary_path: "C:\\Program Files\\ShardX\\browser.exe",
        installed_browser_etag: "fixture",
        remote_browser_etag: "fixture",
        update_available: false,
        fingerprints_installed: !runtimeNeedsInstall,
        spec: { browser: { key: "chromium", label: "Chromium" }, widevine: null },
      };
    case "runtime_install":
      if (runtimeInstallFailures-- > 0) throw new Error("fixture runtime install failed");
      runtimeNeedsInstall = false;
      return null;
    case "profile_list": {
      count("ProfileLists");
      profileListsInFlight += 1;
      maxProfileListsInFlight = Math.max(maxProfileListsInFlight, profileListsInFlight);
      document.documentElement.dataset.e2eMaxProfileListsInFlight = String(maxProfileListsInFlight);
      try {
        if (Number(params.get("profilesDelay") ?? 0) > 0) await wait(Number(params.get("profilesDelay")));
        if (profileFailures-- > 0) throw new Error("fixture profile list failed");
        return [...profiles];
      } finally {
        profileListsInFlight -= 1;
      }
    }
    case "proxy_list": {
      proxyListCalls += 1;
      proxyListsInFlight += 1;
      maxProxyListsInFlight = Math.max(maxProxyListsInFlight, proxyListsInFlight);
      document.documentElement.dataset.e2eMaxProxyListsInFlight = String(maxProxyListsInFlight);
      try {
        if (Number(params.get("proxiesDelay") ?? 0) > 0) await wait(Number(params.get("proxiesDelay")));
        if (scenario === "proxy-error-once" && proxyListCalls === 2) {
          throw new Error("fixture proxy list failed");
        }
        return proxies;
      } finally {
        proxyListsInFlight -= 1;
      }
    }
    case "process_list":
      return [
        ...(profiles.some((profile) => profile.id === "profile-beta") ? ["profile-beta"] : []),
        ...((window as E2EWindow).__e2eStartedElsewhere ?? []),
      ].map((profile_id) => ({
        profile_id,
        pid: 4242,
        cdp: {
          port: 9222,
          http_url: "http://127.0.0.1:9222",
          web_socket_debugger_url: "ws://127.0.0.1:9222/devtools/browser/fixture",
        },
        uptime_ms: 5_000,
      }));
    case "fingerprint_list":
      return fingerprints;
    case "gpu_caps":
      if (scenario !== "fingerprints") throw new Error(`Unhandled E2E command: ${cmd}`);
      return { renderer: "Fixture GPU", vendor: "Fixture", webgl1: [], webgl2: [], webgpu: null, engine_version: "fixture" };
    case "gpu_caps_compat":
      if (scenario !== "fingerprints") throw new Error(`Unhandled E2E command: ${cmd}`);
      return {
        "fp-mac": mismatch("Apple M2"),
        "fp-win": mismatch("NVIDIA GeForce RTX 3060"),
        "fp-ref": { compatible: true, missing_webgl1: [], missing_webgl2: [], missing_webgpu: [], profile_renderer: "Intel UHD 620" },
      };
    case "profile_get": {
      const id = (payload as { id?: string } | undefined)?.id;
      const profile = profiles.find((entry) => entry.id === id) ?? fixtureProfiles[0];
      return {
        _meta: {
          id: profile.id,
          proxy_id: profile.proxy_id,
          gpu_preset_id: "",
        },
        name: profile.name,
        notes: profile.notes,
        navigator: {
          user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/148.0.0.0 Safari/537.36",
          hardware_concurrency: 8,
          device_memory: 16,
          language: "auto",
        },
        custom_fonts: {
          mode: "append",
          dirs: ["C:\\Fixture\\Fonts"],
          names: ["Fixture Sans"],
          random_count: 1,
        },
      };
    }
    case "profile_save": {
      count("ProfileSaves");
      const stored = (payload as { payload?: Record<string, unknown> } | undefined)?.payload ?? {};
      document.documentElement.dataset.e2eSavedCustomFonts = JSON.stringify(stored.custom_fonts ?? null);
      const meta = (stored._meta ?? {}) as { id?: string; proxy_id?: string | null };
      // As prepare_profile_name_for_save: no two profiles share a name, case aside.
      if (typeof stored.name === "string" && profiles.some((p) => p.id !== meta.id && same(p.name, stored.name as string))) {
        throw new Error(`[[shardx:profile.nameTaken|name=${stored.name}]]`);
      }
      const saved = {
        ...fixtureProfiles[0],
        id: meta.id || `profile-created-${++createdProfiles}`,
        name: typeof stored.name === "string" ? stored.name : "untitled",
        notes: typeof stored.notes === "string" ? stored.notes : "",
        proxy_id: meta.proxy_id ?? null,
      };
      // A new profile is listed from now on, as the launcher's would be.
      if (!meta.id) profiles.push({ ...saved, pinned: false, folder: "", tags: [] });
      return saved;
    }
    case "profile_delete": {
      count("ProfileDeletes");
      const at = profiles.findIndex((p) => p.id === (payload as { id?: string } | undefined)?.id);
      if (at >= 0) profiles.splice(at, 1);
      return null;
    }
    case "profile_validate_name": {
      count("ProfileNameValidations");
      const name = (payload as { name?: string } | undefined)?.name ?? "";
      const normalized = name.trimStart();
      if (!normalized || /[\x00-\x1f\x7f/\\<>:"|?*]/.test(normalized) || /[.\s]$/.test(normalized)) {
        throw new Error("Invalid profile name");
      }
      return normalized;
    }
    case "profile_bind_proxy":
      return null;
    case "proxy_last_test":
      return null;
    case "settings_get":
      return settings;
    case "settings_load_error":
      return null;
    case "settings_save":
      Object.assign(settings, (payload as { value?: typeof settings } | undefined)?.value);
      return null;
    case "startup_status":
      return {
        supported: true,
        configured: settings.launch_at_login,
        registered: settings.launch_at_login,
        matches_configuration: true,
        start_minimized: settings.start_minimized,
        launched_for_autostart: false,
        api_enabled: settings.api_enabled,
        api_mode: "launcher_embedded",
        mcp_mode: "client_spawned",
      };
    case "api_info":
      return {
        enabled: true,
        port: settings.api_port,
        base_url: "http://127.0.0.1:40325",
        token: "fixture-token-redacted",
        running: true,
        runtime_enabled: true,
        runtime_port: 40325,
        runtime_base_url: "http://127.0.0.1:40325",
        error: null,
        restart_required: false,
      };
    case "mcp_status":
      return mcpStatus();
    // Directory pickers are native; the suite drives the value the operator
    // would have chosen so the adopt path stays exercisable headlessly.
    case "plugin:dialog|open":
      if (JSON.stringify(payload ?? {}).includes("shxrecovery")) return "C:\\Users\\Example\\a.shxrecovery";
      return scenario === "mcp-adopt-cancelled"
        ? null
        : "C:\\Users\\Example\\Existing-MCP";
    // Adopting a folder must move the reported path, otherwise the operator
    // cannot tell an adopted server from a freshly downloaded one.
    case "mcp_set_path": {
      const dir = String((payload as { dir?: string })?.dir ?? "");
      if (scenario === "mcp-adopt-invalid") {
        throw new Error("No MCP server found in that folder");
      }
      settings.mcp_path = dir;
      return mcpStatus();
    }
    // Raising a page only makes sense for a live profile; the failure path is
    // what the UI must surface, so keep it reachable from a scenario.
    case "devtools_activate": {
      if (scenario === "verification-activate-fails") {
        throw new Error("No active page to raise");
      }
      return null;
    }
    case "codex_mcp_status":
      if (scenario === "codex-needs-repair") {
        return {
          available: true,
          registered: true,
          enabled: false,
          transport_type: "stdio",
          command: "node",
          index_path: "C:\\Users\\Example\\Old-ShardX-MCP\\index.js",
          expected_index_path: "C:\\Users\\Example\\ShardX-MCP\\index.js",
          path_matches: false,
          api: "http://127.0.0.1:40326",
          expected_api: "http://127.0.0.1:40325",
          api_matches: false,
          token_in_config: false,
          ready: false,
          state: "needs_repair",
          message: "Codex MCP fixture needs repair.",
          issues: ["Path and API do not match the selected Launcher settings."],
        };
      }
      return {
        available: true,
        registered: true,
        enabled: true,
        transport_type: "stdio",
        command: "node",
        index_path: "C:\\Users\\Example\\ShardX-MCP\\index.js",
        expected_index_path: "C:\\Users\\Example\\ShardX-MCP\\index.js",
        path_matches: true,
        api: "http://127.0.0.1:40325",
        expected_api: "http://127.0.0.1:40325",
        api_matches: true,
        token_in_config: false,
        ready: true,
        state: "registered",
        message: "Codex MCP fixture ready.",
        issues: [],
      };
    case "hermes_mcp_status":
      if (scenario === "hermes-not-registered") {
        return {
          available: true,
          registered: false,
          enabled: false,
          index_path: null,
          expected_index_path: "C:\\Users\\Example\\ShardX-MCP\\index.js",
          path_matches: null,
          api: null,
          expected_api: "http://127.0.0.1:40325",
          api_matches: null,
          token_in_config: false,
          ready: false,
          state: "not_registered",
          message: "Hermes MCP fixture is not registered.",
          issues: ["shardbrowser is not registered with Hermes"],
        };
      }
      return {
        available: true,
        registered: true,
        enabled: true,
        index_path: "C:\\Users\\Example\\ShardX-MCP\\index.js",
        expected_index_path: "C:\\Users\\Example\\ShardX-MCP\\index.js",
        path_matches: true,
        api: "http://127.0.0.1:40325",
        expected_api: "http://127.0.0.1:40325",
        api_matches: true,
        token_in_config: false,
        ready: true,
        state: "registered",
        message: "Hermes MCP fixture ready.",
        issues: [],
      };
    case "launcher_update_check":
      if (params.get("updateHold") === "1") {
        document.documentElement.dataset.e2eUpdateCheckPending = "true";
        await new Promise<void>((resolve) => {
          (window as E2EWindow).__resolveUpdateCheck = resolve;
        });
        delete (window as E2EWindow).__resolveUpdateCheck;
        document.documentElement.dataset.e2eUpdateCheckPending = "false";
      }
      if (Number(params.get("updateDelay") ?? 0) > 0) await wait(Number(params.get("updateDelay")));
      if (params.get("update") === "check-error") throw new Error("fixture update check failed");
      return updateInfo();
    case "launcher_update_download": {
      count("UpdateDownloads");
      const stepDelay = Number(params.get("updateDownloadStepDelay") ?? 120);
      updateChannel(payload)?.onmessage?.({ event: "started", data: { content_length: 1_000 } });
      await wait(stepDelay);
      updateChannel(payload)?.onmessage?.({ event: "progress", data: { chunk_length: 400 } });
      await wait(stepDelay);
      updateChannel(payload)?.onmessage?.({ event: "progress", data: { chunk_length: 600 } });
      if (params.get("update") === "invalid-signature") {
        throw new Error("Updater signature verification failed");
      }
      updateChannel(payload)?.onmessage?.({ event: "finished" });
      return null;
    }
    case "launcher_update_install":
      count("UpdateInstalls");
      return null;
    case "launcher_update_restart":
      count("RestartRequests");
      return null;
    case "open_link_take":
      return (window as E2EWindow).__e2eOpenLinks?.splice(0) ?? [];
    case "launch":
      count("Launches");
      if (scenario === "slow-launch") {
        await new Promise<void>((resolve) => { cancelPendingLaunch = resolve; });
        throw new Error("launch.cancelled");
      }
      throw new Error("fixture browser launch failed");
    case "launch_cancel":
      cancelPendingLaunch?.();
      return null;
    case "profile_set_tags": {
      const { id, tags } = payload as { id: string; tags: string[] };
      return setProfileTags(id, tags);
    }
    case "tags_list":
      return listTags();
    case "tag_recolor": {
      const { name, color } = payload as { name: string; color: string | null };
      const spelled = listTags().find((x) => same(x.name, name))?.name ?? clean(name);
      takeColor(spelled);
      if (color) tagState.colors[spelled] = color;
      saveTags();
      return null;
    }
    case "tag_rename":
    case "tag_delete": {
      const { old, new: renamed, name } = payload as { old?: string; new?: string; name?: string };
      const target = old ?? name ?? "";
      let n = 0;
      for (const profile of profiles) {
        if (!profile.tags.some((x) => same(x, target))) continue;
        n += 1;
        const next = profile.tags.flatMap((x) => (same(x, target) ? (renamed ? [renamed] : []) : [x]));
        setProfileTags(profile.id, next);
      }
      const color = takeColor(target);
      if (renamed && color) tagState.colors[clean(renamed)] = color;
      saveTags();
      return n;
    }
    case "ps_get_key":
      return "";
    case "clipboard_write":
    case "clipboard_read":
      return "";

    // v2 list endpoints: empty is a valid, uninteresting fixture state.
    case "bookmark_list":
      return [...bookmarks];
    case "bookmark_delete": {
      count("BookmarkDeletes");
      const at = bookmarks.findIndex((b) => b.id === (payload as { id?: string } | undefined)?.id);
      if (at >= 0) bookmarks.splice(at, 1);
      return null;
    }
    case "bookmark_save": {
      count("BookmarkSaves");
      const entry = (payload as { entry: Bookmark }).entry;
      const at = bookmarks.findIndex((b) => b.id === entry.id);
      if (at >= 0) bookmarks[at] = entry; else bookmarks.push(entry);
      return entry;
    }
    case "automation_list":
    case "extension_list":
    case "trash_list":
    case "patch_log_list":
    case "helper_profiles":
    case "sync_group_list":
      return [];

    // v2 scalar/status endpoints with a harmless default.
    case "data_root_get":
      return { path: "C:\\fixture\\shardx", movable: true };
    case "profile_sync_status":
      return null;
    case "team_status":
      return teamStatusFixture();
    case "team_set_connection": {
      const args = payload as { serverUrl?: string; token?: string; tenantId?: string };
      teamConnection = {
        server_url: String(args?.serverUrl ?? ""),
        tenant_id: String(args?.tenantId ?? ""),
        has_token: !!args?.token || teamConnection.has_token,
      };
      return teamStatusFixture();
    }
    case "team_test_connection":
      if (!teamConnection.server_url || !teamConnection.tenant_id) throw new Error("fixture team not configured");
      return "5e".repeat(16);
    case "team_fleet_custody_status":
      return fleetCustody;
    case "team_profiles_under_older_key":
      return [];
    // Copies, as IPC would: a later change must not reach the UI unless it refetches.
    case "team_profiles_status":
      if (Number(params.get("teamStatusDelay") ?? 0) > 0) await wait(Number(params.get("teamStatusDelay")));
      return structuredClone(teamProfiles);
    case "team_fleet_profiles":
      return structuredClone(teamFleet);
    case "team_join_profile": {
      count("Joins");
      const args = payload as { remoteProfileId?: string; localProfileId?: string };
      const remote = teamFleet.find((p) => p.remote_profile_id === args?.remoteProfileId);
      if (!remote) throw new Error("[[shardx:sync.profileNotListed]]");
      if (remote.bound_to) throw new Error("[[shardx:sync.remoteAlreadyBound]]");
      const local = String(args?.localProfileId ?? "");
      if (teamProfiles.profiles.some((p) => p.profile_id === local)) {
        throw new Error("[[shardx:sync.alreadyPublished]]");
      }
      remote.bound_to = local;
      teamProfiles.profiles.push(teamBinding(local, "AVAILABLE", {
        remote_version: remote.current_version,
      }));
      // The binding is filed, then the first pull fails: a retry pulls into it.
      if (params.get("teamJoinFailAfterBind") === "1") throw new Error("[[shardx:sync.remoteAhead]]");
      return 4096;
    }
    case "profile_sync_publish": {
      count("Publishes");
      const id = String((payload as { profileId?: string } | undefined)?.profileId ?? "");
      if (teamProfiles.profiles.some((p) => p.profile_id === id)) throw new Error("[[shardx:sync.alreadyPublished]]");
      // The server holds it at version 0 with the first lease this device owns.
      teamProfiles.profiles.push(teamBinding(id, "CHECKED_OUT", { remote_version: 0, lease_expires_at: teamLease }));
      return { profile_id: "d1".repeat(16), fencing_token: 1, lease_expires_at_ms: 4_070_908_800_000 };
    }
    case "profile_sync_cancel_publish":
      count("CancelPublishes");
      return null;
    case "profile_sync_push": {
      count("CheckIns");
      const b = teamBound(payload);
      Object.assign(b, {
        sync_state: "AVAILABLE", remote_version: b.remote_version + 1, dirty: false,
        lease_expires_at: null, lease_at_risk: false,
      });
      return teamPushResult(b.remote_version);
    }
    case "profile_sync_pull":
      count("Pulls");
      teamBound(payload);
      return 4096;
    case "profile_sync_revert": {
      count("Reverts");
      const b = teamBound(payload);
      Object.assign(b, {
        sync_state: "AVAILABLE", remote_version: b.remote_version + 1, dirty: false, lease_expires_at: null,
        last_error_code: null, revert_available: false, revert_in_progress: false,
      });
      return teamPushResult(b.remote_version);
    }
    case "team_unbind_profile": {
      count("Unbinds");
      const b = teamBound(payload);
      teamProfiles.profiles.splice(teamProfiles.profiles.indexOf(b), 1);
      for (const f of teamFleet) if (f.bound_to === b.profile_id) f.bound_to = null;
      return { local_profile_id: b.profile_id, response_sha256: "ef".repeat(32), discoverable: true };
    }
    case "team_keys_create_file":
      count("KeyFiles");
      keyState = { keys_protected: true, has_key_file: true, keys_locked: false };
      return teamStatusFixture();
    case "team_keys_unlock":
      if ((payload as { passphrase?: string } | undefined)?.passphrase !== "correct horse") {
        throw new Error("That is not the key file passphrase.");
      }
      keyState = { ...keyState, keys_locked: false };
      return teamStatusFixture();
    case "team_custody_bootstrap_status":
      return custodyBootstrap;
    case "plugin:dialog|save":
      count("SaveDialogs");
      return "C:\\Users\\Example\\shardx-recovery.shxrecovery";
    case "team_bootstrap_custody": {
      count("CustodyBootstraps");
      const args = payload as { recoveryPath?: string; passphrase?: string };
      document.documentElement.dataset.e2eCustodyPath = String(args?.recoveryPath ?? "");
      custodyBootstrap = {
        started: true,
        this_device: true,
        activated: true,
        recovery_path: custodyBootstrap.recovery_path || String(args?.recoveryPath ?? ""),
        anchor: "a0".repeat(32),
        root_key_id: TEAM_ROOT_KEY_ID,
        ...noRootRotation,
        ...renewalTimes(Date.now()),
      };
      return custodyBootstrap;
    }

    default:
      throw new Error(`Unhandled E2E command: ${cmd}`);
  }
}, { shouldMockEvents: true });
