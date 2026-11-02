import { mockIPC, mockWindows } from "@tauri-apps/api/mocks";
import type { InvokeArgs } from "@tauri-apps/api/core";
import type {
  TeamFleetProfile, TeamProfileStatus, TeamProfilesStatus,
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
const profiles = scenario === "profiles-empty" ? [] : fixtureProfiles;

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
let runtimeFailures = scenario === "runtime-error-once" ? 1 : 0;
let runtimeInstallFailures = scenario === "runtime-install-error-once" ? 1 : 0;
let runtimeNeedsInstall = scenario === "runtime-install-error-once";
let profileFailures = scenario === "profile-error-once" ? 1 : 0;
let profileListsInFlight = 0;
let maxProfileListsInFlight = 0;
let proxyListCalls = 0;
let proxyListsInFlight = 0;
let maxProxyListsInFlight = 0;

type E2EWindow = Window & { __resolveUpdateCheck?: () => void };

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
const firstDevice = scenario === "team-first-device" || scenario === "team-first-device-resume"
  || scenario === "team-keys-locked";
// The resumed setup also stands for a host whose credential store refused the
// keys; `team-keys-locked` for one whose keys sit in a key file not yet opened.
let keyState = scenario === "team-first-device-resume"
  ? { keys_protected: false, has_key_file: false, keys_locked: false }
  : scenario === "team-keys-locked"
    ? { keys_protected: true, has_key_file: true, keys_locked: true }
    : { keys_protected: true, has_key_file: false, keys_locked: false };
const teamStatusFixture = () => (firstDevice
  ? {
    server_url: "https://team.example.com",
    tenant_id: "11111111-1111-4111-8111-111111111111",
    device_id: "0123456789abcdef0123456789abcdef",
    has_token: true,
    is_enrolled: true,
    keys_unreadable: false,
    can_sync: true,
    can_receive_custody: true,
    has_fleet_key: false,
    ...keyState,
  }
  : {
    server_url: "",
    tenant_id: "",
    device_id: "",
    has_token: false,
    is_enrolled: false,
    keys_unreadable: false,
    can_sync: false,
    can_receive_custody: false,
    has_fleet_key: false,
    keys_protected: true,
    has_key_file: false,
    keys_locked: false,
  });
// `teamRefuse=<command>[,<command>]` makes those team commands refuse the way
// the backend does, before anything changes.
const teamRefusals = new Set((params.get("teamRefuse") ?? "").split(",").filter(Boolean));
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

let custodyBootstrap = scenario === "team-first-device-resume"
  ? { started: true, activated: false, recovery_path: "C:\\Users\\Example\\kept.shxrecovery", anchor: "" }
  : { started: false, activated: false, recovery_path: "", anchor: "" };

mockIPC(async (cmd: string, payload?: InvokeArgs) => {
  if (
    (cmd.startsWith("plugin:") || cmd.startsWith("tauri:"))
    && cmd !== "plugin:dialog|open" && cmd !== "plugin:dialog|save"
  ) {
    return null;
  }
  if (teamRefusals.has(cmd)) {
    throw new Error(`[[shardx:${TEAM_REFUSAL[cmd] ?? "sync.remoteAhead"}]]`);
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
      return profiles.some((profile) => profile.id === "profile-beta")
        ? [{
            profile_id: "profile-beta",
            pid: 4242,
            cdp: {
              port: 9222,
              http_url: "http://127.0.0.1:9222",
              web_socket_debugger_url: "ws://127.0.0.1:9222/devtools/browser/fixture",
            },
            uptime_ms: 5_000,
          }]
        : [];
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
    case "launch":
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
    case "automation_list":
    case "bookmark_list":
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
        activated: true,
        recovery_path: custodyBootstrap.recovery_path || String(args?.recoveryPath ?? ""),
        anchor: "a0".repeat(32),
      };
      return custodyBootstrap;
    }

    default:
      throw new Error(`Unhandled E2E command: ${cmd}`);
  }
}, { shouldMockEvents: true });
