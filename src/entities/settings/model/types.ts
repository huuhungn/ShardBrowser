
/** The translate function, taken as an argument so a label is built when it
 *  is drawn rather than when this module is first imported. */
type Tr = (key: string, vars?: Record<string, string | number>) => string;

export type Settings = {
  browser_path: string | null;
  theme: string;
  geo_checker?: string | null;
  screen_resolution_mode?: string | null;
  api_enabled?: boolean;
  api_port?: number;
  api_secret?: string;
  /** Shard Helper: offer to fill forms a generated identity fits. */
  helper_enabled?: boolean;
  /** Start ShardX when the user signs in. */
  launch_at_login?: boolean;
  /** Start hidden in the tray rather than showing the window. */
  start_minimized?: boolean;
  /** Which field kinds it reacts to. Empty means all of them. */
  helper_triggers?: string[];
  /** Profile's camera is ShardX's rather than the machine's. */
  camera_enabled?: boolean;
  /** Hide to the tray on close instead of quitting. */
  minimize_to_tray?: boolean;
  /** Appended to every launch, one per line. Applied last, so a repeat wins. */
  extra_args?: string;
};

/** Where profiles, user-data, extensions and the trash live. */
export type DataRootInfo = {
  path: string;
  /** False while the data still sits in the config dir. */
  custom: boolean;
  migrating: boolean;
};

/** Progress of a data-root move, as `data-migration` events carry it. */
export type MigrationProgress = {
  phase: "scan" | "copy" | "verify" | "cleanup" | "done";
  done: number;
  total: number;
  percent: number;
  current: string;
};

/** The kinds the engine publishes, and what they are called to a person. */
export const helperKinds = (t: Tr): { value: string; label: string }[] => [
  { value: "first_name",  label: t("helper.firstName") },
  { value: "last_name",   label: t("helper.lastName") },
  { value: "full_name",   label: t("helper.fullName") },
  { value: "email",       label: t("helper.email") },
  { value: "username",    label: t("helper.username") },
  { value: "phone",       label: t("helper.phone") },
  { value: "country",     label: t("helper.country") },
  { value: "city",        label: t("helper.city") },
  { value: "postal_code", label: t("helper.postcode") },
  { value: "street",      label: t("helper.address") },
  { value: "birth_date",  label: t("helper.dateOfBirth") },
  { value: "birth_day",   label: t("helper.birthDay") },
  { value: "birth_month", label: t("helper.birthMonth") },
  { value: "birth_year",  label: t("helper.birthYear") },
  { value: "gender",      label: t("helper.gender") },
];

export type ApiInfo = {
  enabled: boolean;
  port: number;
  base_url: string;
  token: string;
  /** Where the API actually bound, which can differ from the requested port. */
  runtime_base_url?: string | null;
  /** Set when the listener failed to bind, so readiness can say why. */
  error?: string | null;
};

/** Whether the OS runs the Launcher at sign-in for the current user. */
export type StartupStatus = {
  registered: boolean;
  scope: string | null;
  detail: string | null;
};

/** Readiness of the on-demand MCP stdio server. */
export type McpStatus = {
  path: string | null;
  installed: boolean;
  files_downloaded: boolean;
  lockfile_present: boolean;
  version: string | null;
  version_current: boolean;
  required_version: string | null;
  dependencies_installed: boolean;
  api_reachable: boolean;
  ready: boolean;
  state: "not_downloaded" | "update_available" | "dependencies_missing" | "api_unavailable" | "ready" | "missing";
  message: string | null;
};

/** How Codex registered this Launcher's MCP server, if at all. */
export type CodexMcpStatus = {
  state: "ready" | "needs_repair" | "disabled" | "unsupported_transport" | "not_configured";
  issues: string[];
  repair_command: string | null;
  config_path: string | null;
};

/** How Hermes registered this Launcher's MCP server, if at all. */
export type HermesMcpStatus = {
  state:
    | "registered"
    | "needs_repair"
    | "disabled"
    | "not_registered"
    | "hermes_not_found"
    | "timeout"
    | "unavailable";
  available: boolean;
  registered: boolean;
  ready: boolean;
  index_path: string | null;
  expected_index_path: string | null;
  path_matches: boolean | null;
  api: string | null;
  expected_api: string;
  api_matches: boolean | null;
  token_in_config: boolean;
  message: string;
  issues: string[];
};
