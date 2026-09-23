export type Theme = "dark" | "light";
export type Section =
  | "browsers"
  | "proxies"
  | "proxyshard"
  | "automation"
  | "fingerprints"
  | "extensions"
  | "bookmarks"
  | "trash"
  | "patchlog"
  | "settings";

export type ToastItem = { id: number; kind: "ok" | "err" | "info"; text: string };

export type ConfirmButton = { label: string; value: any; danger?: boolean; primary?: boolean };
export type ConfirmReq = {
  title?: string;
  message: string;
  buttons: ConfirmButton[];
  resolve: (v: any) => void;
};

export type ContextItem = {
  label: string;
  onClick: () => void;
  danger?: boolean;
  sep?: boolean;
  /**
   * Why this item cannot be used right now. When set the item is shown but
   * inert, with the reason as its tooltip — better than letting someone click
   * and only then learn the profile has to be stopped first.
   */
  disabledReason?: string;
};

export type OsPlatform = "macOS" | "Windows" | "Linux";

export type IconProps = { size?: number; className?: string };

export type FieldProps = {
  label: string;
  value: string;
  onChange: (v: string) => void;
  type?: string;
  placeholder?: string;
  mono?: boolean;
};

export type CSOption<T> = { value: T; label: string };

export type RtSpec = {
  browser: { key: string; label: string };
  widevine: { key: string; label: string } | null;
};
export type RtStatus = {
  installed: boolean;
  binary_path: string | null;
  installed_browser_etag: string | null;
  remote_browser_etag: string | null;
  update_available: boolean;
  spec: RtSpec | null;
  fingerprints_installed: boolean;
  /** The published engine wants a newer launcher; no engine update is offered. */
  needs_newer_launcher: boolean;
  min_launcher_version: string | null;
  launcher_version: string;
};
export type RtProgress = {
  label: string;
  phase: "download" | "extract";
  received: number;
  total: number;
  percent: number;
};
export type RtUpdate = {
  current: string;
  latest: string | null;
  update_available: boolean;
  release_url: string | null;
  /// Release notes shown before the user consents to the download.
  notes?: string | null;
  pub_date?: string | null;
};
