import { invoke } from "@tauri-apps/api/core";
import { t } from "../i18n";

// Host OS of the launcher window (never spoofed) — drives default OS tab + titlebar.
export function detectHostOs(): "macOS" | "Windows" | "Linux" {
  // Node had no global navigator before v21, and the bundled tests import
  // this module outside a browser. Without a user agent, fall back.
  const ua = typeof navigator === "undefined" ? "" : navigator.userAgent;
  if (/Windows/i.test(ua)) return "Windows";
  if (/Macintosh|Mac OS X/i.test(ua)) return "macOS";
  if (/Linux|X11|CrOS/i.test(ua)) return "Linux";
  return "macOS";
}

export const HOST_OS = detectHostOs();

/// "@1700000000" → "May 26, 14:30" (UTC for cross-timezone consistency).
export function fmtTs(stamp: string): string {
  if (!stamp.startsWith("@")) return stamp;
  const n = parseInt(stamp.slice(1), 10);
  if (!Number.isFinite(n)) return stamp;
  const d = new Date(n * 1000);
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

/// Format ms uptime as "1h 23m" / "12m 30s" / "45s".
export function fmtUptime(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${sec.toString().padStart(2, "0")}s`;
  return `${sec}s`;
}

/// Byte count as "4.2 MB". Base 1024, which is what a file manager shows.
export function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const v = n / 1024 ** i;
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${units[i]}`;
}

/// Whole days from now until a unix-second instant; 0 once it has passed.
export function daysUntil(unixSecs: number): number {
  return Math.max(0, Math.ceil((unixSecs * 1000 - Date.now()) / 86_400_000));
}

// Single UTM tag appended to every outbound proxyshard.com link.
export const UTM_QS = "utm_source=shardx&utm_medium=referral&utm_campaign=shardx-launcher";
export const withUtm = (url: string) => url + (url.includes("?") ? "&" : "?") + UTM_QS;

// ProxyShard dashboard (account, billing, API key).
export const DASHBOARD_URL = withUtm("https://dashboard.proxyshard.com/");

// Docs URL behind the proxy UDP/No-UDP pill.
export const UDP_DOCS_URL = withUtm("https://docs.proxyshard.com/eng/our-products/about-udp");

export const GH_REPO_URL = "https://github.com/ProxyShard/ShardBrowser";

/// Build accept-language chain (primary → base → English fallback).
export function deriveAcceptLanguage(loc: string): string {
  if (!loc) return "en-US,en;q=0.9";
  const base = loc.split("-")[0];
  if (loc === "en-US") return "en-US,en;q=0.9";
  return `${loc},${base};q=0.9,en-US;q=0.8,en;q=0.7`;
}

export function deriveLanguagesArray(loc: string): string[] {
  if (!loc) return ["en-US", "en"];
  const base = loc.split("-")[0];
  if (loc === "en-US") return ["en-US", "en"];
  return [loc, base, "en-US", "en"];
}

// 12-char lowercase alnum sticky-session id (matches ProxyShard's `sid` form).
export const randSid = () => {
  const a = "abcdefghijklmnopqrstuvwxyz0123456789";
  let s = "";
  for (let i = 0; i < 12; i++) s += a[Math.floor(Math.random() * a.length)];
  return s;
};

export const fmtCents = (c: number) => `$${(Number(c || 0) / 100).toFixed(2)}`;

export const fmtGB = (bytes: number) => {
  const gb = Number(bytes || 0) / 1024 ** 3;
  return `${gb >= 100 ? gb.toFixed(0) : gb.toFixed(2)} GB`;
};

export const isDcIsp = (name: string) => /datacenter|isp/i.test(name);

/// available-count product code for a base product name.
export const availCode = (name: string) => (/datacenter/i.test(name) ? "dc" : /isp/i.test(name) ? "isp" : "");

export const readTextFile = (path: string) => invoke<string>("read_text_file", { path });

/**
 * Turn a backend error code into interface language.
 *
 * Tauri commands answer with a plain `String`, so there is no room for a
 * structured error payload without changing every command signature and all
 * 113 call sites that catch one. Instead the backend emits a marker —
 * `[[shardx:launch.browserMissing]]`, optionally `|name=value` arguments —
 * and the lookup happens here, where the chosen language actually lives.
 *
 * Rust cannot do the translating itself: the language is a browser-side
 * setting in localStorage, and shipping a second copy of the dictionary into
 * the binary would leave two catalogues to keep in step.
 *
 * Unknown codes fall through to the English sentence the backend sent, so a
 * missing key degrades to today's behaviour rather than to an empty toast.
 */
export const localiseBackendError = (text: string): string =>
  text.replace(/\[\[shardx:([a-zA-Z0-9_.]+)((?:\|[a-zA-Z0-9_]+=[^\]|]*)*)\]\]/g, (whole, key, rawArgs) => {
    const vars: Record<string, string> = {};
    for (const pair of String(rawArgs).split("|")) {
      if (!pair) continue;
      const eq = pair.indexOf("=");
      if (eq > 0) vars[pair.slice(0, eq)] = pair.slice(eq + 1);
    }
    const translated = t(key, vars);
    // `translate` echoes the key back when it is missing from every
    // dictionary. Showing "launch.browserMissing" to an operator is worse
    // than showing the original English, so keep the marker's own text.
    return translated === key ? whole : translated;
  });

/**
 * Error text safe to show in the UI.
 *
 * Backend errors can quote the request that failed, and that request may carry
 * the API token. Toasts get screenshotted and pasted into chats, so scrub the
 * credential before it is ever rendered.
 */
export const safeUiError = (error: unknown) => {
  const text = error instanceof Error ? error.message : String(error);
  return (
    localiseBackendError(text)
      .replace(/Bearer\s+[^\s"']+/gi, "Bearer ***")
      .replace(/("SHARDX_TOKEN"\s*:\s*")[^"]*(")/gi, "$1***$2")
      .replace(/SHARDX_TOKEN\s*=\s*[^\s;]+/gi, "SHARDX_TOKEN=***")
      // Proxy URLs carry credentials inline; a failed connection would
      // otherwise print user:pass straight into a toast.
      .replace(/(\w+:\/\/)[^\s/@:]+:[^\s/@]+@/g, "$1***:***@")
      // Long hex runs are key material, tokens or device ids. Nothing the
      // user can act on, and the first two are secret.
      .replace(/\b[0-9a-f]{32,}\b/gi, (m) => `${m.slice(0, 8)}…[redacted]`)
      // Passphrases echoed back by a failing call.
      .replace(/(passphrase\s*[:=]\s*)\S+/gi, "$1***")
  );
};
