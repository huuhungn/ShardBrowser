import { t } from "../i18n";

/// "auto" sentinel; the Rust launch resolver replaces with concrete TZ.
export const AUTO_TZ = "auto";
export const AUTO_LANG = "auto";

export const TIMEZONES = [
  AUTO_TZ,
  "America/Chicago", "America/Denver", "America/Los_Angeles", "America/New_York",
  "America/Sao_Paulo", "America/Toronto",
  "Asia/Bangkok", "Asia/Dubai", "Asia/Hong_Kong", "Asia/Jakarta", "Asia/Kolkata",
  "Asia/Seoul", "Asia/Shanghai", "Asia/Singapore", "Asia/Tokyo",
  "Australia/Sydney",
  "Europe/Amsterdam", "Europe/Athens", "Europe/Berlin", "Europe/Bucharest",
  "Europe/Helsinki", "Europe/Istanbul", "Europe/Kyiv", "Europe/Lisbon",
  "Europe/London", "Europe/Madrid", "Europe/Moscow", "Europe/Paris",
  "Europe/Prague", "Europe/Rome", "Europe/Stockholm", "Europe/Warsaw",
  "Europe/Vienna", "Europe/Zurich",
  "Pacific/Auckland", "UTC",
];

export const LOCALES: { code: string; label: string }[] = [
  { code: AUTO_LANG, label: t("profile.autoFromProxyGeo") },
  { code: "en-US", label: "English (US)" },
  { code: "en-GB", label: "English (UK)" },
  { code: "en-CA", label: "English (Canada)" },
  { code: "en-AU", label: "English (Australia)" },
  { code: "de-DE", label: "Deutsch (Deutschland)" },
  { code: "es-ES", label: "Español (España)" },
  { code: "es-MX", label: "Español (México)" },
  { code: "fr-FR", label: "Français (France)" },
  { code: "it-IT", label: "Italiano" },
  { code: "nl-NL", label: "Nederlands" },
  { code: "pl-PL", label: "Polski" },
  { code: "pt-BR", label: "Português (Brasil)" },
  { code: "pt-PT", label: "Português (Portugal)" },
  { code: "ro-RO", label: "Română" },
  { code: "ru-RU", label: "Русский" },
  { code: "uk-UA", label: "Українська" },
  { code: "tr-TR", label: "Türkçe" },
  { code: "el-GR", label: "Ελληνικά" },
  { code: "cs-CZ", label: "Čeština" },
  { code: "sv-SE", label: "Svenska" },
  { code: "fi-FI", label: "Suomi" },
  { code: "no-NO", label: "Norsk" },
  { code: "da-DK", label: "Dansk" },
  { code: "hu-HU", label: "Magyar" },
  { code: "zh-CN", label: "中文 (简体)" },
  { code: "zh-TW", label: "中文 (繁體)" },
  { code: "ja-JP", label: "日本語" },
  { code: "ko-KR", label: "한국어" },
  { code: "ar-SA", label: "العربية" },
  { code: "he-IL", label: "עברית" },
  { code: "id-ID", label: "Bahasa Indonesia" },
  { code: "vi-VN", label: "Tiếng Việt" },
  { code: "th-TH", label: "ไทย" },
  { code: "hi-IN", label: "हिन्दी" },
];

// Constrained options: stay within values Chrome actually reports.
export const MEMORY_OPTIONS = [4, 8, 16, 32];
export const CPU_OPTIONS = [2, 4, 6, 8, 10, 12, 14, 16, 20, 24];
export const MEDIA_COUNT_OPTIONS = [0, 1, 2, 3];

/// Common remote-control/proxy ports to block from outgoing browser connects.
export const DEFAULT_BLOCKED_PORTS = [
  3389, // RDP
  5900, // VNC
  5901, // VNC
  5800, // VNC HTTP
  7070, // RealVNC / RealAudio
  6568, // AnyDesk
  5938, // TeamViewer
  1080, // SOCKS
  8080, // HTTP proxy
  3128, // Squid
  3030, // misc
];

// "Maximally soft" anti-fingerprint defaults: the smallest perturbation that
// still shifts the fingerprint hash without visibly degrading rendering.
// max_offset can't drop below 1 (0 = off), so client_rects is already at its
// gentlest floor.
export const WEBGL_NOISE_INTENSITY = 0.0005;
export const CLIENT_RECTS_MAX_OFFSET = 1;

export const OS_OPTIONS: { id: string; label: string }[] = [
  { id: "macOS",   label: "macOS"   },
  { id: "Windows", label: "Windows" },
  { id: "Linux",   label: "Linux"   },
];
