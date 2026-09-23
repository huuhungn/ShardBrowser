import type { ProfileForm, NoiseMode } from "./types";
import type { FingerprintEntry } from "../../fingerprint/model/types";
import { AUTO_TZ, AUTO_LANG, DEFAULT_BLOCKED_PORTS, WEBGL_NOISE_INTENSITY, CLIENT_RECTS_MAX_OFFSET } from "../../../shared/constants";
import { deriveAcceptLanguage, deriveLanguagesArray } from "../../../shared/lib/utils";

export const defaultForm = (): ProfileForm => ({
  id: "",
  name: "",
  notes: "",
  proxy_id: null,
  color: "",
  extensions: [],

  // Empty until snapped to gpusForOs[0] by useEffect.
  gpu_preset_id: "",
  user_agent:
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36",
  hardware_concurrency: 8,
  device_memory: 16,
  // Empty = inherit donor; setGpu refreshes via enrich_picks_for_preset.
  platform_version: "",

  timezone: AUTO_TZ,
  language: AUTO_LANG,

  webrtc: "auto",
  do_not_track: false,
  // Matches the browser's own default and the Rust side's absent-key default.
  restore_session: true,

  noise_canvas: "real",
  noise_webgl: "real",
  noise_audio: "real",
  noise_client_rects: "real",
  noise_sensors: "real",
  noise_fonts: "real",
  blocked_ports: DEFAULT_BLOCKED_PORTS.slice(),

  geo_mode: "auto",
  geo_lat: 52.2297,
  geo_lng: 21.0122,
  geo_accuracy: 50,

  media_audio_in: 1,
  media_audio_out: 1,
  media_video_in: 1,
});

export function fromStored(stored: any): ProfileForm {
  const f = defaultForm();
  if (!stored) return f;
  // Keep the document we loaded. The editor only knows the fields it renders,
  // so anything else on disk (custom_fonts and other launcher-managed or
  // future keys) would be dropped on save unless we carry it through.
  f._stored = stored;
  f.id = stored?._meta?.id ?? "";
  f.proxy_id = stored?._meta?.proxy_id ?? null;
  f.name = stored?.name ?? "";
  f.notes = stored?.notes ?? "";
  f.color = stored?._meta?.color ?? "";
  f.extensions = Array.isArray(stored?._meta?.extensions) ? stored._meta.extensions : [];
  // Empty for legacy profiles; snapped by useEffect.
  f.gpu_preset_id = stored?._meta?.gpu_preset_id ?? "";
  f.user_agent = stored?.navigator?.user_agent ?? f.user_agent;
  f.hardware_concurrency = stored?.navigator?.hardware_concurrency ?? 8;
  f.device_memory = stored?.navigator?.device_memory ?? 16;
  // The OS version sites read. Absent from the form meant the editor forgot it
  // on every load, and save then rebuilt it from the preset — so editing an
  // unrelated toggle silently moved the profile to a different OS release.
  // client_hints is the fallback: a profile written before navigator carried
  // the key still has it there, and the two are written together on save.
  f.platform_version =
    stored?.navigator?.platform_version ?? stored?.client_hints?.platform_version ?? "";
  f.timezone = stored?.timezone ?? AUTO_TZ;
  f.language = stored?.navigator?.language ?? AUTO_LANG;
  f.webrtc = (stored?.webrtc === "replace" ? "tcp_only" : stored?.webrtc) ?? "auto";
  f.do_not_track = !!stored?.navigator?.do_not_track;
  // Absent means "restore", matching the Rust parser and pre-existing profiles.
  f.restore_session = stored?.launch?.restore_session !== false;

  const noise = stored?.noise ?? {};
  const noiseMode = (n: any): NoiseMode => (n?.enabled ? "auto" : "real");
  f.noise_canvas = noiseMode(noise.canvas);
  f.noise_webgl = noiseMode(noise.webgl);
  f.noise_audio = noiseMode(noise.audio);
  f.noise_client_rects = noiseMode(noise.client_rects);
  f.noise_sensors = noiseMode(noise.sensors);
  // Fonts default OFF (real); mirrors C++ default.
  f.noise_fonts = noiseMode(noise.fonts);
  f.blocked_ports = Array.isArray(stored?.blocked_ports)
    ? stored.blocked_ports.filter((n: any) => typeof n === "number")
    : DEFAULT_BLOCKED_PORTS.slice();

  const geo = stored?.geolocation ?? {};
  f.geo_mode = geo.mode === "manual" ? "manual" : "auto";
  f.geo_lat = typeof geo.latitude === "number" ? geo.latitude : f.geo_lat;
  f.geo_lng = typeof geo.longitude === "number" ? geo.longitude : f.geo_lng;
  f.geo_accuracy = typeof geo.accuracy === "number" ? geo.accuracy : f.geo_accuracy;

  const md = stored?.media_devices ?? {};
  f.media_audio_in = md.audio_input_count ?? 1;
  f.media_audio_out = md.audio_output_count ?? 1;
  f.media_video_in = md.video_input_count ?? 1;

  return f;
}

/// Build on-disk FingerprintConfig from library payload + user-edited fields.
export function toStored(f: ProfileForm, lib: FingerprintEntry | null): any {
  // Start from what was on disk so unrendered fields survive the edit; a new
  // fingerprint library payload is layered on top of it, not instead of it.
  const prior: any = f._stored ? JSON.parse(JSON.stringify(f._stored)) : {};
  const libPayload: any = lib && lib.payload ? JSON.parse(JSON.stringify(lib.payload)) : {};
  const base: any = { ...prior, ...libPayload };

  base._meta = {
    id: f.id,
    proxy_id: f.proxy_id,
    last_launched_at: null,
    gpu_preset_id: f.gpu_preset_id,
    // Absent, not empty: that is what "derive it" means on disk.
    ...(f.color ? { color: f.color } : {}),
    extensions: f.extensions,
  };
  base.name = f.name || "untitled";
  base.notes = f.notes;
  // "auto" sentinel: resolver replaces at launch; persists across edits.
  base.timezone = f.timezone;
  base.icu_locale = f.language === AUTO_LANG ? null : f.language;
  base.webrtc = f.webrtc;

  // Keep any other launch keys (args, extension_dirs) the editor never renders.
  // True is the default, so write the key only when opting out — an absent key
  // reads as "restore" on the Rust side and keeps profiles free of noise.
  const priorLaunch = { ...(base.launch || {}) };
  delete priorLaunch.restore_session;
  const launch = f.restore_session ? priorLaunch : { ...priorLaunch, restore_session: false };
  if (Object.keys(launch).length > 0) base.launch = launch;
  else delete base.launch;

  base.navigator = {
    ...(base.navigator || {}),
    language: f.language,
    accept_language: f.language === AUTO_LANG ? null : deriveAcceptLanguage(f.language),
    languages: f.language === AUTO_LANG ? null : deriveLanguagesArray(f.language),
    user_agent: f.user_agent,
    hardware_concurrency: f.hardware_concurrency,
    device_memory: f.device_memory,
    // Empty → inherit donor; set → write to both navigator + client_hints.
    ...(f.platform_version ? { platform_version: f.platform_version } : {}),
    do_not_track: f.do_not_track ? "1" : null,
  };
  if (f.platform_version) {
    base.client_hints = {
      ...(base.client_hints || {}),
      platform_version: f.platform_version,
    };
  }

  base.media_devices = {
    audio_input_count: f.media_audio_in,
    audio_output_count: f.media_audio_out,
    video_input_count: f.media_video_in,
  };

  base.geolocation =
    f.geo_mode === "manual"
      ? { mode: "manual", latitude: f.geo_lat, longitude: f.geo_lng, accuracy: f.geo_accuracy }
      : { mode: "auto" };

  // seed: 0 is the "derive automatically" sentinel — the launcher fills each
  // vector with a stable per-profile seed once the real profile id exists
  // (see fill_noise_seeds in profile.rs).  Computing seeds here is impossible
  // for new profiles (no id yet) and previously collapsed every new profile
  // onto one shared seed, giving them all an identical fingerprint.
  base.noise = {
    canvas:       { enabled: f.noise_canvas === "auto",       seed: 0 },
    webgl:        { enabled: f.noise_webgl === "auto",        seed: 0, intensity: f.noise_webgl === "auto" ? WEBGL_NOISE_INTENSITY : 0 },
    audio:        { enabled: f.noise_audio === "auto",        seed: 0 },
    client_rects: { enabled: f.noise_client_rects === "auto", seed: 0, max_offset: f.noise_client_rects === "auto" ? CLIENT_RECTS_MAX_OFFSET : 0 },
    sensors:      { enabled: f.noise_sensors === "auto",      seed: 0 },
    fonts:        { enabled: f.noise_fonts === "auto",        seed: 0 },
  };
  base.blocked_ports = [...f.blocked_ports].sort((a, b) => a - b);

  return base;
}
