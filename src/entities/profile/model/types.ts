export type NoiseMode = "real" | "auto";
export type WebRtcMode = "auto" | "tcp_only" | "block";
export type GeoMode = "auto" | "manual";

export type ProfileMeta = {
  id: string;
  name: string;
  notes: string;
  proxy_id: string | null;
  last_launched_at: string | null;
  created_at: string | null;
  pinned: boolean;
  folder: string;
  /// Cumulative engine uptime in ms across every launch.  Increased when
  /// the engine exits — for the currently-running session add `running[id]`
  /// (Date.now() - sessionStartTs) on top.
  total_runtime_ms: number;
  /// Icon accent, "#rrggbb"; null = derived from the name, as the browser does.
  color: string | null;
  /// Extension ids from the library, loaded at launch.
  extensions: string[];
  /// Tag names as the launcher normalized them; colors come from the tag store.
  tags: string[];
};

export type ProfileForm = {
  /** The document this form was loaded from, so a save cannot drop
   *  fields the editor does not render. Absent for new profiles. */
  _stored?: any;
  id: string;
  name: string;
  notes: string;
  proxy_id: string | null;
  /// "" = derive from the name, which is what the browser does on its own.
  color: string;
  /// Extension ids from the library.
  extensions: string[];

  gpu_preset_id: string;
  user_agent: string;
  hardware_concurrency: number;
  device_memory: number;
  /// Sec-CH-UA-Platform-Version override; empty = use donor preset's value.
  platform_version: string;

  timezone: string;
  language: string;

  webrtc: WebRtcMode;
  do_not_track: boolean;
  /// False keeps the browser from reopening last session's tabs on launch.
  /// Automation profiles accumulate tabs nobody closes; restoring them all
  /// makes every reopen slower for no gain.
  restore_session: boolean;

  noise_canvas: NoiseMode;
  noise_webgl: NoiseMode;
  noise_audio: NoiseMode;
  noise_client_rects: NoiseMode;
  noise_sensors: NoiseMode;
  /// Fonts: "real" passes host fonts through; "auto" hides a ~3% per-profile subset.
  noise_fonts: NoiseMode;
  /// TCP ports the browser refuses to connect to (RDP/VNC/TeamViewer/Squid).
  blocked_ports: number[];

  geo_mode: GeoMode;
  geo_lat: number;
  geo_lng: number;
  geo_accuracy: number;

  media_audio_in: number;
  media_audio_out: number;
  media_video_in: number;
};
