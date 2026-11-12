export type ProxyEntry = {
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

export type ProxyTestStatus = "working" | "unstable" | "failed";
export type ProxyFailureReason =
  | "authentication_failed"
  | "timeout"
  | "dns_failed"
  | "unreachable"
  | "protocol_error";

export type ProxyTestSnapshot = {
  first_seen: string;
  last_seen: string;
  ip: string;
  country_code: string;
  country: string;
  region: string;
  city: string;
  isp: string;
  timezone: string;
  latitude: number;
  longitude: number;
  tcp_ms: number | null;
  udp_ms: number | null;
  udp_error: string | null;
  provider: string;
  /** Absent on snapshots saved before retries existed. */
  status?: ProxyTestStatus | null;
  failure_reason?: ProxyFailureReason | null;
  attempts?: number;
};

export type BulkRowState = {
  entry: ProxyEntry;
  selected: boolean;
  status: "idle" | "testing" | "ok" | "fail";
  tcp_ms?: number | null;
  udp_ms?: number | null;
  country?: string;
  error?: string;
};
