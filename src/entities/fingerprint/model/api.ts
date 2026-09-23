import { invoke } from "@tauri-apps/api/core";
import type { FingerprintEntry, GpuCompat, HostGlCaps } from "./types";

export const fingerprintList = () => invoke<FingerprintEntry[]>("fingerprint_list");
export const fingerprintDelete = (id: string) => invoke("fingerprint_delete", { id });
export const fingerprintImport = (jsonText: string, idHint: string | null) => invoke<FingerprintEntry>("fingerprint_import", { jsonText, idHint });
export const fingerprintDir = () => invoke<string>("fingerprint_dir");

/// What this machine's GPU can actually do. Slow on the first call: the engine is
/// started off-screen to be asked, then the answer is cached against its version.
export const gpuCaps = (force = false) => invoke<HostGlCaps>("gpu_caps", { force });

/// Per-library-fingerprint verdicts, keyed by id. An empty map means "not known".
export const gpuCompat = () => invoke<Record<string, GpuCompat>>("gpu_caps_compat");
