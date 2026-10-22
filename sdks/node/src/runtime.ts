// Runtime cache: download ShardX engine + Widevine CDM + fingerprint
// library from the ProxyShard CDN, extract into a per-user cache dir,
// place Widevine inside the engine bundle, remember etags so subsequent
// runs are zero-network. Mirrors src-tauri/src/runtime.rs in the launcher.
import { closeSync, createWriteStream, existsSync, mkdirSync, openSync, readdirSync, readFileSync, readSync, renameSync, rmSync, statSync, writeFileSync, chmodSync, copyFileSync, lstatSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { homedir, platform as osPlatform, arch as osArch } from "node:os";
import { join, dirname, resolve } from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { spawnSync } from "node:child_process";

export const PUB_BASE = "https://pub-e57a7c60f6934eb09a6600bf2fc59cdc.r2.dev";
export const CHROMIUM_VERSION = "156.0.8078.48";
/** This SDK's own version, compared against the manifest's `min_sdk_version`. */
export const SDK_VERSION = "2.1.0";
// Version manifest (GitHub raw) — one tiny GET yields every archive's current
// etag, so we never poll R2/S3 (no per-archive HEAD). Changed archives are then
// pulled from PUB_BASE.
export const MANIFEST_URL = "https://raw.githubusercontent.com/huuhungn/ShardBrowser/main/runtime.json";

export function defaultCacheDir(): string {
  const plat = osPlatform();
  if (plat === "darwin") return join(homedir(), "Library", "Application Support", "shardx-sdk");
  if (plat === "win32")  return join(process.env.LOCALAPPDATA ?? homedir(), "shardx-sdk");
  return join(process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache"), "shardx-sdk");
}

export interface Archive { key: string; label: string; }

export interface HostSpec {
  browser: Archive;
  widevine: Archive | null;
  binarySubpath: string[];
  widevineSubpath: string[];
}

export function hostSpec(): HostSpec {
  const plat = osPlatform();
  const arch = osArch();
  if (plat === "darwin" && arch === "arm64") {
    return {
      browser:  { key: "ShardX-Mac-arm64.zip",          label: "ShardX browser (macOS arm64)" },
      widevine: { key: "ShardX-Widevine-Mac-arm64.zip", label: "Widevine CDM" },
      binarySubpath:   ["ShardX-Mac-arm64", "ShardX.app", "Contents", "MacOS", "ShardX"],
      widevineSubpath: ["ShardX-Mac-arm64", "ShardX.app", "Contents", "Frameworks",
                        "ShardX Framework.framework", "Versions", CHROMIUM_VERSION,
                        "Libraries", "WidevineCdm"],
    };
  }
  if (plat === "win32" && arch === "x64") {
    return {
      browser:  { key: "ShardX-Windows.zip",     label: "ShardX browser (Windows x64)" },
      widevine: { key: "ShardX-Widevine-Win.zip", label: "Widevine CDM" },
      binarySubpath:   ["ShardX-Windows", "chrome.exe"],
      widevineSubpath: ["ShardX-Windows", "WidevineCdm"],
    };
  }
  if (plat === "linux" && arch === "x64") {
    return {
      browser:  { key: "ShardX-Linux.zip",         label: "ShardX browser (Linux x64)" },
      widevine: { key: "ShardX-Widevine-Linux.zip", label: "Widevine CDM" },
      binarySubpath:   ["ShardX-Linux", "chrome"],
      widevineSubpath: ["ShardX-Linux", "WidevineCdm"],
    };
  }
  throw new Error(`Unsupported host: ${plat}/${arch}. ShardX ships mac-arm64, win-x64, linux-x64.`);
}

export const FINGERPRINTS_ARCHIVE: Archive = {
  key: "ShardX-Fingerprints.zip",
  label: "Fingerprint library",
};
const FINGERPRINTS_TOP_DIR = "shardx-fingerprints";

export type ProgressCb = (label: string, received: number, total: number) => void;

/** @internal Shared extraction boundary for the two Windows/plain-data archives.
 *
 *  Windows has no `unzip`, so it uses bsdtar (`tar.exe`, shipped since Windows
 *  10 build 17063), which reads zip archives. Everywhere else GNU tar cannot
 *  read zip at all, so this defers to the same `unzip` the engine bundles use.
 *  Both refuse entries whose paths escape the destination, where adm-zip
 *  followed them and let a crafted archive overwrite arbitrary files
 *  (GHSA-vwc7-r8mq-g2x9). */
export function extractZipArchive(archive: string, destination: string): void {
  mkdirSync(destination, { recursive: true });

  if (osPlatform() !== "win32") {
    systemUnzip(archive, destination);
    return;
  }

  const r = spawnSync(systemTar(), ["-x", "-f", archive, "-C", destination], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  if (r.error) {
    if ((r.error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(
        "system `tar` not found — Windows 10 build 17063 or newer provides it at %SystemRoot%\\System32\\tar.exe",
      );
    }
    throw r.error;
  }
  if ((r.status ?? 0) !== 0) {
    const err = r.stderr?.toString().slice(0, 400) ?? `exit ${r.status}`;
    throw new Error(`tar failed for ${archive} (exit ${r.status}): ${err}`);
  }
}

/** Prefer the System32 copy on Windows: PATH may lead to an MSYS/Git tar that
 *  mangles drive-letter arguments like `C:\dest`. */
function systemTar(): string {
  const system32 = join(process.env.SystemRoot ?? "C:\\Windows", "System32", "tar.exe");
  return existsSync(system32) ? system32 : "tar";
}

interface Manifest {
  browser_etag?: string;
  widevine_etag?: string;
  fingerprints_etag?: string;
  /** Chromium version of the engine binary last extracted on disk. The update
   *  is detected by comparing this (or the on-disk version) to the manifest's
   *  chromium version — robust where the etag check failed. */
  installed_chromium_version?: string;
  /** Build stamp of the archive last extracted; fallback when it ships none. */
  installed_engine_build?: string;
}

export class Runtime {
  readonly root: string;
  readonly spec: HostSpec;
  private readonly progress?: ProgressCb;
  private readonly _profilesRoot?: string;
  /** Set after a successful in-process install() so subsequent launches
   *  skip the R2 HEAD round-trip (~1 s over a clean connection).  Cleared
   *  by `install({force: true})`. */
  private _checkedInProcess = false;
  /** Engine chromium version from the manifest (fallback to the build-time
   *  constant). Used by launch to normalise profile UA + client_hints. */
  private _chromiumVersion: string = CHROMIUM_VERSION;
  /** GREASE brand/version from the manifest (rotates per release; can't be
   *  derived from the version number). Applied to profiles on launch. */
  private _greaseBrand?: string;
  private _greaseVersion?: string;
  /** TLS block from the manifest (signature_algorithms / cipher_suites).
   *  Applied to profiles on launch so the JA4 hash keeps matching the Chrome
   *  version the profile claims — 152 added the ML-DSA signature schemes, and
   *  a profile still carrying the previous list is a mismatch. */
  private _tls?: Record<string, unknown>;

  constructor(opts: { cacheDir?: string; progress?: ProgressCb; profilesDir?: string } = {}) {
    this.root = opts.cacheDir ?? defaultCacheDir();
    mkdirSync(this.root, { recursive: true });
    this._profilesRoot = opts.profilesDir ? resolve(opts.profilesDir) : undefined;
    this.progress = opts.progress;
    this.spec = hostSpec();
  }

  get manifestPath(): string  { return join(this.root, "manifest.json"); }
  get binaryPath(): string    { return join(this.root, ...this.spec.binarySubpath); }
  get fingerprintsDir(): string {
    const d = join(this.root, "fingerprints");
    mkdirSync(d, { recursive: true });
    return d;
  }
  /** Per-profile user-data-dir root. Defaults to `<cacheDir>/profiles/`;
   *  override via `new ShardX({ profilesDir })` or per-launch
   *  `userDataDir`. Resolved path is logged at launch time. */
  get profilesRoot(): string {
    const d = this._profilesRoot ?? join(this.root, "profiles");
    mkdirSync(d, { recursive: true });
    return d;
  }
  get installed(): boolean    { return existsSync(this.binaryPath); }
  /** Engine chromium version (manifest-driven; set on install()). */
  get chromiumVersion(): string { return this._chromiumVersion; }
  /** GREASE brand from the manifest (e.g. "Not)A;Brand"); set on install(). */
  get greaseBrand(): string | undefined { return this._greaseBrand; }
  /** GREASE version from the manifest (e.g. "24"); set on install(). */
  get greaseVersion(): string | undefined { return this._greaseVersion; }
  /** TLS overrides from the manifest; set on install(). */
  get tls(): Record<string, unknown> | undefined { return this._tls; }

  /** Chromium version of the engine actually on disk (mac Framework
   *  `Versions/<ver>/`, win `<ver>.manifest`), or undefined on Linux. */
  private installedEngineVersion(): string | undefined {
    try {
      const plat = osPlatform();
      if (plat === "darwin") {
        const versions = join(this.root, "ShardX-Mac-arm64", "ShardX.app", "Contents",
          "Frameworks", "ShardX Framework.framework", "Versions");
        const v = readdirSync(versions).find((n) => n !== "Current" && /^\d/.test(n));
        return v;
      }
      if (plat === "win32") {
        // Only accept a `<version>.manifest` whose stem parses as a version,
        // so a stray/leftover manifest can't feed a bogus version.
        return readdirSync(join(this.root, "ShardX-Windows"))
          .filter((f) => f.endsWith(".manifest"))
          .map((f) => f.replace(/\.manifest$/, ""))
          .find((s) => /^\d/.test(s) && s.includes("."));
      }
      return undefined; // linux: no on-disk version marker
    } catch { return undefined; }
  }

  /** Effective installed version. Trusts the version recorded at install time
   *  (authoritative — written only after a successful extract) over re-reading
   *  it off disk, which can carry stale files from a previous version. On-disk
   *  detection is the fallback for legacy installs with no recorded version. */
  private effectiveInstalledVersion(local: Manifest): string | undefined {
    return local.installed_chromium_version ?? this.installedEngineVersion();
  }

  /** Build stamp on disk: `<engine>/shardx-build` when the archive ships one,
   *  else what was recorded at install time. */
  private installedEngineBuild(local: Manifest): string | undefined {
    try {
      const stamp = readFileSync(
        join(this.root, this.spec.binarySubpath[0], "shardx-build"), "utf8",
      ).trim();
      if (stamp) return stamp;
    } catch { /* archive predates the stamp */ }
    return local.installed_engine_build || undefined;
  }

  /** Dotted-numeric compare; non-numeric parts count as 0. */
  private static versionLt(a: string, b: string): boolean {
    const parts = (v: string) =>
      v.split(/[.\-+]/).map((p) => (/^\d+$/.test(p) ? Number(p) : 0));
    const pa = parts(a), pb = parts(b);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const x = pa[i] ?? 0, y = pb[i] ?? 0;
      if (x !== y) return x < y;
    }
    return false;
  }

  /** Chromium version, `engine_build`, or the archive hash — any one of them
   *  means the engine moved. An unknown local value is not a mismatch. */
  private engineOutdated(
    local: Manifest,
    remote: { archives: Record<string, string>; chromiumVersion?: string; engineBuild?: string },
  ): boolean {
    if (remote.chromiumVersion !== undefined
        && this.effectiveInstalledVersion(local) !== remote.chromiumVersion) {
      return true;
    }
    const differs = (have?: string, want?: string) => !!have && !!want && have !== want;
    if (differs(this.installedEngineBuild(local), remote.engineBuild)) return true;
    return differs(local.browser_etag, remote.archives[this.spec.browser.key]);
  }

  // ---- manifest ----

  private loadManifest(): Manifest {
    try { return JSON.parse(readFileSync(this.manifestPath, "utf8")); }
    catch { return {}; }
  }
  private saveManifest(m: Manifest): void {
    writeFileSync(this.manifestPath, JSON.stringify(m, null, 2));
  }

  // ---- install ----

  async install(opts: { force?: boolean } = {}): Promise<void> {
    const force = !!opts.force;
    if (this._checkedInProcess && !force) return;
    const local = this.loadManifest();
    const remote = await this.fetchManifest();
    // Remember the engine version + grease so launch can normalise profiles.
    this._chromiumVersion = remote.chromiumVersion ?? CHROMIUM_VERSION;
    this._greaseBrand = remote.greaseBrand;
    this._greaseVersion = remote.greaseVersion;
    this._tls = remote.tls;

    // Refused rather than installed: this SDK could not configure it.
    if (remote.minSdkVersion && Runtime.versionLt(SDK_VERSION, remote.minSdkVersion)) {
      throw new Error(
        `this engine build needs @proxyshard/shardx ${remote.minSdkVersion} or newer — `
        + `you are on ${SDK_VERSION}; upgrade the SDK first`,
      );
    }
    // Unknown is never a mismatch, so adopt a stamp once or the first bump
    // never lands.
    if (this.installed && remote.engineBuild && !this.installedEngineBuild(local)) {
      local.installed_engine_build = remote.engineBuild;
    }
    // Manifest unreachable → don't force a re-download.
    const needBrowser = force || !this.installed || this.engineOutdated(local, remote);
    if (needBrowser) {
      // Wipe the old engine tree first so a leftover `<old>.manifest` / stale
      // libs can't linger beside the new ones (that pinned the detected version
      // → endless re-download). binarySubpath[0] is the engine root dir.
      rmSync(join(this.root, this.spec.binarySubpath[0]), { recursive: true, force: true });
      local.browser_etag = await this.downloadAndExtract(this.spec.browser, this.root);
      if (remote.engineBuild) local.installed_engine_build = remote.engineBuild;
    }
    if (this.spec.widevine && (needBrowser || !local.widevine_etag)) {
      local.widevine_etag = await this.downloadAndExtract(this.spec.widevine, this.root);
      this.placeWidevine();
    }
    const remoteFp = remote.archives[FINGERPRINTS_ARCHIVE.key];
    const fpDirHasJson = readdirSync(this.fingerprintsDir).some((f) => f.endsWith(".json"));
    if (force || !fpDirHasJson || (remoteFp !== undefined && local.fingerprints_etag !== remoteFp)) {
      await this.installFingerprints();
      if (remoteFp !== undefined) local.fingerprints_etag = remoteFp;
    }
    // Authoritative: we just extracted exactly this version (old tree wiped
    // first). Recording the known value beats re-reading it off disk.
    local.installed_chromium_version = this._chromiumVersion;
    this.saveManifest(local);

    // Linux/mac archives produced on Windows lose every Unix exec bit;
    // restore +x on every ELF/Mach-O file under the engine tree (not
    // just the main binary — chrome spawns chrome_crashpad_handler,
    // chrome_sandbox, etc., and they need the exec bit too).
    if (osPlatform() !== "win32") {
      fixUnixExecBits(this.root);
    }
    this._checkedInProcess = true;
  }

  // ---- helpers ----

  /** Fetch the version manifest (GitHub raw) — one request that yields every
   *  archive's current etag + the chromium version, replacing per-archive HEADs
   *  against R2/S3. Empty archives / undefined version when unreachable. */
  private async fetchManifest(): Promise<{ archives: Record<string, string>; chromiumVersion?: string; engineBuild?: string; minSdkVersion?: string; greaseBrand?: string; greaseVersion?: string; tls?: Record<string, unknown> }> {
    try {
      const r = await fetch(MANIFEST_URL);
      if (!r.ok) return { archives: {} };
      const data = await r.json() as { archives?: Record<string, string>; chromium_version?: string; engine_build?: string | number; min_sdk_version?: string; grease_brand?: string; grease_version?: string; tls?: Record<string, unknown> };
      const str = (v: unknown) => (typeof v === "string" ? v : undefined);
      return {
        archives: (data && typeof data.archives === "object" && data.archives) || {},
        chromiumVersion: str(data?.chromium_version),
        // Written as a number or a string; both mean the same thing.
        engineBuild: typeof data?.engine_build === "number"
          ? String(data.engine_build)
          : str(data?.engine_build),
        minSdkVersion: str(data?.min_sdk_version),
        greaseBrand: str(data?.grease_brand),
        greaseVersion: str(data?.grease_version),
        tls: (data?.tls && typeof data.tls === "object" && !Array.isArray(data.tls))
          ? data.tls as Record<string, unknown>
          : undefined,
      };
    } catch { return { archives: {} }; }
  }

  private async downloadAndExtract(arch: Archive, dest: string): Promise<string> {
    const url = `${PUB_BASE}/${arch.key}`;
    mkdirSync(dest, { recursive: true });
    const tmp = join(dest, `.${arch.key}.tmp`);

    const r = await fetch(url);
    if (!r.ok || !r.body) throw new Error(`download ${arch.key}: HTTP ${r.status}`);
    const etag = r.headers.get("etag")?.replace(/^"|"$/g, "") ?? "";
    const total = Number(r.headers.get("content-length") ?? 0);

    let received = 0;
    const reader = r.body.getReader();
    const out = createWriteStream(tmp);
    const stream = new Readable({
      async read() {
        const { value, done } = await reader.read();
        if (done) { this.push(null); return; }
        received += value.byteLength;
        if (arch.label) {/* throttle: rounded percent */}
        this.push(Buffer.from(value));
      },
    });
    // Wire progress in a parallel listener so pipeline stays clean.
    if (this.progress) {
      stream.on("data", () => this.progress!(arch.label, received, total));
    }
    await pipeline(stream, out);

    // Extract.  IMPORTANT: on macOS/Linux shell out to the system
    // `unzip`, which preserves the symlinks (every `Versions/Current/...`
    // link in a `.app` framework) and the +x bit on every helper
    // executable.  bsdtar is used on Windows, where neither applies.
    if (osPlatform() === "win32") {
      extractZipArchive(tmp, dest);
    } else {
      systemUnzip(tmp, dest);
    }
    rmSync(tmp, { force: true });
    return etag;
  }

  private placeWidevine(): void {
    if (!this.spec.widevine) return;
    const wrapper = this.spec.widevine.key.replace(/\.zip$/, "");
    const src = join(this.root, wrapper, "WidevineCdm");
    if (!existsSync(src)) return;
    const dst = join(this.root, ...this.spec.widevineSubpath);
    if (existsSync(dst)) rmSync(dst, { recursive: true, force: true });
    mkdirSync(dirname(dst), { recursive: true });
    renameSync(src, dst);
    rmSync(join(this.root, wrapper), { recursive: true, force: true });
  }

  private async installFingerprints(): Promise<void> {
    const url = `${PUB_BASE}/${FINGERPRINTS_ARCHIVE.key}`;
    const staging = join(this.fingerprintsDir, ".staging");
    if (existsSync(staging)) rmSync(staging, { recursive: true, force: true });
    mkdirSync(staging, { recursive: true });
    const tmp = join(staging, "bundle.zip");

    const r = await fetch(url);
    if (!r.ok || !r.body) throw new Error(`download fingerprints: HTTP ${r.status}`);
    const total = Number(r.headers.get("content-length") ?? 0);

    let received = 0;
    const reader = r.body.getReader();
    const out = createWriteStream(tmp);
    const stream = new Readable({
      async read() {
        const { value, done } = await reader.read();
        if (done) { this.push(null); return; }
        received += value.byteLength;
        this.push(Buffer.from(value));
      },
    });
    if (this.progress) {
      stream.on("data", () => this.progress!(FINGERPRINTS_ARCHIVE.label, received, total));
    }
    await pipeline(stream, out);

    // Fingerprints bundle is plain JSON files — no symlinks or exec bits
    // to preserve, so the plain zip path is fine on every platform.
    extractZipArchive(tmp, staging);

    const srcDir = join(staging, FINGERPRINTS_TOP_DIR);
    const walk = existsSync(srcDir) ? srcDir : staging;
    for (const name of readdirSync(walk)) {
      if (!name.endsWith(".json")) continue;
      const dst = join(this.fingerprintsDir, name);
      // Always overwrite bundled templates so engine-version bumps reach
      // existing libraries; user-added files (other names) are never iterated.
      copyFileSync(join(walk, name), dst);
    }
    rmSync(staging, { recursive: true, force: true });
  }
}

/** Extract via /usr/bin/unzip — preserves symlinks and permission
 *  bits that a plain zip reader drops.  Required for any macOS .app
 *  bundle (Versions/Current symlinks + Helper exec bits).
 *
 *  Accepts exit code 0 (clean) and 1 (warnings — e.g. "backslashes in
 *  path" for archives zipped on Windows; extraction still completes
 *  correctly).  Only 2+ are real fatal errors per unzip(1). */
function systemUnzip(archive: string, dest: string): void {
  mkdirSync(dest, { recursive: true });
  const r = spawnSync("unzip", ["-q", "-o", archive, "-d", dest], {
    stdio: ["ignore", "ignore", "pipe"],
  });
  if (r.error) {
    if ((r.error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new Error(
        "system `unzip` not found — install with `apt install unzip` / `brew install unzip`",
      );
    }
    throw r.error;
  }
  if ((r.status ?? 0) > 1) {
    const err = r.stderr?.toString().slice(0, 400) ?? `exit ${r.status}`;
    throw new Error(`unzip failed for ${archive} (exit ${r.status}): ${err}`);
  }
}

/** ELF + Mach-O magic bytes; first 4 bytes tell us a file is a native
 *  executable that needs the +x bit, regardless of what zip stored. */
const NATIVE_MAGIC: ReadonlyArray<Buffer> = [
  Buffer.from([0x7f, 0x45, 0x4c, 0x46]),                  // ELF
  Buffer.from([0xfe, 0xed, 0xfa, 0xcf]),                  // Mach-O 64 BE
  Buffer.from([0xcf, 0xfa, 0xed, 0xfe]),                  // Mach-O 64 LE
  Buffer.from([0xfe, 0xed, 0xfa, 0xce]),                  // Mach-O 32 BE
  Buffer.from([0xce, 0xfa, 0xed, 0xfe]),                  // Mach-O 32 LE
  Buffer.from([0xca, 0xfe, 0xba, 0xbe]),                  // Mach-O universal BE
  Buffer.from([0xbe, 0xba, 0xfe, 0xca]),                  // Mach-O universal LE
];

/** Walk `root` and add +x to every file whose first 4 bytes match a known
 *  native-binary magic.  Required because Windows zip producers don't
 *  store Unix exec bits, so chrome / chrome_crashpad_handler / chrome_sandbox
 *  all come out non-executable on Linux. */
function fixUnixExecBits(root: string): void {
  const walk = (dir: string): void => {
    for (const ent of readdirSync(dir, { withFileTypes: true })) {
      const p = join(dir, ent.name);
      if (ent.isSymbolicLink()) continue;
      if (ent.isDirectory()) { walk(p); continue; }
      if (!ent.isFile()) continue;
      try {
        const fd = openSync(p, "r");
        const buf = Buffer.alloc(4);
        readSync(fd, buf, 0, 4, 0);
        closeSync(fd);
        if (NATIVE_MAGIC.some((m) => buf.equals(m))) {
          chmodSync(p, lstatSync(p).mode | 0o111);
        }
      } catch { /* skip unreadable / racing files */ }
    }
  };
  walk(root);
}
