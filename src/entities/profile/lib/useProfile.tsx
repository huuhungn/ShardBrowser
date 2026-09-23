import { create } from "zustand";
import { open, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { openPath } from "@tauri-apps/plugin-opener";
import { toast } from "../../../shared/lib/toast";
import { confirmModal } from "../../../shared/lib/confirm";
import { passphraseModal } from "../../../shared/model/passphrase";
import { useTeam } from "../../team";
import { clip } from "../../../shared/lib/clipboard";
import { readTextFile, fmtBytes, safeUiError } from "../../../shared/lib/utils";
import { storeBus } from "../../../shared/lib/storeBus";
import { proxyList, type ProxyEntry } from "../../proxy";
import { fingerprintList, type FingerprintEntry } from "../../fingerprint";
import type { ProfileMeta, ProfileForm } from "../model/types";
import {
  profileList, profileGet, profileSave, profileValidateName, profileDelete, profileClone,
  profileSetPin, profileSetFolder, profileBindProxy, profileImport,
  profileCreateFromTemplate, processList, processKill, launch, syncLaunch,
  folderDelete, cookiesExportToFile, cookiesImport,
  profileSyncStatus, profileSyncPush, profileSyncPull,
  profileBackupCreate, profileBackupInspect, profileBackupRestore,
  devtoolsContext, devtoolsActivate, type CdpInfo,
} from "../model/api";
import { defaultForm, fromStored, toStored } from "../model/form";
import { t } from "../../../shared/i18n";

const FOLDERS_KEY = "shardx-folders";

const loadFolderRegistry = (): string[] => {
  try { return JSON.parse(localStorage.getItem(FOLDERS_KEY) || "[]"); }
  catch { return []; }
};

export type QuickEditTarget = { kind: "proxy" | "notes"; profile: ProfileMeta };
export type FolderModalTarget = { profileId: string | null };

/** Narrows the list beyond the folder tab and the search box. */
export type ProfileFilters = {
  status: "all" | "running" | "idle";
  /** Country code of the bound proxy, or "" for any. */
  country: string;
  /** "bound" = has a proxy, "direct" = none. */
  proxy: "all" | "bound" | "direct";
};

export const emptyFilters = (): ProfileFilters => ({ status: "all", country: "", proxy: "all" });

export type ProfileStore = {
  status: "idle" | "loading" | "ready" | "error";
  error: string | null;

  profiles: ProfileMeta[];
  proxies: ProxyEntry[];
  fingerprints: FingerprintEntry[];

  /// Value = epoch ms at which the engine was first observed running. Used both
  /// as a truthy flag (any number = running) and as the anchor for the ticking
  /// uptime display in the Status column.
  running: Record<string, number>;
  runningCdp: Record<string, CdpInfo>;
  /** Last launch failure per profile, kept on the row until the next attempt. */
  launchError: Record<string, string>;
  /// Profiles whose `launch()` call is in-flight (pre-flight probes can be slow).
  startBusy: Set<string>;
  /// Profiles whose activate call is in-flight, so repeat clicks no-op.
  verificationBusy: Set<string>;
  selected: Set<string>;

  // UI state lives in the store so feature buttons stay prop-free.
  search: string;
  folder: string;
  expanded: string | null;
  draft: ProfileForm | null;
  /// Why the open draft could not be saved, shown beside the form.
  draftError: string | null;
  /// Empty folders persist here until a profile lands in them.
  folderRegistry: string[];
  folderModal: FolderModalTarget | null;
  /// Folder name currently highlighted as a drag-and-drop target ("__all__"
  /// for the All tab). Cleared in dragleave/drop.
  dropTarget: string | null;
  templatePickerOpen: boolean;
  quickEdit: QuickEditTarget | null;
  filters: ProfileFilters;
  /// Row the last plain click landed on; a shift-click selects the run from it.
  anchorId: string | null;

  init: () => Promise<void>;
  reload: () => Promise<void>;
  startProcessPolling: () => () => void;

  copyCdpHttpUrl: (id: string) => Promise<void>;
  copyDevToolsInspectUrl: (id: string) => Promise<void>;
  /** Raises the running profile's page so a verification prompt is visible. */
  bringVerificationToFront: (id: string) => Promise<void>;
  setSearch: (q: string) => void;
  setFolder: (f: string) => void;
  setDraft: (draft: ProfileForm | null) => void;
  setDropTarget: (target: string | null) => void;
  setTemplatePickerOpen: (open: boolean) => void;
  setQuickEdit: (target: QuickEditTarget | null) => void;
  setFolderModal: (target: FolderModalTarget | null) => void;
  setFilters: (f: Partial<ProfileFilters>) => void;
  clearFilters: () => void;

  rememberFolder: (f: string) => void;
  forgetFolder: (f: string) => void;

  selectProfiles: (isChecked: boolean, profiles: ProfileMeta[]) => void;
  toggleSelect: (id: string) => void;
  /** Shift-click: selects every row between the anchor and `id`. */
  selectRangeTo: (id: string) => void;
  clearSelected: () => void;

  expand: (id: string) => Promise<void>;
  newProfile: () => void;
  cancelEdit: () => void;
  saveDraft: () => Promise<void>;

  startStop: (p: ProfileMeta) => Promise<void>;
  remove: (id: string) => Promise<void>;
  cloneProfile: (id: string) => Promise<void>;
  togglePin: (p: ProfileMeta) => Promise<void>;
  exportCookies: (p: ProfileMeta) => Promise<void>;
  backupProfile: (p: ProfileMeta) => Promise<void>;
  restoreProfile: (p: ProfileMeta) => Promise<void>;
  pushProfile: (p: ProfileMeta) => Promise<void>;
  pullProfile: (p: ProfileMeta) => Promise<void>;
  importCookies: (p: ProfileMeta) => Promise<void>;

  setProfileFolder: (id: string, f: string) => Promise<void>;
  deleteFolder: (f: string) => Promise<void>;
  createFromTemplate: (tplId: string) => Promise<void>;

  bulkLaunch: () => Promise<void>;
  /** Launches the selection as one synchronised group. */
  bulkLaunchSynced: () => Promise<void>;
  /** Group currently being synchronised, or null. */
  syncGroup: string | null;
  bulkStop: () => Promise<void>;
  bulkDelete: () => Promise<void>;
  bulkExport: () => Promise<void>;
  bulkImport: () => Promise<void>;
};

export const useProfile = create<ProfileStore>((set, get) => ({
  status: "idle",
  error: null,

  profiles: new Array<ProfileMeta>(),
  proxies: new Array<ProxyEntry>(),
  fingerprints: new Array<FingerprintEntry>(),

  running: {},
  runningCdp: {},
  launchError: {},
  startBusy: new Set<string>(),
  verificationBusy: new Set<string>(),
  selected: new Set<string>(),

  search: "",
  folder: "all",
  expanded: null,
  draftError: null,
  draft: null,
  folderRegistry: loadFolderRegistry(),
  folderModal: null,
  dropTarget: null,
  templatePickerOpen: false,
  quickEdit: null,
  filters: emptyFilters(),
  anchorId: null,

  init: async () => {
    // A failed load must be retryable, so only an in-flight or successful
    // load short-circuits. Retrying clears the previous error first.
    if (get().status === "loading" || get().status === "ready") return;
    // Re-read the folder registry here rather than trusting the value captured
    // at module-eval time: the store module is imported before bootstrap runs,
    // so a registry written after that (another window, or the e2e fixture)
    // would otherwise stay invisible until a reload.
    set({ error: null, folderRegistry: loadFolderRegistry() });
    set({ status: "loading" });
    try {
      const [profiles, proxies, fingerprints] = await Promise.all([
        profileList(), proxyList(), fingerprintList(),
      ]);
      set({ profiles, proxies, fingerprints, status: "ready" });
      // A proxy added on the Proxies page has to reach the editor's select, and
      // a proxy bound there — by the distribute dialog — has to reach the table.
      storeBus.on("proxies", () => { void get().reload(); });
      storeBus.on("profiles", () => { void get().reload(); });
    } catch (e) {
      set({ status: "error", error: (e as Error).message });
      toast.err(String(e));
    }
  },

  reload: async () => {
    try {
      const [profiles, proxies] = await Promise.all([profileList(), proxyList()]);
      set({ profiles, proxies });
    } catch (e) { toast.err(String(e)); }
  },

  // 2s poll for real child status; not optimistic UI state. Uptime is anchored
  // to the moment the engine actually started (now - uptime_ms), preserved
  // across polls so the displayed clock doesn't jitter. When a profile
  // transitions running → not-running, the backend has just bumped its persisted
  // total_runtime_ms — re-fetch so the Time column reflects the new total.
  startProcessPolling: () => {
    let cancelled = false;
    // A single failed poll is normal during a backend restart; a run of them
    // means the status on screen is frozen, and a frozen Running row with a
    // dead Stop button is worse than an empty list.
    let consecutiveFailures = 0;
    const tick = async () => {
      try {
        const list = await processList();
        if (cancelled) return;
        consecutiveFailures = 0;
        const now = Date.now();
        const prev = get().running;
        const next: Record<string, number> = {};
        for (const r of list) {
          next[r.profile_id] = prev[r.profile_id] ?? (now - r.uptime_ms);
        }
        const cdp: Record<string, CdpInfo> = {};
        for (const r of list) if (r.cdp) cdp[r.profile_id] = r.cdp;
        const justExited = Object.keys(prev).some((id) => !(id in next));
        set({ running: next, runningCdp: cdp });
        if (justExited) get().reload();
      } catch (e) {
        if (cancelled) return;
        consecutiveFailures += 1;
        // Three strikes (~6s) before clearing, so a brief blip doesn't wipe
        // a legitimately running list out from under the user.
        if (consecutiveFailures === 3) {
          set({ running: {}, runningCdp: {} });
          toast.err(t("profile.lostTrack", { err: safeUiError(e) }));
        }
      }
    };
    tick();
    const handle = setInterval(tick, 2000);
    return () => { cancelled = true; clearInterval(handle); };
  },

  // DevTools handoff: automation users copy these constantly, so they are
  // first-class actions rather than something to reconstruct by hand.
  copyCdpHttpUrl: async (id) => {
    const cdp = get().runningCdp[id];
    if (!cdp) { toast.err(t("profile.cdpIsNotEnabledForThisRunningProfile")); return; }
    try {
      await clip.write(cdp.http_url);
      toast.ok(t("profile.copiedCDPHTTPURL"));
    } catch (e) { toast.err(safeUiError(e)); }
  },

  copyDevToolsInspectUrl: async (id) => {
    try {
      const ctx = await devtoolsContext(id);
      const url = ctx.current?.devtools_frontend_url
        ?? ctx.targets[0]?.devtools_frontend_url
        ?? `${ctx.cdp.http_url}/json/list`;
      await clip.write(url);
      toast.ok(t("profile.copiedDevToolsInspectURL"));
    } catch (e) { toast.err(safeUiError(e)); }
  },

  // A site can park a CAPTCHA or 2FA prompt on a background tab, where the
  // operator never sees it. Raising the page is the whole point of the action,
  // so a failure has to say so rather than fail silently.
  bringVerificationToFront: async (id) => {
    if (get().verificationBusy.has(id)) return;
    set({ verificationBusy: new Set([...get().verificationBusy, id]) });
    try {
      await devtoolsActivate(id);
      toast.ok(t("profile.verificationTabBroughtToFront"));
    } catch (e) {
      toast.err(t("profile.couldNotFrontTab", { err: safeUiError(e) }));
    } finally {
      const n = new Set(get().verificationBusy);
      n.delete(id);
      set({ verificationBusy: n });
    }
  },

  setSearch: (search) => set({ search }),
  setFolder: (folder) => set({ folder }),
  setDraft: (draft) => set({ draft }),
  setDropTarget: (dropTarget) => set({ dropTarget }),
  setTemplatePickerOpen: (templatePickerOpen) => set({ templatePickerOpen }),
  setQuickEdit: (quickEdit) => set({ quickEdit }),
  setFolderModal: (folderModal) => set({ folderModal }),
  setFilters: (f) => set({ filters: { ...get().filters, ...f } }),
  clearFilters: () => set({ filters: emptyFilters() }),

  rememberFolder: (f) => {
    const next = get().folderRegistry.includes(f)
      ? get().folderRegistry
      : [...get().folderRegistry, f];
    localStorage.setItem(FOLDERS_KEY, JSON.stringify(next));
    set({ folderRegistry: next });
  },
  forgetFolder: (f) => {
    const next = get().folderRegistry.filter((x) => x !== f);
    localStorage.setItem(FOLDERS_KEY, JSON.stringify(next));
    set({ folderRegistry: next });
  },

  selectProfiles: (isChecked, profiles) => {
    const next = new Set(get().selected);
    if (isChecked) {
      for (const p of profiles) next.add(p.id);
    } else {
      for (const p of profiles) next.delete(p.id);
    }
    set({ selected: next });
  },
  toggleSelect: (id) => {
    const next = new Set(get().selected);
    if (next.has(id)) next.delete(id); else next.add(id);
    set({ selected: next, anchorId: id });
  },
  // Ordered as the table paints it. The clicked row decides the direction: a
  // ticked one clears the run, an unticked one selects it.
  selectRangeTo: (id) => {
    const order = visibleIds(get());
    const to = order.indexOf(id);
    if (to < 0) return;
    const anchor = get().anchorId;
    // Only a still-ticked anchor has a run to extend; spanning back over a
    // cleared one would put its tick straight back.
    const from = anchor && get().selected.has(anchor) ? order.indexOf(anchor) : -1;
    if (from < 0) { get().toggleSelect(id); return; }
    const [lo, hi] = from <= to ? [from, to] : [to, from];
    const removing = get().selected.has(id);
    const next = new Set(get().selected);
    for (let i = lo; i <= hi; i++) {
      if (removing) next.delete(order[i]); else next.add(order[i]);
    }
    set({ selected: next });
  },
  clearSelected: () => set({ selected: new Set<string>(), anchorId: null }),

  expand: async (id) => {
    if (get().expanded === id) { set({ expanded: null, draft: null }); return; }
    const stored = await profileGet(id);
    set({ draft: fromStored(stored), expanded: id });
  },
  newProfile: () => set({ draft: defaultForm(), expanded: "__new__", draftError: null }),
  cancelEdit: () => set({ expanded: null, draft: null, draftError: null }),

  saveDraft: async () => {
    const { draft, fingerprints, folder } = get();
    if (!draft) return;
    try {
      // Validate before persisting: the backend owns the rule, and a rejected
      // name must not reach profile_save or the folder assignment below.
      set({ draftError: null });
      await profileValidateName(draft.name, draft.id || null);
      const fp = fingerprints.find((g) => g.id === draft.gpu_preset_id) ?? null;
      const saved = await profileSave(toStored(draft, fp));
      await profileBindProxy(saved.id, draft.proxy_id);
      // A profile created while a folder tab is active should land in that
      // folder (otherwise it pops into t("profile.all") and the user has to drag it back).
      // `!draft.id` scopes this to creations only — edits keep their folder.
      if (!draft.id && folder && folder !== "all") {
        try { await profileSetFolder(saved.id, folder); }
        catch (e) { console.warn("auto-assign folder failed:", e); }
      }
      set({ expanded: null, draft: null });
      get().reload();
      storeBus.emit("profiles");
      toast.ok(draft.id ? t("profile.profileSaved") : t("profile.createdNamed", { name: saved.name }));
    } catch (e) {
      // Shown beside the form, where the offending field is. A toast as well
      // would be the same message twice, and it would scroll away from it.
      set({ draftError: safeUiError(e) });
    }
  },

  // Block the Start button until launch() returns. The launch includes
  // pre-flight steps that can take real time (UDP probe, geo, Widevine
  // pre-warm); surfacing the busy state is what the user reads as "did it work?".
  startStop: async (p) => {
    if (get().running[p.id]) {
      try {
        // False means the backend has no child for this profile: the row is a
        // leftover from a process that already died. Drop it so the button
        // stops lying instead of leaving the user pressing a dead Stop.
        const stopping = await processKill(p.id);
        if (!stopping) {
          const next = { ...get().running };
          delete next[p.id];
          const cdp = { ...get().runningCdp };
          delete cdp[p.id];
          set({ running: next, runningCdp: cdp });
          toast.ok("That browser had already exited; cleared its status");
          get().reload();
        }
      }
      catch (e) { toast.err(String(e)); }
      return;
    }
    if (get().startBusy.has(p.id)) return;
    // A new attempt supersedes the previous failure.
    const cleared = { ...get().launchError };
    delete cleared[p.id];
    set({ startBusy: new Set([...get().startBusy, p.id]), launchError: cleared });
    try {
      await launch(p.id);
      // Don't optimistically flip `running`; the 2s poll picks up the new child.
    } catch (e) {
      // A toast disappears; a failed launch needs to stay readable on the row
      // that failed, next to the button the user just pressed.
      const message = safeUiError(e);
      toast.err(message);
      set({ launchError: { ...get().launchError, [p.id]: message } });
    } finally {
      const n = new Set(get().startBusy);
      n.delete(p.id);
      set({ startBusy: n });
    }
  },

  remove: async (id) => {
    if ((await confirmModal({
      title: t("profile.deleteProfile"),
      message: "Move this profile to the trash? It can be restored there for 7 days.",
      danger: true,
    })) !== true) return;
    try {
      await profileDelete(id);
      get().reload();
      storeBus.emit("profiles");
    } catch (e) { toast.err(String(e)); }
  },

  cloneProfile: async (id) => {
    try { await profileClone(id); get().reload(); }
    catch (e) { toast.err(String(e)); }
  },

  togglePin: async (p) => {
    try { await profileSetPin(p.id, !p.pinned); get().reload(); }
    catch (e) { toast.err(String(e)); }
  },

  // Encrypted single-profile backup to a .shxbak file.
  backupProfile: async (p) => {
    if (get().running[p.id]) { toast.err(t("profile.stopTheProfileBeforeBackingItUp")); return; }
    try {
      const path = await saveDialog({
        defaultPath: `${(p.name || p.id).replace(/[^\w.-]+/g, "_")}.shxbak`,
        filters: [{ name: t("profile.shardxBackup"), extensions: ["shxbak"] }],
      });
      if (typeof path !== "string") return; // cancelled
      const passphrase = await passphraseModal({
        title: t("profile.encryptBackup"),
        message: t("profile.passphraseOnlyWay"),
        confirm: true,
      });
      if (passphrase === null) return;
      const res = await profileBackupCreate(p.id, path, passphrase);
      toast.ok(t("profile.backedUp", { size: fmtBytes(res.file_bytes), hash: res.sha256.slice(0, 12) }));
      const dir = path.replace(/[/\\][^/\\]*$/, "");
      try { await openPath(dir); } catch {}
    } catch (e) { toast.err(safeUiError(e)); }
  },

  restoreProfile: async (p) => {
    if (get().running[p.id]) { toast.err(t("profile.stopTheProfileBeforeRestoringIt")); return; }
    try {
      const path = await open({
        multiple: false, directory: false, title: t("profile.selectAShardxBackup"),
        filters: [{ name: t("profile.shardxBackup"), extensions: ["shxbak"] }],
      });
      if (typeof path !== "string") return;
      // Validate the file before asking for a passphrase, so a wrong pick is
      // caught without the user typing anything.
      await profileBackupInspect(path);
      if ((await confirmModal({
        title: t("profile.restoreProfile"),
        message:
          "This replaces the current profile data with the backup's contents. " +
          t("profile.anythingNotInTheBackupIsLost"),
        danger: true,
        buttons: [{ label: t("common.cancel"), value: false }, { label: t("profile.restore"), value: true, danger: true }],
      })) !== true) return;
      const passphrase = await passphraseModal({
        title: t("profile.openBackup"),
        message: t("profile.enterThePassphraseThisBackupWasCrea"),
      });
      if (passphrase === null) return;
      await profileBackupRestore(p.id, path, passphrase);
      toast.ok(t("profile.profileRestored"));
      get().reload();
    } catch (e) { toast.err(safeUiError(e)); }
  },

  // Push a profile to the team server. The passphrase is the shared secret
  // between devices: whoever pulls this profile must type the same one.
  pushProfile: async (p) => {
    if (get().running[p.id]) { toast.err(t("profile.stopTheProfileBeforePushingIt")); return; }
    try {
      // Read the remote version first. Pushing from a stale base is what the
      // server refuses, and showing the version is how the user learns that
      // another device published in the meantime.
      const remote = await profileSyncStatus(p.id);
      const base = remote?.version ?? 0;
      // A device holding a fleet key needs no passphrase: the fleet shares the
      // key through grants, so asking for one would be theatre.
      let passphrase = "";
      if (!useTeam.getState().status?.has_fleet_key) {
        const typed = await passphraseModal({
          title: base === 0 ? t("profile.encryptProfileForTheTeam") : t("profile.pushOverVersion", { v: base }),
          message:
            t("profile.passphraseShared") +
            t("profile.itIsNotStoredAnywhereAndCannotBeRecove"),
          confirm: base === 0,
        });
        if (typed === null) return;
        passphrase = typed;
      }
      const res = await profileSyncPush(p.id, passphrase, base);
      toast.ok(t("profile.pushedVersion", { v: res.version, size: fmtBytes(res.container_bytes) }));
    } catch (e) { toast.err(safeUiError(e)); }
  },

  // Pull the team's current version over the local profile.
  pullProfile: async (p) => {
    if (get().running[p.id]) { toast.err(t("profile.stopTheProfileBeforePullingIt")); return; }
    try {
      const remote = await profileSyncStatus(p.id);
      if (!remote) { toast.err(t("profile.theTeamServerHasNoSnapshotForThisProfi")); return; }
      if (!(await confirmModal({
        title: t("profile.pullVersion", { v: remote.version }),
        message:
          t("profile.thisReplacesTheCurrentProfileDataWithT") +
          t("profile.anythingNotInThatSnapshotIsLost"),
        buttons: [
          { label: t("common.cancel"), value: false },
          { label: t("profile.pullAndReplace"), value: true, danger: true },
        ],
      }))) return;
      let passphrase: string | null = "";
      if (!useTeam.getState().status?.has_fleet_key) {
        passphrase = await passphraseModal({
          title: t("profile.passphraseForThisProfile"),
          message: t("profile.thePassphraseUsedWhenThisProfileWas"),
        });
      }
      if (passphrase === null) return;
      const bytes = await profileSyncPull(p.id, passphrase);
      toast.ok(t("profile.pulledVersion", { v: remote.version, size: fmtBytes(bytes) }));
    } catch (e) { toast.err(safeUiError(e)); }
  },

  exportCookies: async (p) => {
    try {
      const path = await saveDialog({
        defaultPath: `${(p.name || p.id).replace(/[^\w.-]+/g, "_")}-cookies.json`,
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (typeof path !== "string") return; // cancelled
      const n = await cookiesExportToFile(p.id, path);
      toast.ok(t(n === 1 ? "profile.exportedCookieOne" : "profile.exportedCookieMany", { n }));
      // Open the containing folder so the user sees exactly where it went.
      const dir = path.replace(/[/\\][^/\\]*$/, "");
      try { await openPath(dir); } catch {}
    } catch (e) { toast.err(String(e)); }
  },

  importCookies: async (p) => {
    if (get().running[p.id]) { toast.err(t("profile.stopTheProfileBeforeImportingCookies")); return; }
    try {
      const path = await open({
        multiple: false, directory: false, title: t("profile.selectCookiesJson"),
        filters: [{ name: "JSON", extensions: ["json"] }],
      });
      if (typeof path !== "string") return;
      const text = await readTextFile(path);
      const cookies = JSON.parse(text);
      if (!Array.isArray(cookies)) { toast.err(t("profile.expectedAJSONArrayOfCookies")); return; }
      const n = await cookiesImport(p.id, cookies);
      toast.ok(t(n === 1 ? "profile.importedCookieOne" : "profile.importedCookieMany", { n }));
    } catch (e) { toast.err(String(e)); }
  },

  setProfileFolder: async (id, f) => {
    // Dropping a profile onto the folder it already lives in is a no-op — tell
    // the user instead of silently doing nothing.
    const p = get().profiles.find((x) => x.id === id);
    if (p && p.folder === f) {
      const who = p.name || id.slice(0, 8);
      toast.info(
        f
          ? t("profile.alreadyInFolder", { who, folder: f })
          : t("profile.notInAnyFolder", { who }),
      );
      return;
    }
    try {
      await profileSetFolder(id, f);
      if (f) get().rememberFolder(f);
      get().reload();
      storeBus.emit("profiles");
    } catch (e) { toast.err(String(e)); }
  },

  deleteFolder: async (f) => {
    const count = get().profiles.filter((p) => p.folder === f).length;
    // Three outcomes: delete profiles, unfile, cancel.
    const choice = await confirmModal({
      title: t("profile.deleteFolderTitle", { f }),
      message:
        count > 0
          ? t(count === 1 ? "profile.deleteFolderAskOne" : "profile.deleteFolderAskMany", {
              n: count,
              all: t("profile.all"),
            })
          : t("profile.deleteFolderEmpty", { f }),
      buttons:
        count > 0
          ? [
              { label: t("common.cancel"), value: "cancel" },
              { label: t("profile.keepProfiles"), value: "keep" },
              { label: t("profile.deleteProfiles"), value: "delete", danger: true },
            ]
          : [
              { label: t("common.cancel"), value: "cancel" },
              { label: t("common.delete"), value: "keep", danger: true },
            ],
    });
    if (choice == null || choice === "cancel") return;
    const alsoDelete = choice === "delete";
    try {
      const n = await folderDelete(f, alsoDelete);
      // The folder lives in two places: profile tags (cleared by folder_delete)
      // and the localStorage registry of empty folders. Drop it from the
      // registry too, otherwise the tab lingers after every profile is gone.
      get().forgetFolder(f);
      if (get().folder === f) set({ folder: "all" });
      get().reload();
      toast.ok(
        alsoDelete
          ? t(n === 1 ? "profile.deletedFolderOne" : "profile.deletedFolderMany", { f, n })
          : t(n === 1 ? "profile.removedFolderOne" : "profile.removedFolderMany", { f, n }),
      );
    } catch (e) { toast.err(String(e)); }
  },

  createFromTemplate: async (tplId) => {
    try {
      const meta = await profileCreateFromTemplate(tplId);
      set({ templatePickerOpen: false });
      get().reload();
      toast.ok(t("profile.profileCreatedNamed", { name: meta.name }));
      // Auto-open the new profile in the editor.
      const stored = await profileGet(meta.id);
      set({ draft: fromStored(stored), expanded: meta.id });
    } catch (e) { toast.err(String(e)); }
  },

  syncGroup: null,

  bulkLaunchSynced: async () => {
    const ids = [...get().selected];
    if (ids.length < 2) return;
    // Per launch, not fixed: two fleets must not share session files.
    const group = `fleet-${Date.now().toString(36)}`;
    try {
      const name = await syncLaunch(ids, group);
      set({ syncGroup: name });
      get().clearSelected();
      toast.ok(t("profile.synchronisingProfiles", { n: ids.length }));
    } catch (e) {
      toast.err(String(e));
    }
  },

  bulkLaunch: async () => {
    const { selected, running } = get();
    const failures: string[] = [];
    for (const id of selected) {
      if (running[id]) continue;
      try { await launch(id); }
      catch (e) { failures.push(safeUiError(e)); }
    }
    get().clearSelected();
    // Silence here means a user who selected ten profiles and got three
    // browsers has no idea the other seven failed, or why.
    if (failures.length) {
      toast.err(
        failures.length === 1
          ? t("profile.couldNotStartOne", { err: failures[0] })
          : t("profile.couldNotStartMany", { n: failures.length, err: failures[0] }),
      );
    }
  },

  bulkStop: async () => {
    const failures: string[] = [];
    for (const id of get().selected) {
      try { await processKill(id); }
      catch (e) { failures.push(safeUiError(e)); }
    }
    get().clearSelected();
    if (failures.length) {
      toast.err(
        failures.length === 1
          ? t("profile.couldNotStopOne", { err: failures[0] })
          : t("profile.couldNotStopMany", { n: failures.length, err: failures[0] }),
      );
    }
  },

  bulkDelete: async () => {
    const ids = [...get().selected];
    if (ids.length === 0) return;
    if ((await confirmModal({
      title: t("profile.deleteProfiles"),
      message: t(ids.length === 1 ? "profile.trashAskOne" : "profile.trashAskMany", { n: ids.length }),
      danger: true,
    })) !== true) return;
    for (const id of ids) {
      try { await profileDelete(id); } catch (e) { toast.err(String(e)); }
    }
    get().clearSelected();
    get().reload();
    storeBus.emit("profiles");
    toast.ok(t("profile.movedToTrashN", { n: ids.length }));
  },

  // Dump selected profile FingerprintConfigs as a JSON array to clipboard.
  bulkExport: async () => {
    const ids = [...get().selected];
    if (ids.length === 0) return;
    try {
      const payloads = await Promise.all(ids.map((id) => profileGet(id)));
      await clip.write(JSON.stringify(payloads, null, 2));
      toast.ok(t("common.copiedNToClipboard", { n: payloads.length }));
    } catch (e) { toast.err(String(e)); }
  },

  // Paste profile JSON from clipboard → fresh profiles.
  bulkImport: async () => {
    try {
      const text = await clip.read();
      if (!text.trim()) { toast.err(t("profile.clipboardIsEmpty")); return; }
      const data = JSON.parse(text);
      const arr = Array.isArray(data) ? data : [data];
      const n = await profileImport(arr);
      get().reload();
      toast.ok(t(n === 1 ? "profile.importedProfileOne" : "profile.importedProfileMany", { n }));
    } catch (e) { toast.err(t("profile.importFailed") + String(e)); }
  },
}));

/// The ids in the order the table paints them — a range covers what is visible.
function visibleIds(s: ProfileStore): string[] {
  return applyProfileFilters(
    s.profiles, s.proxies, s.search, s.folder, s.filters, s.running,
  ).map((p) => p.id);
}

/// Shared with `useVisibleProfiles` so the rows on screen and the rows a range
/// covers cannot drift apart.
export function applyProfileFilters(
  profiles: ProfileMeta[],
  proxies: ProxyEntry[],
  search: string,
  folder: string,
  filters: ProfileFilters,
  running: Record<string, number> = {},
): ProfileMeta[] {
  const q = search.trim().toLowerCase();
  const byId = new Map(proxies.map((p) => [p.id, p]));
  return profiles.filter((p) => {
    if (folder !== "all" && p.folder !== folder) return false;
    if (q && !p.name.toLowerCase().includes(q) && !p.notes.toLowerCase().includes(q)) return false;
    if (filters.proxy === "bound" && !p.proxy_id) return false;
    if (filters.proxy === "direct" && p.proxy_id) return false;
    if (filters.country) {
      const cc = p.proxy_id ? byId.get(p.proxy_id)?.country ?? "" : "";
      if (cc.toUpperCase() !== filters.country.toUpperCase()) return false;
    }
    if (filters.status !== "all") {
      const isRunning = !!running[p.id];
      if ((filters.status === "running") !== isRunning) return false;
    }
    return true;
  });
}
