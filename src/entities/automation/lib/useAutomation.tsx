import { create } from "zustand";
import { toast } from "../../../shared/lib/toast";
import { confirmModal } from "../../../shared/lib/confirm";
import {
  automationDelete,
  automationList,
  automationRun,
  automationSave,
} from "../model/api";
import type { Block, Project, RunReport } from "../model/types";
import { t } from "../../../shared/i18n";
import { safeUiError } from "../../../shared/lib/utils";

let seq = 0;

/** Ids only have to be unique inside one project, and the backend keeps them. */
export const newBlockId = () => `b${Date.now().toString(36)}${(seq++).toString(36)}`;

export const emptyBlock = (kind = "navigate"): Block => ({
  id: newBlockId(),
  kind,
  label: "",
  params: {},
  enabled: true,
  x: 0,
  y: 0,
  on_done: "next",
  secrets: [],
  // Stopping is the safe default: a run that carries on past a failed click
  // types into whatever page happens to be in front of it.
  on_fail: "stop",
});

export const emptyProject = (): Project => ({
  id: "",
  name: "",
  notes: "",
  blocks: [],
  run: { threads: 1, loops: 1, hours: 0, profiles: [], start: "" },
  created_at: 0,
  updated_at: 0,
});

export type AutomationStore = {
  status: "idle" | "loading" | "ready" | "error";
  items: Project[];
  /** Project open in the editor, or null. Edited in place, saved on demand. */
  editing: Project | null;
  search: string;

  /** Profile id the run bar targets. */
  runProfile: string;
  /** True while a run is in flight; the run button stays disabled. */
  running: boolean;
  /** The last run's report, shown under the editor. */
  lastRun: RunReport | null;

  init: () => Promise<void>;
  reload: () => Promise<void>;
  setEditing: (p: Project | null) => void;
  patchEditing: (patch: Partial<Project>) => void;
  setSearch: (q: string) => void;
  setRunProfile: (id: string) => void;
  save: (p: Project) => Promise<void>;
  remove: (p: Project) => Promise<void>;
  run: (p: Project) => Promise<void>;
};

export const useAutomation = create<AutomationStore>((set, get) => ({
  status: "idle",
  items: [],
  editing: null,
  search: "",
  runProfile: "",
  running: false,
  lastRun: null,

  init: async () => {
    if (get().status === "loading" || get().status === "ready") return;
    set({ status: "loading" });
    try {
      set({ items: await automationList(), status: "ready" });
    } catch (e) {
      set({ status: "error" });
      toast.err(safeUiError(e));
    }
  },
  reload: async () => {
    try { set({ items: await automationList() }); }
    catch (e) { toast.err(safeUiError(e)); }
  },
  setEditing: (editing) => set({ editing, lastRun: null }),
  patchEditing: (patch) => {
    const current = get().editing;
    if (current) set({ editing: { ...current, ...patch } });
  },
  setSearch: (search) => set({ search }),
  setRunProfile: (runProfile) => set({ runProfile }),

  save: async (p) => {
    try {
      const saved = await automationSave(p);
      // Keep the editor open on the saved copy: the backend assigns the id
      // and timestamps, and editing a stale copy would overwrite them.
      set({ editing: saved });
      await get().reload();
      toast.ok(p.id ? t("automation.projectSaved") : t("automation.projectCreated"));
    } catch (e) {
      toast.err(safeUiError(e));
    }
  },

  remove: async (p) => {
    const ok = await confirmModal({
      title: t("automation.deleteProject"),
      message: t("automation.deleteProjectAsk", { name: p.name || t("automation.thisProject") }),
      buttons: [
        { label: t("common.cancel"), value: false },
        { label: t("common.delete"), value: true, danger: true },
      ],
    });
    if (!ok) return;
    try {
      await automationDelete(p.id);
      if (get().editing?.id === p.id) set({ editing: null, lastRun: null });
      await get().reload();
      toast.ok(t("automation.projectDeleted"));
    } catch (e) {
      toast.err(safeUiError(e));
    }
  },

  run: async (p) => {
    const profileId = get().runProfile;
    if (!profileId) {
      toast.err(t("automation.pickARunningProfileFirst"));
      return;
    }
    if (!p.id) {
      toast.err(t("automation.saveTheProjectBeforeRunningIt"));
      return;
    }
    set({ running: true, lastRun: null });
    try {
      const report = await automationRun(p.id, profileId);
      set({ lastRun: report });
      // A run that ends early is not a success, even though the call returned.
      if (report.ok) toast.ok(t("automation.runFinishedMs", { ms: report.ms }));
      else toast.err(report.stopped_because || t("automation.runFailed"));
    } catch (e) {
      toast.err(safeUiError(e));
    } finally {
      set({ running: false });
    }
  },
}));
