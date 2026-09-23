import { create } from "zustand";
import { toast } from "../../../shared/lib/toast";
import { confirmModal } from "../../../shared/lib/confirm";
import { storeBus } from "../../../shared/lib/storeBus";
import { trashEmpty, trashList, trashPurge, trashRestore } from "../model/api";
import type { TrashEntry } from "../model/types";
import { t } from "../../../shared/i18n";

export type TrashStore = {
  status: "idle" | "loading" | "ready" | "error";
  items: TrashEntry[];
  busy: string | null;

  init: () => Promise<void>;
  reload: () => Promise<void>;
  restore: (e: TrashEntry) => Promise<void>;
  purge: (e: TrashEntry) => Promise<void>;
  empty: () => Promise<void>;
};

export const useTrash = create<TrashStore>((set, get) => ({
  status: "idle",
  items: [],
  busy: null,

  init: async () => {
    if (get().status === "loading") return;
    set({ status: "loading" });
    try { set({ items: await trashList(), status: "ready" }); }
    catch (e) { set({ status: "error" }); toast.err(String(e)); }
  },
  reload: async () => {
    try { set({ items: await trashList() }); }
    catch (e) { toast.err(String(e)); }
  },

  restore: async (e) => {
    set({ busy: e.id });
    try {
      const meta = await trashRestore(e.id);
      await get().reload();
      storeBus.emit("profiles");
      toast.ok(`Restored "${meta.name}"`);
    } catch (err) { toast.err(String(err)); }
    finally { set({ busy: null }); }
  },

  purge: async (e) => {
    const ok = await confirmModal({
      title: t("trash.deleteForGood"),
      message: `"${e.name}" cannot be brought back after this.`,
      danger: true,
    });
    if (ok !== true) return;
    try { await trashPurge(e.id); await get().reload(); }
    catch (err) { toast.err(String(err)); }
  },

  empty: async () => {
    const n = get().items.length;
    if (n === 0) return;
    const ok = await confirmModal({
      title: t("trash.emptyTheTrash"),
      message: `Delete ${n} profile${n === 1 ? "" : "s"} for good?`,
      danger: true,
    });
    if (ok !== true) return;
    try {
      await trashEmpty();
      await get().reload();
      toast.ok(`Deleted ${n}`);
    } catch (err) { toast.err(String(err)); }
  },
}));
