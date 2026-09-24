import { create } from "zustand";
import { open } from "@tauri-apps/plugin-dialog";
import { toast } from "../../../shared/lib/toast";
import { confirmModal } from "../../../shared/lib/confirm";
import { storeBus } from "../../../shared/lib/storeBus";
import { extensionDelete, extensionImport, extensionImportUrl, extensionList } from "../model/api";
import type { ExtensionEntry } from "../model/types";
import { t } from "../../../shared/i18n";
import { safeUiError } from "../../../shared/lib/utils";

export type ExtensionStore = {
  status: "idle" | "loading" | "ready" | "error";
  items: ExtensionEntry[];
  busy: boolean;
  search: string;
  /// The "paste a link" dialog.
  linkOpen: boolean;

  init: () => Promise<void>;
  reload: () => Promise<void>;
  setSearch: (q: string) => void;
  setLinkOpen: (open: boolean) => void;
  importUrl: (url: string) => Promise<void>;
  importFiles: () => Promise<void>;
  importFolder: () => Promise<void>;
  remove: (e: ExtensionEntry) => Promise<void>;
};

export const useExtensions = create<ExtensionStore>((set, get) => ({
  status: "idle",
  items: [],
  busy: false,
  search: "",
  linkOpen: false,

  init: async () => {
    if (get().status === "loading" || get().status === "ready") return;
    set({ status: "loading" });
    try {
      set({ items: await extensionList(), status: "ready" });
    } catch (e) {
      set({ status: "error" });
      toast.err(safeUiError(e));
    }
  },
  reload: async () => {
    try {
      set({ items: await extensionList() });
      storeBus.emit("extensions");
    } catch (e) { toast.err(safeUiError(e)); }
  },
  setSearch: (search) => set({ search }),
  setLinkOpen: (linkOpen) => set({ linkOpen }),

  importUrl: async (url) => {
    if (!url.trim()) return;
    set({ busy: true });
    try {
      const added = await extensionImportUrl(url.trim());
      await get().reload();
      set({ linkOpen: false });
      toast.ok(t("extensions.addedNamed", { name: added.name }));
    } catch (e) { toast.err(t("extensions.downloadFailed") + safeUiError(e)); }
    finally { set({ busy: false }); }
  },

  importFiles: async () => {
    const picked = await open({
      multiple: true,
      title: t("extensions.pickCrxOrZipExtensions"),
      filters: [{ name: t("extensions.extension"), extensions: ["crx", "zip"] }],
    });
    const paths = Array.isArray(picked) ? picked : picked ? [picked] : [];
    if (paths.length === 0) return;
    set({ busy: true });
    try {
      const added = await extensionImport(paths as string[]);
      await get().reload();
      toast.ok(
        t(added.length === 1 ? "extensions.addedOne" : "extensions.addedMany", {
          n: added.length,
        }),
      );
    } catch (e) { toast.err(t("extensions.importFailed") + safeUiError(e)); }
    finally { set({ busy: false }); }
  },

  importFolder: async () => {
    const dir = await open({ directory: true, title: t("extensions.pickAnUnpackedExtensionFolder") });
    if (typeof dir !== "string") return;
    set({ busy: true });
    try {
      const added = await extensionImport([dir]);
      await get().reload();
      toast.ok(
        added.length > 0
          ? t("extensions.addedNamed", { name: added[0].name })
          : t("extensions.nothingAdded"),
      );
    } catch (e) { toast.err(t("extensions.importFailed") + safeUiError(e)); }
    finally { set({ busy: false }); }
  },

  remove: async (e) => {
    const ok = await confirmModal({
      title: t("extensions.removeExtension"),
      message: t("extensions.removeAsk", { name: e.name }),
      danger: true,
    });
    if (ok !== true) return;
    try {
      await extensionDelete(e.id);
      await get().reload();
      toast.ok(t("extensions.extensionRemoved"));
    } catch (err) { toast.err(safeUiError(err)); }
  },
}));
