import { create } from "zustand";
import { toast } from "../../../shared/lib/toast";
import { confirmModal } from "../../../shared/lib/confirm";
import { bookmarkDelete, bookmarkList, bookmarkSave } from "../model/api";
import type { Bookmark } from "../model/types";
import { t } from "../../../shared/i18n";

export const emptyBookmark = (folder = ""): Bookmark => ({
  id: "",
  title: "",
  url: "",
  folder,
});

export type BookmarkStore = {
  status: "idle" | "loading" | "ready" | "error";
  items: Bookmark[];
  /** Open editor, or null. */
  editing: Bookmark | null;
  search: string;
  /** Folder tab; "all" shows everything. */
  folder: string;

  init: () => Promise<void>;
  reload: () => Promise<void>;
  setEditing: (b: Bookmark | null) => void;
  setSearch: (q: string) => void;
  setFolder: (f: string) => void;
  save: (b: Bookmark) => Promise<void>;
  remove: (b: Bookmark) => Promise<void>;
};

export const useBookmarks = create<BookmarkStore>((set, get) => ({
  status: "idle",
  items: [],
  editing: null,
  search: "",
  folder: "all",

  init: async () => {
    if (get().status === "loading" || get().status === "ready") return;
    set({ status: "loading" });
    try {
      set({ items: await bookmarkList(), status: "ready" });
    } catch (e) {
      set({ status: "error" });
      toast.err(String(e));
    }
  },
  reload: async () => {
    try { set({ items: await bookmarkList() }); }
    catch (e) { toast.err(String(e)); }
  },
  setEditing: (editing) => set({ editing }),
  setSearch: (search) => set({ search }),
  setFolder: (folder) => set({ folder }),

  save: async (b) => {
    try {
      await bookmarkSave(b);
      set({ editing: null });
      await get().reload();
      toast.ok(b.id ? t("bookmarks.bookmarkSaved") : t("bookmarks.bookmarkAdded"));
    } catch (e) { toast.err(String(e)); }
  },

  remove: async (b) => {
    const ok = await confirmModal({
      title: t("bookmarks.deleteBookmark"),
      message: t("bookmarks.deleteAsk", { name: b.title || b.url }),
      danger: true,
    });
    if (ok !== true) return;
    try {
      await bookmarkDelete(b.id);
      await get().reload();
    } catch (e) { toast.err(String(e)); }
  },
}));
