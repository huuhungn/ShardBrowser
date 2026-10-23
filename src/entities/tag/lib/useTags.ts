import { create } from "zustand";
import { toast } from "../../../shared/model/toast";
import { tagsList, type TagInfo } from "../model/api";

/// Palette ids the backend accepts; app.css styles `.tag-chip[data-color=…]`.
export const TAG_COLORS = ["gray", "red", "orange", "yellow", "green", "teal", "blue", "purple"] as const;
export type TagColor = (typeof TAG_COLORS)[number];

/// Mirrors the launcher's normalize_tag: trim, collapse whitespace, 32 characters.
export const TAG_NAME_MAX = 32;
export const cleanTag = (name: string) =>
  [...name.replace(/[\s\p{Cc}]+/gu, " ").trim()].slice(0, TAG_NAME_MAX).join("").trimEnd();
export const sameTag = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();

/// A stored palette color, else one derived from the name so it stays put across
/// reloads. A color the API stored outside the palette is treated as none.
export function tagColor(name: string, tags: TagInfo[]): TagColor {
  const stored = tags.find((t) => sameTag(t.name, name))?.color;
  const known = TAG_COLORS.find((c) => c === stored);
  if (known) return known;
  let h = 0;
  for (const ch of name.toLowerCase()) h = (h * 31 + ch.codePointAt(0)!) >>> 0;
  return TAG_COLORS[h % TAG_COLORS.length];
}

type TagStore = {
  tags: TagInfo[];
  reload: () => Promise<void>;
};

export const useTags = create<TagStore>((set) => ({
  tags: [],
  reload: async () => {
    try { set({ tags: await tagsList() }); }
    catch (e) { toast.err(e); }
  },
}));
