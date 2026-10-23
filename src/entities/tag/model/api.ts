import { invoke } from "@tauri-apps/api/core";

/// A tag as the launcher reports it: names live on each profile, colors in tags.json.
export type TagInfo = {
  name: string;
  /// Palette id (see TAG_COLORS); null = derived from the name.
  color: string | null;
  /// Profiles carrying it; 0 for a tag that only has a color so far.
  count: number;
};

export const tagsList = () => invoke<TagInfo[]>("tags_list");
export const tagRename = (old: string, name: string) => invoke<number>("tag_rename", { old, new: name });
/** `color` null clears it; coloring an unused name creates an empty tag. */
export const tagRecolor = (name: string, color: string | null) => invoke<void>("tag_recolor", { name, color });
export const tagDelete = (name: string) => invoke<number>("tag_delete", { name });
