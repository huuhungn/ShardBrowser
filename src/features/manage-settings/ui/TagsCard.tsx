import { useEffect, useState } from "react";
import { Button, Input, cn } from "@proxyshard/shardx-ui-kit";
import { profileSetTags, useProfile } from "../../../entities/profile";
import {
  TAG_COLORS, TagChip, cleanTag, sameTag, tagColor, tagDelete, tagRecolor, tagRename, useTags,
} from "../../../entities/tag";
import { toast } from "../../../shared/model/toast";
import { safeUiError } from "../../../shared/lib/utils";
import { useT } from "../../../shared/i18n";

type Deleted = { name: string; color: string | null; profileIds: string[] };

/// Rename, recolor and delete tags; a delete can be undone until the next change.
export function TagsCard() {
  const t = useT();
  const tags = useTags((s) => s.tags);
  const reloadProfiles = useProfile((s) => s.reload);
  const [editing, setEditing] = useState<string | null>(null);
  const [draft, setDraft] = useState("");
  const [created, setCreated] = useState("");
  const [deleted, setDeleted] = useState<Deleted | null>(null);

  // Profiles carry the tags, so the store reloads both.
  useEffect(() => { void reloadProfiles(); }, [reloadProfiles]);

  const run = async (work: () => Promise<unknown>) => {
    try { await work(); }
    catch (e) { toast.err(safeUiError(e)); }
    await reloadProfiles();
  };

  // The browsers list may be filtered by the tag that just changed name or went away.
  const followFilter = (old: string, next: string) => {
    const { filters, setFilters } = useProfile.getState();
    if (filters.tag && sameTag(filters.tag, old)) setFilters({ tag: next });
  };

  const rename = (old: string) => run(async () => {
    const name = cleanTag(draft);
    setEditing(null);
    if (!name || name === old) return;
    setDeleted(null);
    const n = await tagRename(old, name);
    followFilter(old, name);
    toast.ok(t("tag.renamed", { n }));
  });

  const recolor = (name: string, color: string) => run(async () => {
    setDeleted(null);
    await tagRecolor(name, color);
  });

  const remove = (name: string, color: string | null) => run(async () => {
    const profileIds = useProfile.getState().profiles
      .filter((p) => p.tags.some((x) => sameTag(x, name)))
      .map((p) => p.id);
    const n = await tagDelete(name);
    setDeleted({ name, color, profileIds });
    followFilter(name, "");
    toast.ok(t("tag.deleted", { name, n }));
  });

  // Keeps the banner, with only the profiles still missing the tag, if any fail.
  const undo = (d: Deleted) => run(async () => {
    if (d.color) await tagRecolor(d.name, d.color);
    await reloadProfiles();
    const byId = new Map(useProfile.getState().profiles.map((p) => [p.id, p]));
    const failed: string[] = [];
    let firstError = "";
    for (const id of d.profileIds) {
      const p = byId.get(id);
      if (!p) continue;
      try { await profileSetTags(id, [...p.tags, d.name]); }
      catch (e) { failed.push(id); firstError ||= safeUiError(e); }
    }
    if (failed.length) {
      setDeleted({ ...d, color: null, profileIds: failed });
      toast.err(t("tag.couldNotTag", { n: failed.length, err: firstError }));
      return;
    }
    setDeleted(null);
    toast.ok(t("tag.restored", { name: d.name }));
  });

  const create = () => run(async () => {
    const name = cleanTag(created);
    setCreated("");
    setDeleted(null);
    if (!name) return;
    // A tag with no profile yet exists through its color.
    await tagRecolor(name, tagColor(name, tags));
  });

  return (
    <div className="flex flex-col gap-3">
      <p className="m-0 text-paragraph-xs text-text-soft-400">{t("settings.tags.help")}</p>
      {deleted && (
        <div role="status" className="flex items-center justify-between gap-2 rounded-8 bg-bg-weak-50 px-3 py-2 text-paragraph-xs">
          <span>{t("tag.deletedShort", { name: deleted.name })}</span>
          <Button variant="neutral" mode="stroke" size="2xsmall" onClick={() => undo(deleted)}>{t("tag.undo")}</Button>
        </div>
      )}
      {tags.length === 0 && <p className="m-0 text-paragraph-xs text-text-soft-400">{t("tag.noTags")}</p>}
      <ul className="m-0 flex list-none flex-col gap-1.5 p-0" aria-label={t("settings.tags.title")}>
        {tags.map((x) => (
          <li key={x.name} className="flex flex-wrap items-center gap-2" data-testid="tag-row">
            {editing === x.name ? (
              <Input
                inputSize="small"
                value={draft}
                maxLength={64}
                aria-label={t("tag.rename")}
                autoFocus
                onChange={(e) => setDraft(e.target.value)}
                onBlur={() => setEditing(null)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void rename(x.name);
                  if (e.key === "Escape") setEditing(null);
                }}
              />
            ) : (
              <TagChip name={x.name} />
            )}
            <span className="text-paragraph-xs text-text-soft-400">{t("tag.profileCount", { n: x.count })}</span>
            <span className="flex items-center gap-1">
              {TAG_COLORS.map((c) => (
                <button
                  key={c}
                  type="button"
                  aria-label={t("tag.color", { name: x.name, color: t(`tag.colorName.${c}`) })}
                  aria-pressed={tagColor(x.name, tags) === c}
                  className={cn("tag-swatch", tagColor(x.name, tags) === c && "tag-swatch-on")}
                  data-color={c}
                  onClick={() => recolor(x.name, c)}
                />
              ))}
            </span>
            <span className="ml-auto flex items-center gap-1">
              <Button
                variant="neutral"
                mode="ghost"
                size="2xsmall"
                aria-label={t("tag.renameOne", { name: x.name })}
                onClick={() => { setEditing(x.name); setDraft(x.name); }}
              >
                {t("tag.rename")}
              </Button>
              <Button
                variant="error"
                mode="ghost"
                size="2xsmall"
                aria-label={t("tag.deleteOne", { name: x.name })}
                onClick={() => remove(x.name, x.color)}
              >
                {t("tag.delete")}
              </Button>
            </span>
          </li>
        ))}
      </ul>
      <div className="flex items-end gap-2">
        <Input
          label={t("tag.newTag")}
          inputSize="small"
          value={created}
          maxLength={64}
          placeholder={t("tag.typeToCreate")}
          onChange={(e) => setCreated(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") void create(); }}
        />
        <Button variant="neutral" mode="stroke" size="small" onClick={() => void create()} disabled={!cleanTag(created)}>
          {t("tag.create")}
        </Button>
      </div>
    </div>
  );
}
