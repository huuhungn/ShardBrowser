import { useState } from "react";
import { Button, Input } from "@proxyshard/shardx-ui-kit";
import { useProfile } from "../../../entities/profile";
import { TagChip, cleanTag, sameTag, useTags } from "../../../entities/tag";
import { useT } from "../../../shared/i18n";

/// "Tag" button on the bulk bar: pick or type a tag to toggle it on the selection.
export function BulkTagMenu() {
  const t = useT();
  const tags = useTags((s) => s.tags);
  const bulkToggleTag = useProfile((s) => s.bulkToggleTag);
  const selected = useProfile((s) => s.selected);
  const profiles = useProfile((s) => s.profiles);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");

  const chosen = profiles.filter((p) => selected.has(p.id));
  const carrying = (name: string) => chosen.filter((p) => p.tags.some((x) => sameTag(x, name))).length;
  const apply = (name: string) => {
    const clean = cleanTag(name);
    if (!clean) return;
    setOpen(false);
    setQuery("");
    void bulkToggleTag(clean);
  };

  return (
    <div className="relative">
      <Button variant="neutral" mode="stroke" className="pr-3" size="2xsmall" onClick={() => setOpen((v) => !v)}>
        {t("tag.tagSelection")}
      </Button>
      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div
            role="dialog"
            aria-label={t("tag.tagSelection")}
            className="absolute left-0 z-20 mt-1.5 flex w-[260px] flex-col gap-2 rounded-xl bg-bg-white-0 p-3 shadow-[var(--shadow-md)] ring-1 ring-stroke-soft-200"
          >
            <span className="text-paragraph-xs text-text-soft-400">{t("tag.toggleHint")}</span>
            <div className="flex max-h-[200px] flex-col gap-1 overflow-y-auto">
              {tags.map((x) => {
                const n = carrying(x.name);
                return (
                  <button
                    key={x.name}
                    type="button"
                    className="flex items-center justify-between gap-2 rounded-8 px-1.5 py-1 text-left hover:bg-bg-weak-50"
                    onClick={() => apply(x.name)}
                  >
                    <TagChip name={x.name} />
                    <span className="text-paragraph-xs text-text-soft-400">{n}/{chosen.length}</span>
                  </button>
                );
              })}
            </div>
            <Input
              inputSize="small"
              value={query}
              maxLength={64}
              placeholder={t("tag.typeToCreate")}
              aria-label={t("tag.newTag")}
              autoFocus
              onChange={(e) => setQuery(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") apply(query);
                if (e.key === "Escape") setOpen(false);
              }}
            />
          </div>
        </>
      )}
    </div>
  );
}
