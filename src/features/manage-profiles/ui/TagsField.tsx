import { useState } from "react";
import { Input } from "@proxyshard/shardx-ui-kit";
import { TagChip, cleanTag, sameTag, useTags } from "../../../entities/tag";
import { useT } from "../../../shared/i18n";

/// Chips for the profile's tags plus a box that adds one on Enter, offering existing tags.
export function TagsField({ value, onChange }: {
  value: string[];
  onChange: (tags: string[]) => void;
}) {
  const t = useT();
  const known = useTags((s) => s.tags);
  const [query, setQuery] = useState("");
  const q = cleanTag(query);
  const suggestions = known
    .filter((k) => !value.some((v) => sameTag(v, k.name)))
    .filter((k) => !q || k.name.toLowerCase().includes(q.toLowerCase()))
    .slice(0, 8);

  const add = (name: string) => {
    const clean = cleanTag(name);
    if (!clean || value.some((v) => sameTag(v, clean))) { setQuery(""); return; }
    // Reuse the spelling already in use, as the launcher would.
    const spelled = known.find((k) => sameTag(k.name, clean))?.name ?? clean;
    onChange([...value, spelled]);
    setQuery("");
  };

  return (
    <div className="flex flex-col gap-2">
      <div className="flex min-h-6 flex-wrap items-center gap-1.5" data-testid="tags-field-chips">
        {value.length === 0 && <span className="text-paragraph-xs text-text-soft-400">{t("tag.noTags")}</span>}
        {value.map((name) => (
          <TagChip key={name} name={name}>
            <button
              type="button"
              className="tag-chip-x"
              aria-label={t("tag.removeTag", { name })}
              onClick={() => onChange(value.filter((v) => v !== name))}
            >
              ×
            </button>
          </TagChip>
        ))}
      </div>
      <Input
        label={t("tag.addTag")}
        inputSize="small"
        value={query}
        maxLength={64}
        placeholder={t("tag.typeToCreate")}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter") { e.preventDefault(); add(query); }
        }}
      />
      {suggestions.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {suggestions.map((k) => (
            <button key={k.name} type="button" className="rounded-full" onClick={() => add(k.name)}>
              <TagChip name={k.name} className="cursor-pointer opacity-80 hover:opacity-100" />
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
