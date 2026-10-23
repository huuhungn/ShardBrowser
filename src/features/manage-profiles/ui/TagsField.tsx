import { Input } from "@proxyshard/shardx-ui-kit";
import { TagChip, cleanTag, sameTag, useTags } from "../../../entities/tag";
import { useT } from "../../../shared/i18n";

/// Adds `query` to `tags` the way Enter would; callers saving the field use it
/// so a name typed but not yet entered is not lost.
export function withPendingTag(tags: string[], query: string, known: { name: string }[]): string[] {
  const clean = cleanTag(query);
  if (!clean || tags.some((v) => sameTag(v, clean))) return tags;
  // Reuse the spelling already in use, as the launcher would.
  return [...tags, known.find((k) => sameTag(k.name, clean))?.name ?? clean];
}

/// Chips for the profile's tags plus a box that adds one on Enter, offering existing tags.
export function TagsField({ value, onChange, query, onQuery }: {
  value: string[];
  onChange: (tags: string[]) => void;
  query: string;
  onQuery: (query: string) => void;
}) {
  const t = useT();
  const known = useTags((s) => s.tags);
  const q = cleanTag(query);
  const suggestions = known
    .filter((k) => !value.some((v) => sameTag(v, k.name)))
    .filter((k) => !q || k.name.toLowerCase().includes(q.toLowerCase()))
    .slice(0, 8);

  const add = (name: string) => {
    onChange(withPendingTag(value, name, known));
    onQuery("");
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
        onChange={(e) => onQuery(e.target.value)}
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
