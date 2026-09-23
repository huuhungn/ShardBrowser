import { cn } from "@proxyshard/shardx-ui-kit";
import { useT } from "../../shared/i18n";

/** Profile accent: the window icon and the omnibox pill. "" = derive from the
 *  name, which is what the browser does on its own. */
export const PROFILE_COLORS = [
  "#2FCB80", "#12B76A", "#0BA5EC", "#3B82F6", "#724FFF", "#9E5BFF",
  "#E040C8", "#EC4899", "#F04438", "#F97316", "#EAB308", "#84CC16",
];

export function ColorSwatches({
  value, onChange, label,
}: {
  value: string;
  onChange: (v: string) => void;
  label?: string;
}) {
  const t = useT();
  return (
    <div className="flex flex-col gap-1.5">
      {label && <span className="text-label-base font-medium text-text-strong-900">{label}</span>}
      <div className="flex flex-wrap items-center gap-1.5">
        <button
          type="button"
          title={t("ui.autoDerivedFromTheProfileName")}
          onClick={() => onChange("")}
          className={cn(
            "grid size-6 place-items-center rounded-full text-[9px] font-bold text-text-sub-600 ring-1 ring-inset transition-[box-shadow]",
            value === ""
              ? "ring-2 ring-primary-base"
              : "ring-stroke-soft-200 hover:ring-stroke-sub-300",
          )}
        >
          A
        </button>
        {PROFILE_COLORS.map((c) => (
          <button
            key={c}
            type="button"
            title={c}
            onClick={() => onChange(c)}
            style={{ background: c }}
            className={cn(
              "size-6 rounded-full transition-[box-shadow]",
              value.toLowerCase() === c.toLowerCase()
                ? "ring-2 ring-text-strong-950 ring-offset-2 ring-offset-bg-weak-50"
                : "ring-1 ring-inset ring-black/10 hover:ring-black/25",
            )}
          />
        ))}
      </div>
    </div>
  );
}
