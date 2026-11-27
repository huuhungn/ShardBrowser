import { SegmentControl } from "@proxyshard/shardx-ui-kit";
import type { NoiseMode } from "../../entities/profile";
import { WarningIcon } from "../icons";
import { t } from "../i18n";

/// Two-way toggle (Real/Auto-noise or Allow/Block) — UI-kit SegmentControl.
export function Pair({
  label, value, on, blockLabel, onText, note, warn,
}: {
  label: string;
  value: NoiseMode;
  on: (v: NoiseMode) => void;
  /// Allow/Block labels instead of Real/Auto (used by Ports).
  blockLabel?: boolean;
  /// Custom "on" label (default t("ui.autoNoise"); Fonts passes "Noise").
  onText?: string;
  /// A line under the toggle; `warn` shows it as a warning.
  note?: string;
  warn?: boolean;
}) {
  const labelFor = (o: NoiseMode) =>
    blockLabel
      ? (o === "real" ? t("ui.allow") : t("ui.block"))
      : (o === "real" ? t("ui.real") : (onText ?? t("ui.autoNoise")));
  const control = (
    <label className="flex flex-col gap-1">
      <span className="text-label-base font-medium text-text-strong-900">{label}</span>
      <SegmentControl
        size="small"
        className="w-full *:flex-1 flex-nowrap text-nowrap"
        value={value}
        
        items={(["real", "auto"] as NoiseMode[]).map((o) => ({ value: o, label: labelFor(o) }))}
        onChange={(v) => on(v as NoiseMode)}
      />
    </label>
  );
  // Outside the label, so the note is not part of the toggle's accessible name.
  if (!note) return control;
  return (
    <div className="flex flex-col gap-1">
      {control}
      <span className={`flex items-start gap-1 text-paragraph-xs ${warn ? "text-[var(--color-warning)]" : "text-text-soft-400"}`}>
        {warn && <WarningIcon className="mt-[2px] size-3.5 shrink-0" />}
        <span>{note}</span>
      </span>
    </div>
  );
}
