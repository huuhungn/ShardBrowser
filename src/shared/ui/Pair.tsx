import { SegmentControl } from "@proxyshard/shardx-ui-kit";
import type { NoiseMode } from "../../entities/profile";
import { t } from "../i18n";

/// Two-way toggle (Real/Auto-noise or Allow/Block) — UI-kit SegmentControl.
export function Pair({
  label, value, on, blockLabel, onText,
}: {
  label: string;
  value: NoiseMode;
  on: (v: NoiseMode) => void;
  /// Allow/Block labels instead of Real/Auto (used by Ports).
  blockLabel?: boolean;
  /// Custom "on" label (default t("ui.autoNoise"); Fonts passes "Noise").
  onText?: string;
}) {
  const labelFor = (o: NoiseMode) =>
    blockLabel
      ? (o === "real" ? t("ui.allow") : t("ui.block"))
      : (o === "real" ? t("ui.real") : (onText ?? t("ui.autoNoise")));
  return (
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
}
