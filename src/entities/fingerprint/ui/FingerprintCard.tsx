import type { ReactNode } from "react";
import Badge from "../../../shared/ui/Badge";
import type { FingerprintEntry } from "../model/types";
import { useGpuCompat, useGpuCompatReady } from "../../../shared/model/gpuCompat";
import { IncompatibleBadge } from "../../../features/gpu-compat";

export function FingerprintCard({ entry, actions }: { entry: FingerprintEntry; actions?: ReactNode }) {
  // undefined while the GPU probe has not answered yet, and on machines where
  // it cannot run at all. Both are "no verdict", and no verdict must not look
  // like a clean one — hence the badge renders only on a definite mismatch.
  useGpuCompatReady();
  const compat = useGpuCompat((s) => s.byId[entry.id]);
  return (
    <div
      className="relative flex flex-col gap-1.5 rounded-10 border-l-[3px] bg-bg-white-0 px-3.5 py-3 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200 transition-colors hover:bg-bg-weak-50 hover:ring-stroke-sub-300"
      style={{ borderLeftColor: entry.tag_color ?? "var(--color-primary-base)" }}
    >
      <div className="flex items-baseline justify-between gap-2.5">
        <span className="min-w-0 overflow-hidden text-ellipsis whitespace-nowrap text-label-xs leading-[1.25] text-text-strong-950">{entry.label}</span>
        <span className="flex flex-none items-center gap-1.5">
          {compat && <IncompatibleBadge compat={compat} />}
          {entry.chrome && <Badge color="gray" variant="filled" size="small" className="flex-none">Chrome {entry.chrome}</Badge>}
        </span>
      </div>
      <div className="mono overflow-hidden text-ellipsis whitespace-nowrap text-[11px] text-text-soft-400" title={entry.gpu}>{entry.gpu || "—"}</div>
      {actions && (
        <div className="mt-1 flex items-center gap-1.5 border-t border-stroke-soft-200 pt-2">
          {actions}
        </div>
      )}
    </div>
  );
}
