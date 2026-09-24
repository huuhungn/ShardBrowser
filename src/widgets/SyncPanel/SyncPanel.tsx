import { useEffect, useRef, useState } from "react";
import {
  syncStatus, syncSetPaused, syncArrange, syncStop, syncSetExcluded,
  syncClosePanel, type SyncStatus, type SyncLayout,
} from "../../entities/profile/model/api";
import { PlayIcon, PauseIcon, SyncIcon, StopIcon } from "../../shared/icons";
import { dragWindowOnMouseDown } from "../../shared/lib/dragWindow";
import { useT } from "../../shared/i18n";

/**
 * One floating control surface for the whole group. Every window is equal —
 * whichever the operator works in is the one driving — so nothing is per-window.
 */
export function SyncPanel({ group }: { group: string }) {
  const t = useT();
  const [status, setStatus] = useState<SyncStatus | null>(null);
  const [busy, setBusy] = useState(false);
  // Must survive the second before the first browser connects, and go once
  // they are all gone.
  const everHadMembers = useRef(false);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const s = await syncStatus(group);
        if (!alive) return;
        setStatus(s);
        if (s.members.length > 0) everHadMembers.current = true;
        else if (everHadMembers.current) void syncClosePanel();
      } catch { /* the group may not exist yet */ }
    };
    void tick();
    const id = setInterval(tick, 1000);
    return () => { alive = false; clearInterval(id); };
  }, [group]);

  const paused = status?.paused ?? false;
  const members = status?.members ?? [];

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try { await fn(); } catch { /* the next poll shows the truth */ }
    setBusy(false);
  };

  return (
    // The whole panel drags. Explicit startDragging, not
    // data-tauri-drag-region — Tauri tests that on the exact element hit.
    <div
      onMouseDown={dragWindowOnMouseDown}
      className="flex h-screen w-screen flex-col rounded-12 bg-bg-white-0 ring-1 ring-inset ring-stroke-soft-200"
    >
      <div className="flex shrink-0 select-none items-center gap-2 px-3 pt-2.5 pb-1.5">
        <SyncIcon className="size-4 shrink-0 text-primary-base" />
        <div className="flex-1 truncate text-label-xs text-text-strong-950">
          {members.length} in sync
        </div>
        <button type="button" onMouseDown={(e) => e.stopPropagation()} disabled={busy}
                onClick={() => run(() => syncSetPaused(group, !paused))}
                title={paused ? t("sync.resume") : t("sync.holdWorkInOneWindowAlone")}
                className="flex size-6 items-center justify-center rounded-6 text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200 hover:bg-bg-weak-50 disabled:opacity-50">
          {paused ? <PlayIcon className="size-3" /> : <PauseIcon className="size-3" />}
        </button>
        <button type="button" onMouseDown={(e) => e.stopPropagation()} disabled={busy}
                onClick={() => run(() => syncStop(group))}
                title={t("sync.closeEveryWindowInTheGroup")}
                className="flex size-6 items-center justify-center rounded-6 text-error-base ring-1 ring-inset ring-stroke-soft-200 hover:bg-error-lighter disabled:opacity-50">
          <StopIcon className="size-3" />
        </button>
      </div>

      <div className="flex shrink-0 gap-1 px-3 pb-2">
        {(["row", "grid", "cascade"] as SyncLayout[]).map((l) => (
          <button key={l} type="button" disabled={busy || members.length === 0}
                  onClick={() => run(() => syncArrange(group, l))}
                  className="flex-1 rounded-6 py-1 text-paragraph-xs capitalize text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200 hover:bg-bg-weak-50 disabled:opacity-40">
            {l}
          </button>
        ))}
      </div>

      {/* Chips, not rows: twelve rows is a scrollbar, and twelve is an
          ordinary fleet. */}
      <div className="min-h-0 flex-1 content-start overflow-auto border-t border-stroke-soft-200 px-2 py-1.5">
        {members.length === 0 ? (
          <div className="text-paragraph-xs text-text-soft-400">{t("sync.starting")}</div>
        ) : (
          <div className="flex flex-wrap gap-1">
            {members.map((m) => (
              <button
                key={m.profile}
                type="button"
                disabled={busy}
                onClick={() => run(() => syncSetExcluded(group, m.profile, !m.excluded))}
                title={`${m.profile}${m.driving ? " — driving" : ""}\n${
                  m.excluded ? t("sync.clickToBringBackIntoTheGroup") : t("sync.clickToHoldOut")}`}
                className={`flex max-w-[9rem] items-center gap-1 rounded-6 px-1.5 py-0.5 text-paragraph-xs ring-1 ring-inset disabled:opacity-50 ${
                  m.excluded
                    ? "text-text-soft-400 line-through ring-stroke-soft-200"
                    : "text-text-sub-600 ring-stroke-soft-200 hover:bg-bg-weak-50"
                }`}
              >
                {/* Where the input is coming from. */}
                <span className={`size-1.5 shrink-0 rounded-full ${
                  m.driving && !m.excluded ? "bg-success-base" : "bg-stroke-soft-200"}`} />
                <span className="truncate">{m.profile}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
