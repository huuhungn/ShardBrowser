import { useRef } from "react";
import { Checkbox, cn } from "@proxyshard/shardx-ui-kit";
import Badge from "../../shared/ui/Badge";
import { PinIconApp } from "../../shared/icons";
import type { ContextItem } from "../../shared/types";
import { CountryFlag } from "../../shared/ui/CountryFlag";
import { fmtTs, fmtUptime } from "../../shared/lib/utils";
import { useProfile, type ProfileMeta } from "../../entities/profile";
import { useTeam, canSyncProfiles, syncBlockedReason } from "../../entities/team";
import type { ProxyEntry } from "../../entities/proxy";
import { ProfileInlineEditor, ProfileRowActions } from "../../features/manage-profiles";
import { useT } from "../../shared/i18n";

export function ProfileRow({ profile, proxy, onMenu }: {
  profile: ProfileMeta;
  proxy: ProxyEntry | null;
  onMenu: (e: React.MouseEvent, items: ContextItem[]) => void;
}) {
  const t = useT();
  const p = profile;
  const isRunning = useProfile((s) => !!s.running[p.id]);
  const runningSince = useProfile((s) => s.running[p.id]);
  const isSel = useProfile((s) => s.selected.has(p.id));
  const isExpanded = useProfile((s) => s.expanded === p.id);

  const startStop = useProfile((s) => s.startStop);
  const togglePin = useProfile((s) => s.togglePin);
  const cloneProfile = useProfile((s) => s.cloneProfile);
  const remove = useProfile((s) => s.remove);
  const expand = useProfile((s) => s.expand);
  const toggleSelect = useProfile((s) => s.toggleSelect);
  const selectRangeTo = useProfile((s) => s.selectRangeTo);
  const setQuickEdit = useProfile((s) => s.setQuickEdit);
  const setFolderModal = useProfile((s) => s.setFolderModal);
  const setProfileFolder = useProfile((s) => s.setProfileFolder);
  const exportCookies = useProfile((s) => s.exportCookies);
  const backupProfile = useProfile((s) => s.backupProfile);
  const restoreProfile = useProfile((s) => s.restoreProfile);
  const pushProfile = useProfile((s) => s.pushProfile);
  const pullProfile = useProfile((s) => s.pullProfile);
  const teamReady = useTeam(canSyncProfiles);
  // An enrolled device that still cannot sync gets the entries, greyed with
  // the reason, rather than silently missing menu items.
  const syncBlocked = useTeam(syncBlockedReason);
  const importCookies = useProfile((s) => s.importCookies);
  const copyCdpHttpUrl = useProfile((s) => s.copyCdpHttpUrl);
  const copyDevToolsInspectUrl = useProfile((s) => s.copyDevToolsInspectUrl);
  const bringVerificationToFront = useProfile((s) => s.bringVerificationToFront);
  const launchError = useProfile((s) => s.launchError[p.id]);

  // Shift-presses are handled in mousedown only: a click on the checkbox's
  // <label> reaches the row twice, and applying the range twice would undo it.
  const shiftPress = useRef(false);

  // Per-profile action menu shared by right-click and the ⋮ button.
  const menu = (): ContextItem[] => [
    { label: isRunning ? "Stop" : "Launch", onClick: () => startStop(p) },
    { label: "Edit", onClick: () => expand(p.id) },
    { label: "Clone", onClick: () => cloneProfile(p.id) },
    { label: p.pinned ? "Unpin" : "Pin to top", onClick: () => togglePin(p) },
    { sep: true, label: "", onClick: () => {} },
    { label: "Move to folder…", onClick: () => setFolderModal({ profileId: p.id }) },
    ...(p.folder
      ? [{ label: "Remove from folder", onClick: () => setProfileFolder(p.id, "") }]
      : []),
    { sep: true, label: "", onClick: () => {} },
    // These read or replace the whole profile directory, which Chromium holds
    // open while it runs. Showing them greyed with the reason beats letting
    // someone click and only then be told to stop the profile.
    {
      label: "Back up (encrypted)…",
      onClick: () => backupProfile(p),
      disabledReason: isRunning ? "Stop the profile first" : undefined,
    },
    {
      label: "Restore from backup…",
      onClick: () => restoreProfile(p),
      disabledReason: isRunning ? "Stop the profile first" : undefined,
    },
    ...(teamReady || syncBlocked
      ? [
          { sep: true, label: "", onClick: () => {} },
          {
            label: "Push to team",
            onClick: () => pushProfile(p),
            disabledReason: syncBlocked ?? (isRunning ? "Stop the profile first" : undefined),
          },
          {
            label: "Pull from team",
            onClick: () => pullProfile(p),
            disabledReason: syncBlocked ?? (isRunning ? "Stop the profile first" : undefined),
          },
        ]
      : []),
    { sep: true, label: "", onClick: () => {} },
    // Only meaningful while the engine is up and exposing a debugger port.
    {
      label: "Copy CDP HTTP URL",
      onClick: () => { void copyCdpHttpUrl(p.id); },
      disabledReason: isRunning ? undefined : "Start the profile first",
    },
    {
      label: "Copy DevTools inspect URL",
      onClick: () => { void copyDevToolsInspectUrl(p.id); },
      disabledReason: isRunning ? undefined : "Start the profile first",
    },
    {
      label: "Bring verification tab to front",
      onClick: () => { void bringVerificationToFront(p.id); },
      disabledReason: isRunning ? undefined : "Start the profile first",
    },
    { sep: true, label: "", onClick: () => {} },
    { label: "Export cookies", onClick: () => exportCookies(p) },
    { label: "Import cookies", onClick: () => importCookies(p) },
    { sep: true, label: "", onClick: () => {} },
    {
      label: "Delete",
      onClick: () => remove(p.id),
      danger: true,
      disabledReason: isRunning ? "Stop the profile first" : undefined,
    },
  ];

  return (
    <div
      className={cn(
        "relative border-t border-stroke-soft-200 first:border-t-0",
        isRunning && "row-running",
        isExpanded && "row-expanded",
        p.pinned && "bg-[linear-gradient(90deg,var(--color-primary-alpha-10)_0%,transparent_30%)]",
      )}
      onContextMenu={(e) => onMenu(e, menu())}
      // Buttons keep their own meaning; the expanded editor is text.
      onMouseDown={(e) => {
        const t = e.target as HTMLElement;
        shiftPress.current =
          e.button === 0 &&
          e.shiftKey &&
          !t.closest(".inline-editor") &&
          !t.closest("button, a");
        if (!shiftPress.current) return;
        // Stops the text selection a shift-drag would otherwise begin, and the
        // label activation that would reach the checkbox.
        e.preventDefault();
        selectRangeTo(p.id);
      }}
      // The press already did the work; the clicks it produces must not redo it.
      onClick={(e) => { if (shiftPress.current) e.preventDefault(); }}
      draggable={!isExpanded}
      onDragStart={(e) => {
        e.dataTransfer.effectAllowed = "move";
        // Set BOTH a custom MIME (so non-folder drop zones can ignore it) and
        // text/plain (Firefox refuses to start a drag without text/plain, and
        // some Chromium variants hide custom MIME values from
        // `dataTransfer.types` during dragover for cross-origin reasons).
        e.dataTransfer.setData("application/x-shardx-profile", p.id);
        e.dataTransfer.setData("text/plain", p.id);
        // Replace the default full-row ghost (it obscures the folder tabs and
        // stops the drop event firing on them) with a tiny chip near the cursor.
        const chip = document.createElement("div");
        chip.className = "drag-chip";
        chip.textContent = p.name || p.id.slice(0, 8);
        document.body.appendChild(chip);
        e.dataTransfer.setDragImage(chip, 12, 12);
        // The ghost is rasterised synchronously, so removing it next tick is safe.
        setTimeout(() => chip.remove(), 0);
      }}
    >
      <div className={cn("t-cols transition-colors hover:bg-bg-weak-50", isExpanded && "bg-bg-weak-50")}>
        <div className="flex items-center justify-center pl-1">
          <span
            className={cn(
              "inline-block h-[7px] w-[7px] rotate-45 transition-[background,box-shadow] duration-150",
              isRunning ? "shard-on" : "shard-off bg-bg-sub-300",
            )}
          />
        </div>
        <div>
          <Checkbox
            aria-label={`Select profile ${p.name}`}
            checked={isSel}
            onChange={() => { if (!shiftPress.current) toggleSelect(p.id); }}
          />
        </div>
        <div className="cell-name min-w-0 cursor-pointer overflow-hidden" title={p.name} onClick={() => { if (!shiftPress.current) expand(p.id); }}>
          <div className="overflow-hidden text-ellipsis whitespace-nowrap text-label-xs text-text-strong-950">
            {p.pinned && (
              <span className="mr-1.5 inline-flex items-center align-middle text-primary-base" title={t("common.pinned")}>
                <PinIconApp className="size-3" />
              </span>
            )}
            <span className="name-main">{p.name}</span>
          </div>
          {launchError && (
            <div className="launch-error-inline mt-0.5 overflow-hidden text-ellipsis whitespace-nowrap text-paragraph-xs text-error-base" title={launchError}>
              {launchError}
            </div>
          )}
          <div className="mono mt-0.5 overflow-hidden text-ellipsis whitespace-nowrap text-[10.5px] text-text-disabled-300">{p.id.slice(0, 8)}</div>
        </div>
        <div>
          <Badge color={isRunning ? "success" : "gray"} variant='filled' size="small" dot>
            {isRunning ? "Running" : "Idle"}
          </Badge>
        </div>
        <div
          className="cursor-pointer transition-colors hover:text-primary-base"
          onClick={() => { if (!shiftPress.current) setQuickEdit({ kind: "proxy", profile: p }); }}
          title={t("profileTable.changeProxy")}
        >
          {proxy ? (
            <div className="flex min-w-0 items-center gap-2 overflow-hidden">
              <Badge
                size="small"
                variant="filled"
                color={proxy.kind === "socks5" ? "primary" : proxy.kind === "https" ? "success" : "information"}
              >
                {proxy.kind.toUpperCase()}
              </Badge>
              <span className="flex min-w-0 items-center gap-1.5 overflow-hidden">
                {proxy.country && (
                  <>
                    <CountryFlag cc={proxy.country} />
                    <span className="inline-block rounded-4 bg-bg-weak-50 px-1.5 py-0.5 text-[10.5px] font-bold tracking-[0.5px] text-text-sub-600">{proxy.country}</span>
                  </>
                )}
                <span className="mono small text-text-sub-600">{proxy.host}:{proxy.port}</span>
              </span>
            </div>
          ) : <span className="text-paragraph-xs text-text-soft-400">— direct —</span>}
        </div>
        <div
          className="cell-notes min-w-0 cursor-pointer overflow-hidden text-ellipsis whitespace-nowrap text-paragraph-xs text-text-sub-600 transition-colors hover:text-primary-base"
          title={p.notes || "Click to edit notes"}
          onClick={() => { if (!shiftPress.current) setQuickEdit({ kind: "notes", profile: p }); }}
        >
          {p.notes || <span className="text-text-soft-400">—</span>}
        </div>
        <div className="cell-time">
          <span className={cn("text-paragraph-xs", isRunning ? "text-text-strong-950" : "text-text-soft-400")}>
            {(() => {
              const live = isRunning && runningSince ? Date.now() - runningSince : 0;
              const total = p.total_runtime_ms + live;
              return total > 0 ? fmtUptime(total) : "—";
            })()}
          </span>
        </div>
        <div className="cell-lastrun"><span className="text-paragraph-xs text-text-soft-400">{p.last_launched_at ? fmtTs(p.last_launched_at) : "never"}</span></div>
        <ProfileRowActions
          profile={p}
          onMore={(e) => { e.stopPropagation(); onMenu(e, menu()); }}
        />
      </div>
      {isExpanded && <ProfileInlineEditor />}
    </div>
  );
}
