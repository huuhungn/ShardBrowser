import { useEffect, useRef } from "react";
import { cn } from "@proxyshard/shardx-ui-kit";
import { useContextMenu } from "../../shared/hooks/useContextMenu";
import { useProfile, useFolders } from "../../entities/profile";
import { useT } from "../../shared/i18n";

/* UI-kit "line" tab look, hand-rolled because tabs are drop targets too. */
const tabBase =
  "relative -mb-px flex flex-none cursor-pointer items-center gap-1.5 whitespace-nowrap border-0 border-b-2 bg-transparent px-3.5 py-2 text-label-xs transition-colors pointer-events-auto [&>*]:pointer-events-none";
const tabActive = "border-b-primary-base text-text-strong-950";
const tabIdle = "border-b-transparent text-text-sub-600 hover:text-text-strong-950";
const tabDrop = "bg-primary-alpha-10! text-primary-base! outline outline-1 outline-dashed outline-primary-base";
const badge = (active: boolean) =>
  cn(
    "rounded-full px-1.5 py-px text-[10px] font-semibold",
    active ? "bg-primary-alpha-10 text-primary-base" : "bg-bg-weak-50 text-text-sub-600",
  );

const readDragId = (e: React.DragEvent) =>
  e.dataTransfer.getData("application/x-shardx-profile") || e.dataTransfer.getData("text/plain");

export function FolderTabs() {
  const t = useT();
  const profiles = useProfile((s) => s.profiles);
  const folder = useProfile((s) => s.folder);
  const dropTarget = useProfile((s) => s.dropTarget);
  const setFolder = useProfile((s) => s.setFolder);
  const setDropTarget = useProfile((s) => s.setDropTarget);
  const setProfileFolder = useProfile((s) => s.setProfileFolder);
  const setFolderModal = useProfile((s) => s.setFolderModal);
  const deleteFolder = useProfile((s) => s.deleteFolder);
  const folders = useFolders();
  const ctx = useContextMenu();

  // Native non-passive wheel handler turns vertical scroll into horizontal tab scroll.
  const folderTabsRef = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = folderTabsRef.current;
    if (!el) return;
    const onWheel = (e: WheelEvent) => {
      if (el.scrollWidth <= el.clientWidth || e.deltaY === 0) return;
      e.preventDefault();
      el.scrollLeft += e.deltaY;
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  // Fall back to "all" when the active folder tab becomes empty.
  useEffect(() => {
    if (folder !== "all" && !folders.includes(folder)) setFolder("all");
  }, [folders, folder, setFolder]);

  return (
    <div
      className="flex min-w-0 overflow-x-auto border-b border-stroke-soft-200 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
      ref={folderTabsRef}
    >
      <button
        className={cn(tabBase, folder === "all" ? tabActive : tabIdle, dropTarget === "__all__" && tabDrop)}
        onClick={() => setFolder("all")}
        // Unconditional preventDefault on dragover is the *only* way HTML5 marks
        // the element as a valid drop target — the preventDefault itself must
        // fire on every event or `drop` never lands.
        onDragOver={(e) => {
          e.preventDefault();
          e.dataTransfer.dropEffect = "move";
          if (dropTarget !== "__all__") setDropTarget("__all__");
        }}
        onDragLeave={(e) => {
          // Ignore enter-into-child events: relatedTarget will be a descendant
          // of the button, so the drag is still over us.
          if (!e.currentTarget.contains(e.relatedTarget as Node)) setDropTarget(null);
        }}
        onDrop={(e) => {
          e.preventDefault();
          setDropTarget(null);
          const id = readDragId(e);
          if (id) setProfileFolder(id, ""); // "" = unassign folder
        }}
      >
        All<span className={badge(folder === "all")}>{profiles.length}</span>
      </button>
      {folders.map((f) => (
        <button
          key={f}
          className={cn(tabBase, folder === f ? tabActive : tabIdle, dropTarget === f && tabDrop)}
          onClick={() => setFolder(f)}
          title={t("folders.rightClickForFolderActionsDropProfil")}
          onContextMenu={(e) =>
            ctx.open(e, [
              { label: "Delete folder…", onClick: () => deleteFolder(f), danger: true },
            ])
          }
          onDragOver={(e) => {
            e.preventDefault();
            e.dataTransfer.dropEffect = "move";
            if (dropTarget !== f) setDropTarget(f);
          }}
          onDragLeave={(e) => {
            if (!e.currentTarget.contains(e.relatedTarget as Node)) setDropTarget(null);
          }}
          onDrop={(e) => {
            e.preventDefault();
            setDropTarget(null);
            const id = readDragId(e);
            if (id) setProfileFolder(id, f);
          }}
        >
          {f}
          <span className={badge(folder === f)}>
            {profiles.filter((p) => p.folder === f).length}
          </span>
        </button>
      ))}
      <button
        className="flex-none cursor-pointer whitespace-nowrap border-0 bg-transparent px-3 py-2 text-base font-normal leading-none text-text-soft-400 hover:text-primary-base"
        title={t("folders.createANewFolder")}
        onClick={() => setFolderModal({ profileId: null })}
      >
        +
      </button>
      {ctx.node}
    </div>
  );
}
