import { useEffect, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Button, cn } from "@proxyshard/shardx-ui-kit";
import Badge from "../../shared/ui/Badge";
import {
  NavBrowsersIcon,
  RouteIcon,
  NavShopIcon,
  NavFingerprintsIcon,
  NavSettingsIcon,
  NavPatchLogIcon,
  NavExtensionsIcon,
  NavAutomationIcon,
  NavBookmarksIcon,
  NavTrashIcon,
  CopyIcon,
  DocsIcon,
  ShardLogo,
} from "../../shared/icons";
import { clip } from "../../shared/lib/clipboard";
import { toast } from "../../shared/model/toast";
import { withUtm } from "../../shared/lib/utils";
import type { Section } from "../../shared/types";
import { useNav } from "../../shared/model/navigation";
import { DownloadMcp } from "../../features/DownloadMcp";
import { ThemeSwitch } from "../../features/ThemeSwitch";
import { UpdaterPill } from "../UpdaterPill";
import { useT } from "../../shared/i18n";

export function Sidebar() {
  const t = useT();
  const section = useNav((s) => s.section);
  const setSection = useNav((s) => s.setSection);

  const sections: { label: string; items: { id: Section; label: string; svg: ReactNode }[] }[] = [
    {
      label: "Workspace",
      items: [
        { id: "browsers", label: "Browsers", svg: <NavBrowsersIcon className="size-[18px]" /> },
        { id: "proxies", label: "Proxies", svg: <RouteIcon className="size-[18px]" /> },
        { id: "proxyshard", label: "ProxyShard", svg: <NavShopIcon className="size-[18px]" /> },
        { id: "automation", label: "Automation", svg: <NavAutomationIcon className="size-[18px]" /> },
      ],
    },
    {
      label: "Library",
      items: [
        { id: "fingerprints", label: "Fingerprints", svg: <NavFingerprintsIcon className="size-[18px]" /> },
        { id: "extensions", label: "Extensions", svg: <NavExtensionsIcon className="size-[18px]" /> },
        { id: "bookmarks", label: "Bookmarks", svg: <NavBookmarksIcon className="size-[18px]" /> },
      ],
    },
    {
      label: "System",
      items: [
        { id: "trash", label: "Trash", svg: <NavTrashIcon className="size-[18px]" /> },
        { id: "patchlog", label: "Patch log", svg: <NavPatchLogIcon className="size-[18px]" /> },
        { id: "settings", label: "Settings", svg: <NavSettingsIcon className="size-[18px]" /> },
      ],
    },
  ];

  // Automation/MCP quick widget (fills the sidebar's lower space).
  const [autoUrl, setAutoUrl] = useState("");
  useEffect(() => {
    invoke<{ base_url: string; enabled: boolean }>("api_info")
      .then((i) => setAutoUrl(i.enabled ? i.base_url : ""))
      .catch(() => {});
  }, []);

  return (
    <aside className="flex flex-col border-r border-stroke-soft-200 bg-bg-white-0 py-2.5 pl-5 pr-2.5">
      <div className="flex items-center gap-2.5 pb-3.5 pt-1.5 text-label-sm font-bold tracking-tight text-text-strong-950">
        <span className="text-primary-base"><ShardLogo /></span>
        <span>ShardX</span>
      </div>
      <nav>
        {sections.map((sec) => (
          <div key={sec.label} className="mt-3.5 flex flex-col gap-1.5 first:mt-1">
            <div className="px-2 pb-1.5 text-subheading-2xs text-text-soft-400">{sec.label}</div>
            {sec.items.map((it) => (
              <button
                key={it.id}
                className={cn(
                  "relative flex cursor-pointer items-center gap-2.5 rounded-lg border-0 px-2.5 py-[7px] text-left text-label-xs transition-colors",
                  section === it.id
                    ? "bg-primary-alpha-10 text-primary-base"
                    : "bg-transparent text-text-sub-600 hover:bg-bg-weak-50 hover:text-text-strong-950",
                )}
                onClick={() => setSection(it.id)}
              >
                <span
                  className={cn(
                    "grid w-5 place-items-center",
                    section === it.id ? "text-primary-base" : "text-icon-soft-400",
                  )}
                >
                  {it.svg}
                </span>
                <span>{it.label}</span>
              </button>
            ))}
          </div>
        ))}
      </nav>
      <div className="mt-auto border-t border-stroke-soft-200 pt-2">
        <div className="mb-2.5 flex flex-col gap-[7px] rounded-xl bg-bg-weak-50 p-2.5 ring-1 ring-inset ring-stroke-soft-200">
          <div className="flex items-center justify-between">
            <span className="text-subheading-2xs text-text-soft-400">Automation API</span>
            {autoUrl && <Badge color="success" variant="filled" size="small" dot>on</Badge>}
          </div>
          {autoUrl ? (
            <button
              className="flex w-full cursor-pointer items-center justify-between gap-1.5 rounded-lg bg-bg-white-0 px-2 py-[5px] text-paragraph-xs text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200 transition-colors hover:text-text-strong-950 hover:ring-stroke-sub-300"
              title={t("sidebar.copyApiBaseUrl")}
              onClick={() => { clip.write(autoUrl); toast.ok("Copied API URL"); }}
            >
              <span className="mono truncate">{autoUrl.replace(/^https?:\/\//, "")}</span>
              <CopyIcon className="size-3.5 shrink-0" />
            </button>
          ) : (
            <div className="text-paragraph-xs text-text-soft-400">API off — enable in Settings</div>
          )}
          <DownloadMcp />
          <Button
            variant="neutral"
            mode="ghost"
            size="xsmall"
            className="w-full"
            leftIcon={<DocsIcon className="size-4" />}
            onClick={() => {
              openUrl(withUtm("https://docs.proxyshard.com/eng/shardx-launcher-api/binding-and-lifecycle?fallback=true")).catch(() => {});
            }}
            title={t("sidebar.openTheFullAutomationApiReferenceOnD")}
          >
            {t("sidebar.documentation")}
          </Button>
        </div>
        <ThemeSwitch />
        <UpdaterPill />
      </div>
    </aside>
  );
}
