import { useEffect, useMemo, useState } from "react";
import { Button, Checkbox, Pagination } from "@proxyshard/shardx-ui-kit";
import { ShardLogo } from "../../shared/icons";
import { useContextMenu } from "../../shared/hooks/useContextMenu";
import {
  useProfile,
  useVisibleProfiles,
  useProxyMap,
} from "../../entities/profile";
import {
  ProfileInlineEditor,
  FromTemplateButton,
  NewProfileButton,
} from "../../features/manage-profiles";
import { ProfileRow } from "./ProfileRow";
import { useT } from "../../shared/i18n";

const PAGE_SIZE = 20;

export function ProfileTable() {
  const t = useT();
  const selected = useProfile((s) => s.selected);
  const selectProfiles = useProfile((s) => s.selectProfiles);
  const expanded = useProfile((s) => s.expanded);
  const folder = useProfile((s) => s.folder);
  const search = useProfile((s) => s.search);
  const setSearch = useProfile((s) => s.setSearch);
  const running = useProfile((s) => s.running);

  const visible = useVisibleProfiles();
  const proxyMap = useProxyMap();
  const ctx = useContextMenu();

  // Pagination of the (filtered) profile list.
  const [page, setPage] = useState(1);
  const pageCount = Math.max(1, Math.ceil(visible.length / PAGE_SIZE));
  // Reset to page 1 when the filter changes; clamp if the list shrank.
  useEffect(() => { setPage(1); }, [folder, search]);
  useEffect(() => { if (page > pageCount) setPage(pageCount); }, [pageCount, page]);
  const paged = useMemo(
    () => visible.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE),
    [visible, page],
  );

  // Re-render every second so the uptime label ticks without re-fetching the
  // process list (which polls every 2s in the store).
  const [, setUptimeTick] = useState(0);
  useEffect(() => {
    if (Object.keys(running).length === 0) return;
    const h = setInterval(() => setUptimeTick((t) => t + 1), 1000);
    return () => clearInterval(h);
  }, [running]);

  // Scroll the expanded editor into view after the expand animation.
  useEffect(() => {
    if (!expanded || expanded === "__new__") return;
    const t = setTimeout(() => {
      const el = document.querySelector<HTMLElement>(".row-wrap.row-expanded .inline-editor");
      el?.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 60);
    return () => clearTimeout(t);
  }, [expanded]);

  const allPageSelected = paged.length > 0 && paged.every((p) => selected.has(p.id));
  const anyPageSelected = paged.some((p) => selected.has(p.id));

  return (
    <>
      <div className="overflow-x-auto overflow-y-hidden rounded-lg bg-bg-white-0 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
        <div className="t-cols border-b border-stroke-soft-200 bg-bg-weak-50 text-subheading-2xs text-text-soft-400">
          <div></div>
          <div>
            <Checkbox
              aria-label={t("profileTable.selectAllProfilesOnThisPage")}
              title={t("profileTable.selectAllOnThisPage")}
              // Header checkbox toggles only visible page rows; other pages preserved.
              checked={allPageSelected}
              indeterminate={anyPageSelected && !allPageSelected}
              onChange={(e) => selectProfiles(e.target.checked, paged)}
            />
          </div>
          <div>{t("profileTable.name")}</div>
          <div>{t("profileTable.status")}</div>
          <div>{t("profileTable.proxy")}</div>
          <div className="head-notes">{t("profileTable.notes")}</div>
          <div className="head-time">{t("profileTable.time")}</div>
          <div className="head-lastrun">{t("profileTable.lastRun")}</div>
          <div></div>
        </div>
        {expanded === "__new__" && (
          <div className="row-expanded row-new relative border-t border-stroke-soft-200 first:border-t-0">
            <ProfileInlineEditor />
          </div>
        )}
        {paged.map((p) => (
          <ProfileRow
            key={p.id}
            profile={p}
            proxy={p.proxy_id ? proxyMap[p.proxy_id] ?? null : null}
            onMenu={ctx.open}
          />
        ))}
        {visible.length === 0 && !expanded && (
          <div className="flex flex-col items-center gap-2.5 px-6 py-14 text-center">
            <div className="grid size-14 place-items-center rounded-[14px] bg-primary-alpha-10 text-primary-base ring-1 ring-inset ring-primary-alpha-24">
              <ShardLogo />
            </div>
            {search ? (
              <>
                <h3 className="m-0 text-label-sm text-text-strong-950">{t("profileTable.noMatchingProfiles")}</h3>
                <p className="m-0 max-w-[420px] text-paragraph-sm text-text-sub-600">
                  Nothing matches “{search}”.
                </p>
                <div className="mt-2 flex gap-2">
                  <Button variant="neutral" mode="stroke" size="xsmall" onClick={() => setSearch("")}>
                    {t("profileTable.clearSearch")}
                  </Button>
                </div>
              </>
            ) : folder && folder !== "all" ? (
              <>
                <h3 className="m-0 text-label-sm text-text-strong-950">{t("profileTable.folderIsEmpty")}</h3>
                <p className="m-0 max-w-[420px] text-paragraph-sm text-text-sub-600">
                  “{folder}” has no profiles. Move one in, or create one here.
                </p>
                <div className="mt-2 flex gap-2">
                  <FromTemplateButton />
                  <NewProfileButton />
                </div>
              </>
            ) : (
              <>
                <h3 className="m-0 text-label-sm text-text-strong-950">{t("profileTable.noProfilesYet")}</h3>
                <p className="m-0 max-w-[420px] text-paragraph-sm text-text-sub-600">
                  {t("profileTable.pickAFingerprintTemplateToStartFromA")}
                </p>
                <div className="mt-2 flex gap-2">
                  <FromTemplateButton />
                  <NewProfileButton />
                </div>
              </>
            )}
          </div>
        )}
      </div>
      {pageCount > 1 && (
        <div className="flex items-center justify-center py-3 pb-1">
          <Pagination
            page={page}
            totalPages={pageCount}
            asLinks={false}
            onPageChange={setPage}
            infoLabel={(p, total) => `Page ${p} of ${total} · ${visible.length} profiles`}
          />
        </div>
      )}
      {ctx.node}
    </>
  );
}
