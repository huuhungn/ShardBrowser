import { useEffect } from "react";
import { Button } from "@proxyshard/shardx-ui-kit";
import { Topbar } from "../../shared/ui/Topbar";
import { useStoreChanged } from "../../shared/hooks/useStoreChanged";
import { useProfile } from "../../entities/profile";
import { BrowsersMetrics } from "../../widgets/ProfileTable/BrowsersMetrics";
import { FolderTabs } from "../../widgets/ProfileTable/FolderTabs";
import { ProfileToolbar } from "../../widgets/ProfileTable/ProfileToolbar";
import { ProfileTable } from "../../widgets/ProfileTable/ProfileTable";
import {
  ProfileTemplatePicker,
  ProfileFolderModal,
  ProfileQuickEdit,
} from "../../features/manage-profiles";
import { useT } from "../../shared/i18n";

export function BrowsersPage() {
  const init = useProfile((s) => s.init);
  const reload = useProfile((s) => s.reload);
  const startProcessPolling = useProfile((s) => s.startProcessPolling);
  const search = useProfile((s) => s.search);
  const setSearch = useProfile((s) => s.setSearch);
  const status = useProfile((s) => s.status);
  const error = useProfile((s) => s.error);

  const t = useT();

  useEffect(() => { init(); }, [init]);
  // Poll real child-process status (anchors the uptime clock, refreshes totals).
  useEffect(() => startProcessPolling(), [startProcessPolling]);
  // Pick up profiles/proxies created via the automation API or MCP live.
  useStoreChanged(reload);

  return (
    <section className="flex flex-col">
      <Topbar crumbs={[t("nav.workspace"), t("browsers.title")]} search={search} onSearch={setSearch} />

      <BrowsersMetrics />

      <div className="mb-3.5 flex items-end justify-between gap-4">
        <div className="flex min-w-0 flex-1 flex-col gap-3.5">
          <h1 className="m-0 text-title-h5 text-text-strong-950">{t("browsers.title")}</h1>
          <FolderTabs />
        </div>
        <ProfileToolbar />
      </div>

      {status === "loading" && (
        <div role="status" className="px-6 py-14 text-center text-paragraph-sm text-text-sub-600">
          {t("browsers.loading")}
        </div>
      )}

      {status === "error" && (
        <div role="alert" className="flex flex-col items-center gap-2.5 px-6 py-14 text-center">
          <h3 className="m-0 text-label-sm text-text-strong-950">{t("browsers.loadFailed")}</h3>
          <p className="m-0 max-w-[420px] text-paragraph-sm text-text-sub-600">{error}</p>
          <Button variant="neutral" mode="stroke" size="xsmall" onClick={() => { void init(); }}>
            {t("common.retry")}
          </Button>
        </div>
      )}

      {status === "ready" && <ProfileTable />}

      <ProfileTemplatePicker />
      <ProfileFolderModal />
      <ProfileQuickEdit />
    </section>
  );
}
