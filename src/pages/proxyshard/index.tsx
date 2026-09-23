import { useEffect } from "react";
import { Topbar } from "../../shared/ui/Topbar";
import { usePsAccount } from "../../entities/proxyshard";
import { PsApiKeyCard } from "../../features/proxyshard";
import { PsAccountMetrics } from "../../widgets/ProxyShard/PsAccountMetrics";
import { PsToolbar } from "../../widgets/ProxyShard/PsToolbar";
import { PsManagementPanels } from "../../widgets/ProxyShard/PsManagementPanels";
import { useT } from "../../shared/i18n";

export function ProxyShardPage() {
  const t = useT();
  const init = usePsAccount((s) => s.init);
  useEffect(() => { init(); }, [init]);

  return (
    <section className="ps-page flex flex-col">
      <Topbar crumbs={[t("nav.workspace"), "ProxyShard"]} />

      <PsAccountMetrics />

      <div className="mb-3.5 flex items-end justify-between gap-4">
        <h1 className="m-0 text-title-h5 text-text-strong-950">ProxyShard</h1>
        <PsToolbar />
      </div>

      {/* API key — kept first so it's always on view. */}
      <PsApiKeyCard />

      <PsManagementPanels />
    </section>
  );
}
