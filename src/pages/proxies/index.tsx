import { useEffect } from "react";
import { Button } from "@proxyshard/shardx-ui-kit";
import { Topbar } from "../../shared/ui/Topbar";
import { useStoreChanged } from "../../shared/hooks/useStoreChanged";
import { useProxy } from "../../entities/proxy";
import { storeBus } from "../../shared/lib/storeBus";
import { ProxyEditor, ProxyBulkImporter, ProxyInfoPopover, ProxyDistributeModal } from "../../features/manage-proxies";
import { ProxyTable } from "../../widgets/ProxyTable/ProxyTable";
import { ProxyToolbar } from "../../widgets/ProxyTable/ProxyToolbar";
import { useT } from "../../shared/i18n";

export function ProxiesPage() {
  const init = useProxy((s) => s.init);
  const reload = useProxy((s) => s.reload);
  const search = useProxy((s) => s.search);
  const setSearch = useProxy((s) => s.setSearch);
  const editing = useProxy((s) => s.editing);
  const setEditing = useProxy((s) => s.setEditing);
  const bulkOpen = useProxy((s) => s.bulkOpen);
  const setBulkOpen = useProxy((s) => s.setBulkOpen);
  const infoFor = useProxy((s) => s.infoFor);
  const setInfoFor = useProxy((s) => s.setInfoFor);
  const snapshots = useProxy((s) => s.snapshots);
  const distributeOpen = useProxy((s) => s.distributeOpen);
  const status = useProxy((s) => s.status);
  const error = useProxy((s) => s.error);
  const setDistributeOpen = useProxy((s) => s.setDistributeOpen);

  const t = useT();

  useEffect(() => { init(); }, [init]);
  // Pick up proxies/profiles added via the automation API or MCP live.
  useStoreChanged(reload);

  return (
    <section className="flex flex-col">
      <Topbar crumbs={[t("nav.workspace"), t("proxies.title")]} search={search} onSearch={setSearch} />
      <div className="mb-3.5 flex items-end justify-between gap-4">
        <h1 className="m-0 text-title-h5 text-text-strong-950">{t("proxies.title")}</h1>
        <ProxyToolbar />
      </div>
      {status === "loading" && (
        <div role="status" className="py-8 text-center text-paragraph-sm text-text-sub-600">
          {t("proxies.loading")}
        </div>
      )}
      {status === "error" && (
        <div role="alert" className="flex flex-col items-center gap-2 py-8 text-center">
          <p className="m-0 text-paragraph-sm text-text-strong-950">{t("proxies.loadFailed")}</p>
          {error && <p className="m-0 text-paragraph-xs text-text-sub-600">{error}</p>}
          <Button size="xsmall" onClick={() => { void init(); }}>{t("common.retry")}</Button>
        </div>
      )}
      {status === "ready" && <ProxyTable />}
      {editing && (
        <ProxyEditor
          initial={editing}
          onClose={() => { setEditing(null); reload(); }}
          onSaved={() => storeBus.emit("proxies")}
        />
      )}
      {bulkOpen && (
        <ProxyBulkImporter
          onClose={() => { setBulkOpen(false); reload(); storeBus.emit("proxies"); }}
        />
      )}
      {distributeOpen && <ProxyDistributeModal onClose={() => setDistributeOpen(false)} />}
      {infoFor && (
        <ProxyInfoPopover
          proxy={infoFor.proxy}
          anchor={infoFor.anchor}
          latest={snapshots[infoFor.proxy.id]}
          onClose={() => setInfoFor(null)}
        />
      )}
    </section>
  );
}
