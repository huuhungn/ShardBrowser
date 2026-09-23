import { useEffect, useMemo, useState } from "react";
import { Button, Checkbox, Pagination } from "@proxyshard/shardx-ui-kit";
import { RouteIcon } from "../../shared/icons";
import { useContextMenu } from "../../shared/hooks/useContextMenu";
import { useProxy, useFilteredProxies, useProfileCountByProxy } from "../../entities/proxy";
import { NewProxyButton } from "../../features/manage-proxies";
import { ProxyRow } from "./ProxyRow";
import { useT } from "../../shared/i18n";

const PROXY_PAGE_SIZE = 20;

export function ProxyTable() {
  const t = useT();
  const totalProxies = useProxy((s) => s.proxies.length);
  const selectProxy = useProxy((s) => s.selectProxy);
  const proxySel = useProxy((s) => s.proxySel);
  const search = useProxy((s) => s.search);
  const setSearch = useProxy((s) => s.setSearch);

  const filteredProxies = useFilteredProxies();
  const profileCountByProxy = useProfileCountByProxy();
  const ctx = useContextMenu();

  const [proxyPage, setProxyPage] = useState(1);
  const proxyPageCount = Math.max(1, Math.ceil(filteredProxies.length / PROXY_PAGE_SIZE));
  useEffect(() => {
    if (proxyPage > proxyPageCount) setProxyPage(proxyPageCount);
  }, [proxyPageCount, proxyPage]);
  // Reset to page 1 when the search narrows the list to fewer pages.
  useEffect(() => { setProxyPage(1); }, [search]);
  const pagedProxies = useMemo(
    () => filteredProxies.slice((proxyPage - 1) * PROXY_PAGE_SIZE, proxyPage * PROXY_PAGE_SIZE),
    [filteredProxies, proxyPage],
  );

  const allPageSelected = pagedProxies.length > 0 && pagedProxies.every((p) => proxySel.has(p.id));
  const anyPageSelected = pagedProxies.some((p) => proxySel.has(p.id));

  return (
    <>
      <div className="overflow-x-auto overflow-y-hidden rounded-12 bg-bg-white-0 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
        <div className="p-cols w-full justify-between border-b border-stroke-soft-200 bg-bg-weak-50 text-subheading-2xs text-text-soft-400">
          <div>
            <Checkbox
              title={t("proxyTable.selectAllOnThisPage")}
              checked={allPageSelected}
              indeterminate={anyPageSelected && !allPageSelected}
              onChange={(e) => selectProxy(e.target.checked, pagedProxies)}
            />
          </div>
          <div>{t("proxyTable.name")}</div>
          <div>{t("proxyTable.type")}</div>
          <div>Host:Port</div>
          <div className="head-country">{t("proxyTable.country")}</div>
          <div className="head-profiles">{t("proxyTable.profiles")}</div>
          <div>{t("proxyTable.testResult")}</div>
          <div></div>
        </div>
        {pagedProxies.map((p) => (
          <ProxyRow
            key={p.id}
            proxy={p}
            profileCount={profileCountByProxy[p.id] ?? 0}
            onMenu={ctx.open}
          />
        ))}
        {filteredProxies.length === 0 && (
          <div className="flex flex-col items-center gap-2.5 px-6 py-14 text-center">
            <div className="grid size-14 place-items-center rounded-[14px] bg-primary-alpha-10 text-primary-base ring-1 ring-inset ring-primary-alpha-24">
              <RouteIcon className="size-6" />
            </div>
            {/* A search that hides every proxy is not an empty list: offering
                "add a proxy" there buries the ones the user already has. */}
            {search ? (
              <>
                <h3 className="m-0 text-label-sm text-text-strong-950">{t("proxyTable.noMatchingProxies")}</h3>
                <p className="m-0 max-w-[420px] text-paragraph-sm text-text-sub-600">
                  Nothing matches “{search}”.
                </p>
                <div className="mt-2 flex gap-2">
                  <Button size="xsmall" onClick={() => setSearch("")}>{t("proxyTable.clearSearch")}</Button>
                </div>
              </>
            ) : (
              <>
                <h3 className="m-0 text-label-sm text-text-strong-950">{t("proxyTable.noProxiesYet")}</h3>
                <p className="m-0 max-w-[420px] text-paragraph-sm text-text-sub-600">
                  Add a SOCKS5/HTTP(S) endpoint so profiles can route through it.
                </p>
                <div className="mt-2 flex gap-2">
                  <NewProxyButton />
                </div>
              </>
            )}
          </div>
        )}
      </div>
      {proxyPageCount > 1 && (
        <div className="flex items-center justify-center py-3 pb-1">
          <Pagination
            page={proxyPage}
            totalPages={proxyPageCount}
            asLinks={false}
            onPageChange={setProxyPage}
            infoLabel={(p, total) => `Page ${p} of ${total} · ${totalProxies} proxies`}
          />
        </div>
      )}
      {ctx.node}
    </>
  );
}
