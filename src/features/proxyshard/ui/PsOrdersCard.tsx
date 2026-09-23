import { useEffect, useState } from "react";
import { Button, Select } from "@proxyshard/shardx-ui-kit";
import { DownloadIcon, EditIcon, RefreshIcon } from "../../../shared/icons";
import { toast } from "../../../shared/model/toast";
import { isDcIsp } from "../../../shared/lib/utils";
import type { PsOrder } from "../../../entities/proxyshard";
import { psOrders, psRenew, usePsAccount } from "../../../entities/proxyshard";
import { PsImportModal } from "./PsImportModal";
import { PsTagModal } from "./PsTagModal";
import { useT } from "../../../shared/i18n";

/// Orders list: add DC/ISP proxies to the local list, top up residential
/// traffic, edit the tag, or renew an on-hold order. Mobile proxies are
/// hidden (they aren't manageable from here), and the list is paginated.
const PS_ORDERS_PAGE = 10;

export function PsOrdersCard() {
  const t = useT();
  // Refresh the account wallet/orders metrics after a renew.
  const onChanged = usePsAccount((s) => s.refreshMe);
  const [status, setStatus] = useState("active");
  const [orders, setOrders] = useState<PsOrder[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState<Record<number, boolean>>({});
  const [offset, setOffset] = useState(0);
  const [hasNext, setHasNext] = useState(false);
  const [importing, setImporting] = useState<PsOrder | null>(null);
  const [tagging, setTagging] = useState<PsOrder | null>(null);

  const load = async (off = offset) => {
    setLoading(true);
    try {
      const r = await psOrders({ status, offset: off, limit: PS_ORDERS_PAGE });
      setOrders(r.orders ?? []);
      // `next` is a page URI when more results exist (nullable).
      setHasNext(!!r.next);
    } catch (e) { toast.err(String(e)); }
    finally { setLoading(false); }
  };
  // Reset to the first page whenever the status filter changes.
  useEffect(() => { setOffset(0); load(0); }, [status]); // eslint-disable-line react-hooks/exhaustive-deps

  const setB = (id: number, v: boolean) => setBusy((s) => ({ ...s, [id]: v }));

  const renew = async (o: PsOrder) => {
    setB(o.order_id, true);
    try {
      await psRenew(o.order_id);
      toast.ok(t("ps.renewedOrder", { id: o.order_id }));
      load();
      onChanged();
    } catch (e) { toast.err(String(e)); }
    finally { setB(o.order_id, false); }
  };

  const go = (next: boolean) => {
    const off = Math.max(0, offset + (next ? PS_ORDERS_PAGE : -PS_ORDERS_PAGE));
    setOffset(off);
    load(off);
  };

  // Orders here are Datacenter/ISP only — residential is managed in the
  // Residential card, mobile isn't manageable from the launcher.
  const visible = orders.filter((o) => isDcIsp(o.product_name));

  return (
    <div className="mb-3.5 rounded-lg bg-bg-white-0 p-[18px] shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
      <div className="mb-2.5 flex items-center justify-between gap-3">
        <h3 className="m-0 text-label-sm text-text-strong-950">{t("ps.orders")}</h3>
        <div className="flex items-center gap-2">
          <div className="w-[130px]">
            <Select
              size="small"
              value={status}
              onChange={setStatus}
              options={[
                { value: "active", label: t("ps.active") },
                { value: "on-hold", label: t("ps.onHold") },
                { value: "cancelled", label: t("ps.cancelled") },
                { value: "all", label: t("ps.all") },
              ]}
            />
          </div>
          <Button variant="neutral" mode="stroke" size="xsmall" onlyIcon onClick={() => load()} title={t("ps.refresh")}>
            <RefreshIcon className="size-4" />
          </Button>
        </div>
      </div>
      {loading && <p className="m-0 text-paragraph-xs text-text-soft-400">Loading…</p>}
      {!loading && visible.length === 0 && <p className="m-0 text-paragraph-xs text-text-soft-400">{t("ps.noOrdersForThisFilter")}</p>}
      {!loading && visible.length > 0 && (
        <div className="mt-1 overflow-hidden rounded-10 ring-1 ring-inset ring-stroke-soft-200">
          {visible.map((o) => (
            <div key={o.order_id} className="flex items-center justify-between gap-3 border-b border-stroke-soft-200 px-4 py-3 last:border-b-0">
              <div className="flex min-w-0 flex-col gap-0.5">
                <span className="text-label-xs text-text-strong-950">{o.product_name}</span>
                <span className="text-paragraph-xs text-text-soft-400">
                  #{o.order_id} · {o.cycle_name}
                  {o.tag && o.tag !== "none" ? ` · ${o.tag}` : ""}
                  {o.expires_at ? t("ps.untilDate", { date: o.expires_at.slice(0, 10) }) : ""}
                </span>
              </div>
              <div className="flex shrink-0 justify-end gap-1.5">
                <Button
                  variant="neutral"
                  mode="stroke"
                  size="2xsmall"
                  leftIcon={<DownloadIcon className="size-3.5" />}
                  onClick={() => setImporting(o)}
                  title={t("ps.pickWhichProxiesToAddToYourList")}
                >
                  {t("ps.addToProxies")}
                </Button>
                <Button variant="neutral" mode="stroke" size="2xsmall" onlyIcon onClick={() => setTagging(o)} title={t("ps.editTag")}>
                  <EditIcon className="size-3.5" />
                </Button>
                {status === "on-hold" && (
                  <Button variant="neutral" mode="stroke" size="2xsmall" disabled={busy[o.order_id]} onClick={() => renew(o)}>
                    {t("ps.renew")}
                  </Button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
      {!loading && (offset > 0 || hasNext) && (
        <div className="mt-3 flex items-center justify-center gap-3.5">
          <Button variant="neutral" mode="stroke" size="2xsmall" disabled={offset <= 0} onClick={() => go(false)}>‹ Prev</Button>
          <span className="text-paragraph-xs text-text-soft-400">Page {Math.floor(offset / PS_ORDERS_PAGE) + 1}</span>
          <Button variant="neutral" mode="stroke" size="2xsmall" disabled={!hasNext} onClick={() => go(true)}>Next ›</Button>
        </div>
      )}
      {importing && (
        <PsImportModal order={importing} onClose={() => setImporting(null)} />
      )}
      {tagging && (
        <PsTagModal order={tagging} onClose={() => setTagging(null)} onDone={() => { setTagging(null); load(); }} />
      )}
    </div>
  );
}
