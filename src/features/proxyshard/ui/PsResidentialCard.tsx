import { useEffect, useState } from "react";
import { Button, ProgressBar, SegmentControl } from "@proxyshard/shardx-ui-kit";
import { AddIcon } from "../../../shared/icons";
import { toast } from "../../../shared/model/toast";
import { fmtGB, safeUiError } from "../../../shared/lib/utils";
import type { PsOrder, ResiType } from "../../../entities/proxyshard";
import { psProfileTraffic, psOrders, psRenew } from "../../../entities/proxyshard";
import { PsTopupModal } from "./PsTopupModal";
import { PsResiGenerator } from "./PsResiGenerator";
import { useT } from "../../../shared/i18n";

function TrafficStat({ value, label }: { value: string; label: string }) {
  return (
    <div className="flex flex-col gap-[3px] rounded-md bg-bg-weak-50 px-3 py-2.5 ring-1 ring-inset ring-stroke-soft-200">
      <span className="text-title-h6 text-text-strong-950">{value}</span>
      <span className="text-subheading-2xs text-text-soft-400">{label}</span>
    </div>
  );
}

/// Residential card: tier toggle (Standard / Premium / Unmetered), metered
/// traffic for Standard/Premium, in-place top-up, and the relay proxy
/// generator. Unmetered is a flat plan, so it skips the GB meter.
export function PsResidentialCard() {
  const t = useT();
  const [type, setType] = useState<ResiType>("standart");
  const [data, setData] = useState<{ data: number; data_remain: number; data_spent: number } | null>(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState("");
  const [orders, setOrders] = useState<PsOrder[]>([]);
  const [topup, setTopup] = useState<PsOrder | null>(null);
  const [genOpen, setGenOpen] = useState(false);
  const [renewing, setRenewing] = useState(false);

  const loadTraffic = async (t: ResiType) => {
    setData(null);
    setErr("");
    if (t === "unmetered") return; // flat plan — no GB meter
    setLoading(true);
    try {
      const r = await psProfileTraffic(t);
      setData({ data: r.data ?? 0, data_remain: r.data_remain ?? 0, data_spent: r.data_spent ?? 0 });
    } catch (e) { setErr(String(e)); }
    finally { setLoading(false); }
  };
  useEffect(() => { loadTraffic(type); }, [type]);
  // Orders back the top-up / renew targets (need an order id).
  const loadOrders = () =>
    psOrders({ status: "all", limit: 100 })
      .then((r) => setOrders(r.orders ?? []))
      .catch(() => {});
  useEffect(() => { loadOrders(); }, []);

  const re = { standart: /standart\s+residential/i, premium: /premium\s+residential/i, unmetered: /unmetered\s+residential/i }[type];
  const order = orders.find((o) => re.test(o.product_name)) ?? null;

  const renew = async () => {
    if (!order) return;
    setRenewing(true);
    try {
      await psRenew(order.order_id);
      toast.ok(t("ps.renewedOrder", { id: order.order_id }));
      loadOrders();
    } catch (e) { toast.err(safeUiError(e)); }
    finally { setRenewing(false); }
  };
  const pct = data && data.data > 0 ? Math.min(100, Math.round((data.data_spent / data.data) * 100)) : 0;

  return (
    <div className="mb-3.5 rounded-lg bg-bg-white-0 p-[18px] shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
      <div className="mb-2.5 flex items-center justify-between gap-3">
        <h3 className="m-0 text-label-sm text-text-strong-950">{t("ps.residential")}</h3>
        <SegmentControl
          size="small"
          value={type}
          items={[
            { value: "standart", label: t("ps.standard") },
            { value: "premium", label: t("ps.premium") },
            { value: "unmetered", label: t("ps.unmetered") },
          ]}
          onChange={(v) => setType(v as ResiType)}
        />
      </div>

      {type !== "unmetered" ? (
        <>
          {loading && <p className="m-0 text-paragraph-xs text-text-soft-400">Loading…</p>}
          {err && !loading && <p className="m-0 text-paragraph-xs text-text-soft-400">{err}</p>}
          {data && !loading && (
            <>
              <div className="my-1 mb-3 grid grid-cols-3 gap-2.5">
                <TrafficStat value={fmtGB(data.data_remain)} label={t("ps.remaining")} />
                <TrafficStat value={fmtGB(data.data_spent)} label={t("ps.used")} />
                <TrafficStat value={fmtGB(data.data)} label={t("ps.total")} />
              </div>
              <ProgressBar value={pct} color={pct > 90 ? "error" : pct > 70 ? "warning" : "primary"} />
              <p className="m-0 mt-1 text-paragraph-xs text-text-soft-400">{pct}% used.</p>
            </>
          )}
        </>
      ) : (
        <p className="m-0 text-paragraph-xs text-text-soft-400">
          Unlimited plan{order?.expires_at ? t("ps.expiresDate", { date: order.expires_at.slice(0, 10) }) : ""}.
        </p>
      )}

      <div className="mt-3.5 flex items-center gap-3">
        {type !== "unmetered" ? (
          <Button
            variant="neutral"
            mode="stroke"
            size="small"
            leftIcon={<AddIcon className="size-4" />}
            disabled={!order}
            title={order ? undefined : t("ps.noResidentialOrderFoundForThisTier")}
            onClick={() => order && setTopup(order)}
          >
            {t("ps.addTraffic")}
          </Button>
        ) : (
          <Button
            variant="neutral"
            mode="stroke"
            size="small"
            disabled={!order || renewing}
            isLoading={renewing}
            title={order ? undefined : t("ps.noUnmeteredOrderFound")}
            onClick={renew}
          >
            {renewing ? "Renewing…" : t("ps.renew")}
          </Button>
        )}
        <Button variant="primary" mode="filled" size="small" onClick={() => setGenOpen(true)}>
          {t("ps.generateProxies")}
        </Button>
      </div>

      {topup && <PsTopupModal order={topup} onClose={() => setTopup(null)} onDone={() => { setTopup(null); loadTraffic(type); }} />}
      {genOpen && <PsResiGenerator type={type} onClose={() => setGenOpen(false)} />}
    </div>
  );
}
