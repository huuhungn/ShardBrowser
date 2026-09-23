import { useEffect, useMemo, useState } from "react";
import { Button, Checkbox } from "@proxyshard/shardx-ui-kit";
import Badge from "../../../shared/ui/Badge";
import { CSSelect } from "../../../shared/ui/CSSelect";
import { NumField } from "../../../shared/ui/NumField";
import { Field } from "../../../shared/ui/Field";
import { toast } from "../../../shared/model/toast";
import { confirmModal } from "../../../shared/model/confirm";
import { fmtCents, isDcIsp, availCode } from "../../../shared/lib/utils";
import type { PsOrder, PsProduct, PsCalc, PsBuyOption } from "../../../entities/proxyshard";
import { psProducts, psOrders, psAvailableCount, psCalculate, psPurchase, usePsAccount } from "../../../entities/proxyshard";
import { useT } from "../../../shared/i18n";

/// Buy a new order. DC/ISP can be bought repeatedly (quantity + country);
/// residential products can only be owned once, so any already-owned tier is
/// hidden here (top it up from the Residential card instead).
export function PsBuyCard() {
  const t = useT();
  // Refresh the account wallet/orders metrics after a purchase.
  const onPurchased = usePsAccount((s) => s.refreshMe);
  const [options, setOptions] = useState<PsBuyOption[]>([]);
  const [avail, setAvail] = useState<Record<string, number>>({});
  const [productName, setProductName] = useState("");
  const [cycle, setCycle] = useState("");
  const [country, setCountry] = useState("");
  const [quantity, setQuantity] = useState(1);
  const [promo, setPromo] = useState("");
  const [autoRenew, setAutoRenew] = useState(false);
  const [buyP0f, setBuyP0f] = useState(false);
  const [calc, setCalc] = useState<PsCalc | null>(null);
  const [calcing, setCalcing] = useState(false);
  const [buying, setBuying] = useState(false);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const [prodRes, orderRes] = await Promise.all([
          psProducts(),
          psOrders({ status: "all", limit: 100 }),
        ]);
        // Already-owned product names (any status) — used to hide
        // single-purchase residential tiers from the buy list.
        const owned = new Set<string>((orderRes.orders ?? []).map((o: PsOrder) => o.product_name));
        // Collapse the per-location product rows into one option per name,
        // keeping the set of locations (DC/ISP country picker). Drop mobile,
        // and drop residential tiers already owned.
        const byName = new Map<string, PsBuyOption>();
        for (const p of (prodRes.products ?? []) as PsProduct[]) {
          if (/mobile/i.test(p.name)) continue;
          if (!isDcIsp(p.name) && owned.has(p.name)) continue;
          const o = byName.get(p.name) ?? { name: p.name, cycles: p.cycles ?? [], locations: [] };
          if (p.location && !o.locations.includes(p.location)) o.locations.push(p.location);
          byName.set(p.name, o);
        }
        const list = [...byName.values()];
        setOptions(list);
        if (list[0]) {
          setProductName(list[0].name);
          setCycle(list[0].cycles?.[0] ?? "");
          setCountry(isDcIsp(list[0].name) ? (list[0].locations[0] ?? "") : "");
        }
      } catch (e) { toast.err(String(e)); }
      // available-count is best-effort (badge only).
      try {
        const arr = await psAvailableCount();
        const m: Record<string, number> = {};
        for (const a of (arr ?? []) as { country: string; product: string; amount: number }[]) {
          m[`${String(a.product).toLowerCase()}|${String(a.country).toUpperCase()}`] = a.amount;
        }
        setAvail(m);
      } catch { /* ignore */ }
      setReady(true);
    })();
  }, []);

  const product = useMemo(() => options.find((p) => p.name === productName) ?? null, [options, productName]);
  const needLocation = isDcIsp(productName);

  // Reset dependent fields + stale price when the product changes.
  useEffect(() => {
    setCycle(product?.cycles?.[0] ?? "");
    setCountry(product && isDcIsp(product.name) ? (product.locations[0] ?? "") : "");
    setCalc(null);
  }, [productName]); // eslint-disable-line react-hooks/exhaustive-deps

  const availForCountry = needLocation && country ? avail[`${availCode(productName)}|${country.toUpperCase()}`] : undefined;

  const buildBody = () => {
    const body: any = { product: productName };
    if (cycle) body.cycle = cycle;
    if (needLocation && country) body.location = country;
    if (quantity) body.quantity = quantity;
    if (promo.trim()) body.promo_code = promo.trim();
    if (autoRenew) body.auto_renewal = true;
    const addons = p0fAddons();
    if (addons) body.addons = addons;
    return body;
  };

  // p0f slots — one per proxy, only meaningful for DC/ISP. null when off.
  const p0fAddons = () => (needLocation && buyP0f ? [{ addon_key: "p0f_slots", qty: quantity }] : null);

  const fetchCalc = async (): Promise<PsCalc> => {
    const addons = p0fAddons();
    const r = await psCalculate({
      product: productName,
      location: needLocation ? country || null : null,
      cycle: cycle || null,
      quantity,
      promoCode: promo.trim() || null,
      addonsJson: addons ? JSON.stringify(addons) : null,
    });
    return {
      original_price: r.original_price ?? 0,
      final_price: r.final_price ?? 0,
      discount_percent: r.discount_percent ?? 0,
      addons_price: r.addons_price ?? 0,
      total_with_addons: r.total_with_addons,
    };
  };

  const calculate = async () => {
    setCalcing(true);
    setCalc(null);
    try { setCalc(await fetchCalc()); }
    catch (e) { toast.err(String(e)); }
    finally { setCalcing(false); }
  };

  const buy = async () => {
    if (needLocation && !country) { toast.err(t("ps.pickALocationForDatacenterISPProxies")); return; }
    // Auto-calculate when the user hasn't pressed Calculate, so the confirm
    // shows the real total (incl. add-ons) instead of a placeholder.
    let c = calc;
    if (!c) {
      try { c = await fetchCalc(); setCalc(c); } catch { /* show placeholder below */ }
    }
    const price = c ? fmtCents(c.total_with_addons ?? c.final_price) : t("ps.thisOrder");
    const ok = await confirmModal({
      title: t("ps.confirmPurchase"),
      message: t("ps.buyAsk", {
        quantity,
        product: productName,
        cycle: cycle ? ` (${cycle})` : "",
        price,
      }),
      buttons: [
        { label: t("common.cancel"), value: false },
        { label: t("ps.buy"), value: true, primary: true },
      ],
    });
    if (ok !== true) return;
    setBuying(true);
    try {
      const r = await psPurchase(buildBody());
      toast.ok(
        r.message
          ? `${r.message}${r.order_id ? t("ps.orderIdSuffix", { id: r.order_id }) : ""}`
          : t("ps.orderPlaced"),
      );
      setCalc(null);
      onPurchased();
    } catch (e) { toast.err(String(e)); }
    finally { setBuying(false); }
  };

  return (
    <div className="mb-3.5 rounded-lg bg-bg-white-0 p-[18px] shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
      <h3 className="m-0 mb-2 text-label-sm text-text-strong-950">{t("ps.buyProxies")}</h3>
      {!ready ? (
        <p className="m-0 text-paragraph-xs text-text-soft-400">Loading products…</p>
      ) : options.length === 0 ? (
        <p className="m-0 text-paragraph-xs text-text-soft-400">{t("ps.nothingAvailableToBuyRightNow")}</p>
      ) : (
        <div className="flex flex-col gap-3">
          <div className="grid grid-cols-2 gap-3">
            <label className="flex flex-col gap-1">
              <span className="text-label-xs text-text-sub-600">{t("ps.product")}</span>
              <CSSelect
                value={productName}
                onChange={setProductName}
                options={options.map((p) => ({ value: p.name, label: p.name }))}
              />
            </label>
            <label className="flex flex-col gap-1">
              <span className="text-label-xs text-text-sub-600">{t("ps.billingCycle")}</span>
              <CSSelect
                value={cycle}
                onChange={setCycle}
                placeholder="—"
                options={(product?.cycles?.length ? product.cycles : []).map((c) => ({ value: c, label: c }))}
              />
            </label>
          </div>
          <div className="grid grid-cols-2 gap-3">
            {needLocation ? (
              <label className="flex flex-col gap-1">
                <span className="text-label-xs text-text-sub-600">
                  Location{availForCountry != null && <span className="text-text-soft-400"> · {availForCountry} available</span>}
                </span>
                <CSSelect
                  value={country}
                  onChange={setCountry}
                  placeholder={t("ps.pickACountry")}
                  isSearchable
                  searchPlaceholder="Search locations…"
                  options={(product?.locations ?? []).map((l) => ({ value: l, label: l }))}
                />
              </label>
            ) : (
              <div />
            )}
            <NumField label={t("ps.quantity")} value={quantity} onChange={(v) => { setQuantity(Math.max(1, Math.round(v))); setCalc(null); }} />
          </div>
          <div className="grid grid-cols-2 items-end gap-3">
            <Field label={t("ps.promoCodeOptional")} value={promo} onChange={setPromo} />
            <Checkbox
              label={t("ps.autoRenew")}
              checked={autoRenew}
              onChange={(e) => setAutoRenew(e.target.checked)}
              wrapperClassName="mb-2"
            />
          </div>
          {needLocation && (
            <Checkbox
              label={t(quantity === 1 ? "ps.addP0fSlotsOne" : "ps.addP0fSlotsMany", { n: quantity })}
              checked={buyP0f}
              onChange={(e) => { setBuyP0f(e.target.checked); setCalc(null); }}
            />
          )}
          <div className="mt-1 flex items-center gap-3">
            <Button variant="neutral" mode="stroke" size="small" onClick={calculate} disabled={calcing || !productName} isLoading={calcing}>
              {calcing ? "Calculating…" : t("ps.calculatePrice")}
            </Button>
            {calc && (
              <span className="ml-auto inline-flex items-center gap-2">
                {calc.discount_percent > 0 && <span className="text-paragraph-sm text-text-soft-400 line-through">{fmtCents(calc.original_price)}</span>}
                <span className="text-title-h6 text-text-strong-950">{fmtCents(calc.total_with_addons ?? calc.final_price)}</span>
                {calc.discount_percent > 0 && <Badge color="success" variant="lighter" size="small">-{calc.discount_percent}%</Badge>}
                {!!calc.addons_price && calc.addons_price > 0 && (
                  <span className="text-paragraph-xs text-text-soft-400">incl. {fmtCents(calc.addons_price)} p0f</span>
                )}
              </span>
            )}
            <Button variant="primary" mode="filled" size="small" onClick={buy} disabled={buying || !productName} isLoading={buying}>
              {buying ? "Buying…" : t("ps.buy")}
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
