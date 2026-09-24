import { useEffect, useState } from "react";
import { Checkbox, DialogModal, SegmentControl } from "@proxyshard/shardx-ui-kit";
import Badge from "../../../shared/ui/Badge";
import { CSSelect } from "../../../shared/ui/CSSelect";
import { Field } from "../../../shared/ui/Field";
import { toast } from "../../../shared/model/toast";
import type { PsOrder, PsActiveProxy } from "../../../entities/proxyshard";
import { psSignatures, psActive, psOrder, psSignatureSet } from "../../../entities/proxyshard";
import { proxyBulkSave } from "../../../entities/proxy";
import { useT } from "../../../shared/i18n";
import { safeUiError } from "../../../shared/lib/utils";

/// Active-proxy picker: fetch an order's proxies, choose SOCKS5/HTTP and which
/// IPs to import into the local proxy list (via proxy_bulk_save, which dedups).
export function PsImportModal({ order, onClose }: { order: PsOrder; onClose: () => void }) {
  const t = useT();
  const [items, setItems] = useState<PsActiveProxy[] | null>(null);
  const [err, setErr] = useState("");
  const [kind, setKind] = useState<"socks5" | "http">("socks5");
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);
  const [tag, setTag] = useState("");
  // Per-IP p0f signature ("" = leave unchanged).
  const [sigByIp, setSigByIp] = useState<Record<string, string>>({});
  // p0f slot accounting from the order detail (available vs already used).
  const [slots, setSlots] = useState<{ avail: number; used: number } | null>(null);

  useEffect(() => {
    psActive(order.order_id)
      .then((r) => {
        const data: PsActiveProxy[] = r.data ?? [];
        setItems(data);
        setSel(new Set(data.map((d) => d.ip))); // select all by default
        // Prefill each row with its currently-set signature.
        setSigByIp(Object.fromEntries(data.map((d) => [d.ip, d.signature ?? ""])));
        setTag((r.order_tag && r.order_tag !== "none" ? r.order_tag : "") || `order ${order.order_id}`);
      })
      .catch((e) => setErr(String(e)));
    psOrder(order.order_id)
      .then((r) => {
        const o = r.order ?? {};
        setSlots({ avail: o.p0f_slots_available ?? 0, used: o.p0f_slots_used ?? 0 });
      })
      .catch(() => { });
  }, [order.order_id]);

  const toggle = (ip: string) =>
    setSel((s) => { const n = new Set(s); n.has(ip) ? n.delete(ip) : n.add(ip); return n; });

  const allChecked = !!items && items.length > 0 && items.every((d) => sel.has(d.ip));
  const toggleAll = () =>
    setSel(allChecked ? new Set() : new Set((items ?? []).map((d) => d.ip)));

  // p0f can be assigned only while free slots remain.
  const canSetP0f = !!slots && slots.avail > slots.used;
  const free = slots ? Math.max(0, slots.avail - slots.used) : 0;
  const setSig = (ip: string, v: string) => setSigByIp((m) => ({ ...m, [ip]: v }));

  const save = async () => {
    if (!items) return;
    const chosen = items.filter((d) => sel.has(d.ip));
    if (chosen.length === 0) { toast.err(t("ps.selectAtLeastOneProxy")); return; }
    const label = tag.trim() || `order ${order.order_id}`;
    const entries = chosen
      .map((d) => {
        const port = kind === "http" ? d.http_port : d.socks_port;
        if (!d.ip || !port) return null;
        return {
          id: "",
          name: `${label} · ${d.ip}`,
          kind,
          host: d.ip,
          port,
          username: d.username ?? "",
          password: d.password ?? "",
          country: "",
          notes: t("ps.orderTitle", { id: order.order_id }),
        };
      })
      .filter(Boolean);
    setSaving(true);
    try {
      const n = await proxyBulkSave(entries);
      toast.ok(n > 0 ? t(n === 1 ? "ps.addedProxyOne" : "ps.addedProxyMany", { n }) : t("ps.noNewProxiesAlreadyInYourList"));
      // Apply only the selected proxies whose signature actually changed
      // (a non-empty value differing from the one already set).
      const sigItems = chosen
        .filter((d) => { const v = sigByIp[d.ip] ?? ""; return v !== "" && v !== (d.signature ?? ""); })
        .map((d) => ({ ip: d.ip, signature: sigByIp[d.ip] }));
      if (sigItems.length > 0) {
        try {
          await psSignatureSet(order.order_id, sigItems);
          toast.ok(t(sigItems.length === 1 ? "ps.setP0fOnOne" : "ps.setP0fOnMany", { n: sigItems.length }));
        } catch (e) { toast.err(t("ps.signatureError", { error: String(e) })); }
      }
      onClose();
    } catch (e) { toast.err(safeUiError(e)); }
    finally { setSaving(false); }
  };

  return (
    <DialogModal
      open
      onClose={onClose}
      title={t("ps.addProxiesTitle", { product: order.product_name, id: order.order_id })}
      maxWidthClassName="max-w-[880px]"
      confirmLabel={saving ? "Adding…" : `Add ${sel.size}`}
      onConfirm={save}
      isLoading={saving}
      isDisabled={saving || !items || sel.size === 0}
      cancelLabel={t("common.cancel")}
      onCancel={onClose}
    >
      <div className="flex flex-col gap-3 py-4">
        <div className="mb-2.5 flex items-end gap-3">
          <div className="flex-1">
            <Field label={t("ps.namePrefix")} value={tag} onChange={setTag} />
          </div>
          <div>
            <SegmentControl
              size="small"
              value={kind}
              items={[
                { value: "socks5", label: t("ps.socks5") },
                { value: "http", label: t("ps.http") },
              ]}
              onChange={(v) => setKind(v as "socks5" | "http")}
            />
          </div>
        </div>
        {slots && (
          <p className="m-0 mb-1.5 text-paragraph-xs text-text-soft-400">
            p0f slots: {slots.used}/{slots.avail} used
            {canSetP0f ? t("ps.freeSetSignature", { free }) : " · no free slots (buy more to assign p0f)"}
          </p>
        )}
        {!items && !err && <p className="m-0 text-paragraph-xs text-text-soft-400">Loading proxies…</p>}
        {err && <p className="m-0 text-paragraph-xs text-text-soft-400">{err}</p>}
        {items && items.length === 0 && <p className="m-0 text-paragraph-xs text-text-soft-400">{t("ps.thisOrderHasNoActiveProxies")}</p>}
        {items && items.length > 0 && (
          <div className="mt-1.5 max-h-[320px] overflow-hidden overflow-y-auto rounded-10 bg-bg-white-0 ring-1 ring-inset ring-stroke-soft-200">
            <div className="grid items-center gap-2.5 border-b border-stroke-soft-200 bg-bg-weak-50 px-3 py-2" style={{ gridTemplateColumns: "20px 1fr 132px" }}>
              <Checkbox checked={allChecked} onChange={toggleAll} title={t("ps.selectAll")} />
              <span className="text-paragraph-xs text-text-soft-400">{sel.size} of {items.length} selected</span>
              <span className="text-right text-paragraph-xs text-text-soft-400">{canSetP0f ? "p0f" : ""}</span>
            </div>
            {items.map((d) => {
              const port = kind === "http" ? d.http_port : d.socks_port;
              return (
                <div
                  key={d.ip}
                  className="grid items-center gap-2.5 border-b border-stroke-soft-200 px-3 py-[9px] transition-colors last:border-b-0 hover:bg-bg-weak-50"
                  style={{ gridTemplateColumns: "20px minmax(120px,1.3fr) 1fr auto 132px" }}
                >
                  <Checkbox checked={sel.has(d.ip)} onChange={() => toggle(d.ip)} />
                  <span className="mono cursor-pointer text-paragraph-xs text-text-strong-950 transition-colors hover:text-primary-base" onClick={() => toggle(d.ip)}>{d.ip}:{port}</span>
                  <span className="text-paragraph-xs text-text-soft-400">{d.username}</span>
                  <Badge color={d.status === "active" ? "success" : "gray"} variant="filled" size="small" dot>
                    {d.status}
                  </Badge>
                  {(canSetP0f || d.signature) ? (
                    // Editable when free slots exist, or this IP is already
                    // signed (re-assigning an OS doesn't consume a slot).
                    <div onClick={(e) => e.stopPropagation()}>
                      <CSSelect value={sigByIp[d.ip] ?? ""} onChange={(v) => setSig(d.ip, v)} options={psSignatures(t)} placeholder={t("ps.p0f")} />
                    </div>
                  ) : (
                    <span className="text-right text-paragraph-xs text-text-soft-400">—</span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </DialogModal>
  );
}
