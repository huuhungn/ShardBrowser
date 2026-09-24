import { useState } from "react";
import { DialogModal } from "@proxyshard/shardx-ui-kit";
import { NumField } from "../../../shared/ui/NumField";
import { Field } from "../../../shared/ui/Field";
import { toast } from "../../../shared/model/toast";
import type { PsOrder } from "../../../entities/proxyshard";
import { psAddBandwidth } from "../../../entities/proxyshard";
import { useT } from "../../../shared/i18n";
import { safeUiError } from "../../../shared/lib/utils";

export function PsTopupModal({ order, onClose, onDone }: { order: PsOrder; onClose: () => void; onDone: () => void }) {
  const t = useT();
  const [amount, setAmount] = useState(5);
  const [promo, setPromo] = useState("");
  const [busy, setBusy] = useState(false);
  const submit = async () => {
    if (amount < 1) { toast.err(t("ps.amountMustBeAtLeast1GB")); return; }
    setBusy(true);
    try {
      await psAddBandwidth(order.order_id, amount, promo.trim() || null);
      toast.ok(t("ps.addedGb", { amount, id: order.order_id }));
      onDone();
    } catch (e) { toast.err(safeUiError(e)); }
    finally { setBusy(false); }
  };
  return (
    <DialogModal
      open
      onClose={onClose}
      title={t("ps.addTraffic")}
      subtitle={t("ps.productOrder", { product: order.product_name, id: order.order_id })}
      confirmLabel={busy ? "Buying…" : `Buy ${amount} GB`}
      onConfirm={submit}
      isLoading={busy}
      cancelLabel={t("common.cancel")}
      onCancel={onClose}
    >
      <div className="flex flex-col gap-3 py-4">
        <NumField label={t("ps.amountGb")} value={amount} onChange={(v) => setAmount(Math.max(1, Math.round(v)))} />
        <Field label={t("ps.promoCodeOptional")} value={promo} onChange={setPromo} />
      </div>
    </DialogModal>
  );
}
