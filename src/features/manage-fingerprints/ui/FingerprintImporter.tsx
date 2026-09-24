import { useState } from "react";
import { DialogModal, Textarea } from "@proxyshard/shardx-ui-kit";
import { Field } from "../../../shared/ui/Field";
import { toast } from "../../../shared/model/toast";
import { fingerprintImport } from "../../../entities/fingerprint";
import { useT } from "../../../shared/i18n";
import { safeUiError } from "../../../shared/lib/utils";

export function FingerprintImporter({ onClose }: { onClose: () => void }) {
  const t = useT();
  const [text, setText] = useState("");
  const [name, setName] = useState("");
  const save = async () => {
    try {
      const e = await fingerprintImport(text, name || null);
      toast.ok(t("fp.importedNamed", { label: e.label }));
      onClose();
    } catch (e) { toast.err(safeUiError(e)); }
  };
  return (
    <DialogModal
      open
      onClose={onClose}
      title={t("fp.pasteFingerprintconfigJson")}
      maxWidthClassName="max-w-[880px]"
      confirmLabel={t("common.import")}
      onConfirm={save}
      cancelLabel={t("common.cancel")}
      onCancel={onClose}
    >
      <div className="flex flex-col gap-3 py-4">
        <Field label={t("fp.nameOptionalBecomesTheFileId")} value={name} onChange={setName} placeholder={t("fp.eGMacM4ProReal")} />
        <Textarea
          label={t("fp.pasteTheFullJson")}
          rows={14}
          className="mono w-[500px]"
          value={text}
          onChange={(e) => setText(e.target.value)}
          placeholder='{ "name": "...", "navigator": { ... }, "webgl": { ... }, ... }'
        />
      </div>
    </DialogModal>
  );
}
