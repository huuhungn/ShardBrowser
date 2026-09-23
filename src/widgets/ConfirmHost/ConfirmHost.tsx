import { Button, Modal } from "@proxyshard/shardx-ui-kit";
import { useConfirmStore } from "../../shared/model/confirm";
import { t } from "../../shared/i18n";

/// Global confirm dialog — UI-kit Modal fed by the zustand confirm store.
export function ConfirmHost() {
  const req = useConfirmStore((s) => s.req);
  if (!req) return null;
  const done = (v: any) => req.resolve(v);
  return (
    <Modal
      open
      onClose={() => done(null)}
      title={req.title ?? t("ui.confirm")}
      maxWidthClassName="max-w-md"
      footer={
        <div className="flex justify-end gap-2">
          {req.buttons.map((b, i) => (
            <Button
              key={i}
              size="small"
              variant={b.danger ? "error" : b.primary ? "primary" : "neutral"}
              mode={b.danger || b.primary ? "filled" : "stroke"}
              onClick={() => done(b.value)}
            >
              {b.label}
            </Button>
          ))}
        </div>
      }
    >
      <p className="m-0 text-paragraph-sm text-text-sub-600">{req.message}</p>
    </Modal>
  );
}
