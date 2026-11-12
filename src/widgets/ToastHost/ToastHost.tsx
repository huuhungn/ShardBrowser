import { Alert } from "@proxyshard/shardx-ui-kit";
import { useToastStore } from "../../shared/model/toast";

/// Global toast stack — UI-kit Alerts fed by the zustand toast store.
export function ToastHost() {
  const items = useToastStore((s) => s.items);
  const dismiss = useToastStore((s) => s.dismiss);
  if (items.length === 0) return null;
  return (
    <div className="pointer-events-none fixed bottom-6 right-6 z-300 flex flex-col-reverse gap-3">
      {items.map((t) => (
        <div
          key={t.id}
          className="pointer-events-auto min-w-[280px] max-w-[520px] animate-[toastIn_0.2s_cubic-bezier(.2,.9,.3,1)] shadow-[var(--shadow-md)]"
        >
          <Alert
            className={t.kind === "err" ? "toast-err" : t.kind === "ok" ? "toast-ok" : "toast-info"}
            status={t.kind === "ok" ? "success" : t.kind === "err" ? "error" : "information"}
            variant="light"
            onClose={() => dismiss(t.id)}
          >
            {t.text}
            {t.action && (
              <button
                type="button"
                className="ml-2 font-medium underline underline-offset-2"
                onClick={() => { dismiss(t.id); t.action?.onClick(); }}
              >
                {t.action.label}
              </button>
            )}
          </Alert>
        </div>
      ))}
    </div>
  );
}
