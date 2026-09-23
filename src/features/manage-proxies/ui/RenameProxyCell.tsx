import { useState } from "react";
import { Input } from "@proxyshard/shardx-ui-kit";
import { useProxy, type ProxyEntry } from "../../../entities/proxy";
import { useT } from "../../../shared/i18n";

export function RenameProxyCell({ proxy }: { proxy: ProxyEntry }) {
  const t = useT();
  const renameProxy = useProxy((s) => s.renameProxy);
  const [draft, setDraft] = useState<string | null>(null);

  const commit = async () => {
    if (draft == null) return;
    await renameProxy(proxy.id, draft);
    setDraft(null);
  };

  return (
    <div className="min-w-0 cursor-pointer overflow-hidden">
      {draft != null ? (
        <Input
          autoFocus
          inputSize="small"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={commit}
          onKeyDown={(e) => {
            if (e.key === "Enter") commit();
            else if (e.key === "Escape") setDraft(null);
          }}
        />
      ) : (
        <span
          className="cursor-pointer text-label-xs text-text-strong-950 transition-colors hover:text-primary-base"
          // A shift-click on the row is a range selection, not a rename. The
          // event is honest here — this is a span, not a checkbox's label.
          onClick={(e) => { if (!e.shiftKey) setDraft(proxy.name); }}
          title={t("proxy.clickToRename")}
        >
          {proxy.name || "—"}
        </span>
      )}
    </div>
  );
}
