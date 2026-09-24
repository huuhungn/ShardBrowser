import Badge from "../../../shared/ui/Badge";
import type { PsMe } from "../model/types";
import type { PsStatus } from "../lib/usePsAccount";
import { t } from "../../../shared/i18n";
import { safeUiError } from "../../../shared/lib/utils";

export function PsConnectionBadge({ status, me, err, hasKey }: {
  status: PsStatus;
  me: PsMe | null;
  err: string;
  hasKey: boolean;
}) {
  return (
    <div className="mt-2.5 min-h-[22px]">
      {status === "checking" && <span className="text-paragraph-xs text-text-soft-400">{t("ps.validating")}</span>}
      {status === "ok" && me && (
        <Badge color="success" variant="filled" size="small" dot>{t("ps.connectedAs", { email: me.email })}</Badge>
      )}
      {status === "err" && (
        <Badge color="error" variant="filled" size="small" dot title={safeUiError(err)}>{t("ps.notConnectedReason", { error: safeUiError(err) })}</Badge>
      )}
      {status === "idle" && !hasKey && <span className="text-paragraph-xs text-text-soft-400">{t("ps.noKeySetYet")}</span>}
    </div>
  );
}
