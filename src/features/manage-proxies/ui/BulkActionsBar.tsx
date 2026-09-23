import { Button } from "@proxyshard/shardx-ui-kit";
import { RefreshIcon, UploadIcon, DeleteIcon, SyncIcon } from "../../../shared/icons";
import { useProxy } from "../../../entities/proxy";
import { t } from "../../../shared/i18n";

export function BulkActionsBar() {
  const count = useProxy((s) => s.proxySel.size);
  const bulkTest = useProxy((s) => s.bulkTest);
  const bulkExport = useProxy((s) => s.bulkExport);
  const bulkDelete = useProxy((s) => s.bulkDelete);
  const clearSelected = useProxy((s) => s.clearSelected);
  const setDistributeOpen = useProxy((s) => s.setDistributeOpen);

  if (count === 0) return null;

  return (
    <div className="flex items-center gap-2 rounded-8 bg-primary-alpha-10 py-1 pl-3 pr-1 text-label-xs text-primary-base ring-1 ring-inset ring-primary-alpha-24">
      <span>{count} selected</span>
      <Button variant="neutral" mode="stroke" size="2xsmall" leftIcon={<RefreshIcon className="size-3.5" />} onClick={bulkTest}>{t("proxy.test")}</Button>
      <Button variant="primary" mode="stroke" size="2xsmall" leftIcon={<SyncIcon className="size-3.5" />} onClick={() => setDistributeOpen(true)}>{t("proxy.distribute")}</Button>
      <Button variant="neutral" mode="stroke" size="2xsmall" leftIcon={<UploadIcon className="size-3.5" />} onClick={bulkExport}>{t("proxy.export")}</Button>
      <Button variant="error" mode="stroke" size="2xsmall" leftIcon={<DeleteIcon className="size-3.5" />} onClick={bulkDelete}>{t("proxy.delete")}</Button>
      <Button variant="neutral" mode="ghost" size="2xsmall" onClick={clearSelected}>{t("proxy.clear")}</Button>
    </div>
  );
}
