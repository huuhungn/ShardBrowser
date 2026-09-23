import { Button } from "@proxyshard/shardx-ui-kit";
import { DownloadIcon } from "../../../shared/icons";
import { useProxy } from "../../../entities/proxy";
import { useT } from "../../../shared/i18n";

export function ImportProxyButton() {
  const t = useT();
  const bulkImportClipboard = useProxy((s) => s.bulkImportClipboard);
  return (
    <Button
      variant="neutral"
      mode="stroke"
      size="small"
      leftIcon={<DownloadIcon className="size-4" />}
      onClick={bulkImportClipboard}
      title={t("proxy.importProxiesFromTheClipboard")}
    >
      {t("common.import")}
    </Button>
  );
}
