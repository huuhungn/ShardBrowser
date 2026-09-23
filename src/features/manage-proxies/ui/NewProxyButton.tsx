import { Button } from "@proxyshard/shardx-ui-kit";
import { AddIcon } from "../../../shared/icons";
import { useProxy } from "../../../entities/proxy";
import { useT } from "../../../shared/i18n";

export function NewProxyButton({ className }: { className?: string }) {
  const t = useT();
  const setBulkOpen = useProxy((s) => s.setBulkOpen);
  return (
    <Button
      variant="primary"
      mode="filled"
      size="small"
      className={className}
      leftIcon={<AddIcon className="size-4" />}
      onClick={() => setBulkOpen(true)}
    >
      {t("proxy.newProxy")}
    </Button>
  );
}
