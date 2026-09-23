import { Button } from "@proxyshard/shardx-ui-kit";
import { FolderIcon } from "../../../shared/icons";
import { useFingerprint } from "../../../entities/fingerprint";
import { useT } from "../../../shared/i18n";

export function ImportFromFileButton() {
  const t = useT();
  const importJsonFile = useFingerprint((s) => s.importJsonFile);
  return (
    <Button variant="neutral" mode="stroke" size="small" leftIcon={<FolderIcon className="size-4" />} onClick={importJsonFile}>
      {t("fp.importFromFile")}
    </Button>
  );
}
