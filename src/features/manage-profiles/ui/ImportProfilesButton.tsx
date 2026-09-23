import { Button } from "@proxyshard/shardx-ui-kit";
import { DownloadIcon } from "../../../shared/icons";
import { useProfile } from "../../../entities/profile";
import { useT } from "../../../shared/i18n";

export function ImportProfilesButton() {
  const t = useT();
  const bulkImport = useProfile((s) => s.bulkImport);
  return (
    <Button
      variant="neutral"
      mode="stroke"
      size="small"
      leftIcon={<DownloadIcon className="size-4" />}
      onClick={bulkImport}
      title={t("profile.createProfilesFromExportedJsonInTheC")}
    >
      {t("common.import")}
    </Button>
  );
}
