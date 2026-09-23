import { Button } from "@proxyshard/shardx-ui-kit";
import { FolderIcon } from "../../../shared/icons";
import { useFingerprint } from "../../../entities/fingerprint";
import { useT } from "../../../shared/i18n";

export function LibraryFolderButton() {
  const t = useT();
  const openLibraryFolder = useFingerprint((s) => s.openLibraryFolder);
  return (
    <Button
      variant="neutral"
      mode="stroke"
      size="small"
      leftIcon={<FolderIcon className="size-4" />}
      onClick={openLibraryFolder}
      title={t("fp.revealTheOnDiskLibraryFolderDropJson")}
    >
      {t("fp.libraryFolder")}
    </Button>
  );
}
