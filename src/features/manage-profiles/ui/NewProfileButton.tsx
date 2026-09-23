import { Button } from "@proxyshard/shardx-ui-kit";
import { AddIcon } from "../../../shared/icons";
import { useProfile } from "../../../entities/profile";
import { useT } from "../../../shared/i18n";

export function NewProfileButton() {
  const t = useT();
  const newProfile = useProfile((s) => s.newProfile);
  return (
    <Button variant="primary" mode="filled" size="small" leftIcon={<AddIcon className="size-4" />} onClick={newProfile}>
      {t("profile.newProfile")}
    </Button>
  );
}
