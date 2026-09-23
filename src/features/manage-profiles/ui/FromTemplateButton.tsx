import { Button } from "@proxyshard/shardx-ui-kit";
import { useProfile } from "../../../entities/profile";
import { useT } from "../../../shared/i18n";

export function FromTemplateButton() {
  const t = useT();
  const setTemplatePickerOpen = useProfile((s) => s.setTemplatePickerOpen);
  return (
    <Button variant="neutral" mode="stroke" size="small" onClick={() => setTemplatePickerOpen(true)}>
      {t("profile.fromTemplate")}
    </Button>
  );
}
