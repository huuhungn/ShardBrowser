import { openUrl } from "@tauri-apps/plugin-opener";
import { Button } from "@proxyshard/shardx-ui-kit";
import { ShardMini } from "../../../shared/icons";
import { DASHBOARD_URL } from "../../../shared/lib/utils";
import { useT } from "../../../shared/i18n";

export function OpenDashboardButton() {
  const t = useT();
  return (
    <Button
      variant="primary"
      mode="lighter"
      size="small"
      leftIcon={<ShardMini />}
      onClick={() => { openUrl(DASHBOARD_URL).catch(() => {}); }}
      title={t("ps.openTheProxyshardDashboardInYourBrow")}
    >
      {t("ps.openDashboard")}
    </Button>
  );
}
