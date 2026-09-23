import { openUrl } from "@tauri-apps/plugin-opener";
import { Button } from "@proxyshard/shardx-ui-kit";
import { withUtm } from "../../../shared/lib/utils";
import { useT } from "../../../shared/i18n";

/// Promo: routes to ProxyShard's UDP / p0f-spoofed residential pool — the
/// proxies that actually make ShardX's QUIC + WebRTC stack work end-to-end.
export function BuyProxiesButton() {
  const t = useT();
  return (
    <Button
      variant="primary"
      mode="lighter"
      size="small"
      onClick={() => { openUrl(withUtm("https://proxyshard.com")).catch(() => { }); }}
      title={t("proxy.openProxyshardComResidentialSocks5Wi")}
    >
      {t("proxy.buyProxies")} <span className="ml-1 opacity-70">- UDP + p0f</span>
    </Button>
  );
}
