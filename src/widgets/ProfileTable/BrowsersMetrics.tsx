import { Metric } from "../../shared/ui/Metric";
import { useProfile, useRunningCount } from "../../entities/profile";
import { useT } from "../../shared/i18n";

export function BrowsersMetrics() {
  const t = useT();
  const profileCount = useProfile((s) => s.profiles.length);
  const proxyCount = useProfile((s) => s.proxies.length);
  const fingerprintCount = useProfile((s) => s.fingerprints.length);
  const runningCount = useRunningCount();

  return (
    <div className="mb-4 grid grid-cols-2 gap-[10px] [@media(min-width:1100px)]:grid-cols-4">
      <Metric label={t("common.profiles")} value={String(profileCount)} accent />
      <Metric label={t("common.running")} value={String(runningCount)} pulse={runningCount > 0} />
      <Metric label={t("common.proxies")} value={String(proxyCount)} />
      <Metric label={t("common.fingerprints")} value={String(fingerprintCount)} />
    </div>
  );
}
