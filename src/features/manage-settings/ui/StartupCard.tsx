import { Switch } from "@proxyshard/shardx-ui-kit";
import type { Settings, StartupStatus } from "../../../entities/settings";
import { useT } from "../../../shared/i18n";

/// Sign-in startup, and whether the OS actually registered it.
///
/// The switch is a request; `startup_status` is the truth. Showing both
/// stops a failed registration from looking like a working one.
export function StartupCard({
  settings,
  onChange,
  status,
  error,
}: {
  settings: Settings;
  onChange: (next: Settings) => void;
  status: StartupStatus | null;
  error: string | null;
}) {
  const t = useT();
  const launch = settings.launch_at_login ?? false;
  return (
    <div className="flex flex-col gap-3">
      <p className="m-0 text-paragraph-sm text-text-sub-600">
        {t("settings.startShardxLauncherWhenYouSignInSoIt")}
      </p>

      <Switch
        label={t("settings.startShardxLauncherWhenISignIn")}
        checked={launch}
        onChange={(checked) => onChange({ ...settings, launch_at_login: checked })}
      />
      <Switch
        label={t("settings.startInTheSystemTray")}
        checked={settings.start_minimized ?? true}
        disabled={!launch}
        onChange={(checked) => onChange({ ...settings, start_minimized: checked })}
      />

      <div
        role={error ? "alert" : "status"}
        className="flex flex-col gap-0.5 rounded-lg bg-bg-weak-50 px-3 py-2"
      >
        <strong className="text-label-xs text-text-strong-950">
          {status?.registered
            ? t("settings.startupEntryRegistered")
            : error
              ? t("settings.startupStatusUnavailable")
              : t("settings.startupEntryNotRegistered")}
        </strong>
        <span className="text-paragraph-xs text-text-sub-600">
          {error ??
            (status?.registered
              ? t("settings.launcherAndAutomationAPIWillStartAtDes")
              : t("settings.enableThisOptionAndSaveSettingsToReg"))}
        </span>
      </div>
    </div>
  );
}
