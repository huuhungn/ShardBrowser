import { useEffect, useState } from "react";
import { open } from "@tauri-apps/plugin-dialog";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Button, Input, Select, Switch, Textarea } from "@proxyshard/shardx-ui-kit";
import { DownloadIcon } from "../../shared/icons";
import { Topbar } from "../../shared/ui/Topbar";
import { CopyField } from "../../shared/ui/CopyField";
import { toast } from "../../shared/model/toast";
import { useNav } from "../../shared/model/navigation";
import { withUtm } from "../../shared/lib/utils";
import type { Settings, ApiInfo, StartupStatus, McpStatus, CodexMcpStatus, HermesMcpStatus } from "../../entities/settings";
import { HELPER_KINDS } from "../../entities/settings";
import { settingsGet, settingsSave, apiInfo, apiRegenerateToken, mcpDownload, mcpSetPath,
  startupStatus, mcpStatus as mcpStatusGet, codexMcpStatus, hermesMcpStatus } from "../../entities/settings";
import { StartupCard, McpCard } from "../../features/manage-settings";
import { safeUiError } from "../../shared/lib/utils";
import { DataRootCard } from "../../features/manage-profiles/ui/DataRootCard";
import { LANG_OPTIONS, useLang, useT } from "../../shared/i18n";
import { Rich } from "../../shared/i18n/Rich";
import { TeamCard } from "../../features/manage-team/ui/TeamCard";

function SettingsCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-3.5 rounded-lg bg-bg-white-0 p-[18px] shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
      <h3 className="m-0 mb-1.5 text-label-sm text-text-strong-950">{title}</h3>
      {children}
    </div>
  );
}

export function SettingsPage() {
  const t = useT();
  const lang = useLang((v) => v.lang);
  const setLang = useLang((v) => v.setLang);
  const [s, setS] = useState<Settings>({
    browser_path: null,
    theme: "dark",
    geo_checker: "ip-api.com",
    screen_resolution_mode: "fingerprint",
    helper_enabled: true,
    helper_triggers: [],
    extra_args: "",
    api_enabled: true,
    api_port: 40325,
  });
  const [api, setApi] = useState<ApiInfo | null>(null);
  // The saved copy, so "unsaved changes" is a fact rather than a guess.
  const [baseline, setBaseline] = useState<Settings | null>(null);
  const [startup, setStartup] = useState<StartupStatus | null>(null);
  const [startupError, setStartupError] = useState<string | null>(null);
  const [mcp, setMcp] = useState<McpStatus | null>(null);
  const [mcpError, setMcpError] = useState<string | null>(null);
  const [codex, setCodex] = useState<CodexMcpStatus | null>(null);
  const [codexError, setCodexError] = useState<string | null>(null);
  const [hermes, setHermes] = useState<HermesMcpStatus | null>(null);
  const [hermesError, setHermesError] = useState<string | null>(null);

  const refreshApi = () => apiInfo().then(setApi).catch(() => {});
  const refreshStartup = () =>
    startupStatus().then((v) => { setStartup(v); setStartupError(null); })
      .catch((e) => setStartupError(safeUiError(e)));
  const refreshMcp = () =>
    mcpStatusGet().then((v) => { setMcp(v); setMcpError(null); })
      .catch((e) => setMcpError(safeUiError(e)));
  const checkCodex = () =>
    codexMcpStatus().then((v) => { setCodex(v); setCodexError(null); })
      .catch((e) => setCodexError(safeUiError(e)));

  const checkHermes = () =>
    hermesMcpStatus().then((v) => { setHermes(v); setHermesError(null); })
      .catch((e) => setHermesError(safeUiError(e)));

  const setSection = useNav((n) => n.setSection);

  useEffect(() => {
    settingsGet().then((v) => { setS(v); setBaseline(v); });
    void refreshApi();
    void refreshStartup();
    void refreshMcp();
  }, []);
  const regenToken = async () => {
    try { setApi(await apiRegenerateToken()); toast.ok(t("settings.api.tokenRegenerated")); }
    catch (e) { toast.err(String(e)); }
  };

  const [mcpBusy, setMcpBusy] = useState(false);
  // Download MCP server source; user manages install + client setup.
  const downloadMcp = async () => {
    const dir = await open({ directory: true, title: t("settings.mcp.pickDownloadDir") });
    if (typeof dir !== "string") return;
    setMcpBusy(true);
    try {
      const path = await mcpDownload(dir);
      toast.ok(t("settings.mcp.downloaded", { path }));
    } catch (e) { toast.err(t("settings.mcp.downloadFailed", { error: String(e) })); }
    finally { setMcpBusy(false); }
  };
  // Adopt an MCP server the operator already has, instead of downloading a
  // duplicate copy next to it.
  const useExistingMcp = async () => {
    const dir = await open({ directory: true, title: t("settings.mcp.pickExistingDir") });
    if (typeof dir !== "string") return;
    setMcpBusy(true);
    try {
      const status = await mcpSetPath(dir);
      setMcp(status);
      setMcpError(null);
      toast.ok(t("settings.mcp.usingAt", { path: status.path ?? dir }));
    } catch (e) { toast.err(safeUiError(e)); }
    finally { setMcpBusy(false); }
  };
  const save = async () => {
    try {
      await settingsSave(s);
      setBaseline({ ...s });
      // Saving is what registers the startup entry, so re-read the truth.
      await Promise.all([refreshApi(), refreshStartup()]);
      toast.ok(t("settings.save.saved"));
    } catch (e) { toast.err(safeUiError(e)); }
  };

  const dirty = !!baseline && JSON.stringify(s) !== JSON.stringify(baseline);
  const restartPending =
    !!api && ((s.api_enabled ?? true) !== api.enabled || (s.api_port ?? 40325) !== api.port);
  return (
    <section className="flex flex-col">
      <Topbar crumbs={[t("settings.crumb.system"), t("settings.crumb.settings")]} />
      <div className="mb-3.5 flex items-end justify-between gap-4">
        <h1 className="m-0 text-title-h5 text-text-strong-950">{t("settings.title")}</h1>
      </div>

      <SettingsCard title={t("settings.startup.title")}>
        <StartupCard settings={s} onChange={setS} status={startup} error={startupError} />
      </SettingsCard>

      <SettingsCard title={t("settings.mcp.title")}>
        <McpCard
          status={mcp}
          statusError={mcpError}
          codex={codex}
          codexError={codexError}
          hermes={hermes}
          hermesError={hermesError}
          api={api}
          onRefresh={async () => { await refreshMcp(); await checkCodex(); await checkHermes(); }}
          onCheckCodex={checkCodex}
          onCheckHermes={checkHermes}
        />
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          <Rich text={t("settings.mcp.help")} />
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <Button
            variant="neutral"
            mode="stroke"
            size="small"
            leftIcon={<DownloadIcon className="size-4" />}
            onClick={downloadMcp}
            disabled={mcpBusy}
            isLoading={mcpBusy}
          >
            {mcpBusy ? t("settings.mcp.downloading") : t("settings.mcp.download")}
          </Button>
          <Button
            variant="neutral"
            mode="stroke"
            size="small"
            onClick={useExistingMcp}
            disabled={mcpBusy}
          >
            {t("settings.mcp.useExisting")}
          </Button>
        </div>
        {mcp?.path && (
          <p className="m-0 mt-2 text-paragraph-xs text-text-sub-600">
            {t("settings.mcp.currentFolder")} <code>{mcp.path}</code>
          </p>
        )}
      </SettingsCard>

      <SettingsCard title={t("settings.team.title")}>
        <TeamCard />
      </SettingsCard>

      <SettingsCard title={t("settings.language.title")}>
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          {t("settings.language.help")}
        </p>
        <Select
          label={t("settings.language.label")}
          size="small"
          value={lang}
          onChange={(v) => setLang(v as (typeof LANG_OPTIONS)[number]["value"])}
          options={LANG_OPTIONS}
        />
      </SettingsCard>

      <SettingsCard title={t("settings.geo.title")}>
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          <Rich text={t("settings.geo.help")} />
        </p>
        <Select
          label={t("settings.geo.label")}
          size="small"
          value={s.geo_checker ?? "ip-api.com"}
          onChange={(v) => setS({ ...s, geo_checker: v })}
          options={[
            { value: "ip-api.com", label: "ip-api.com (45 req/min, HTTP)" },
            { value: "ipapi.co", label: "ipapi.co (1k/day, HTTPS)" },
            { value: "ipwho.is", label: "ipwho.is (10k/month, HTTPS)" },
          ]}
        />
      </SettingsCard>

      <SettingsCard title={t("settings.screen.title")}>
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          <Rich text={t("settings.screen.help")} />
        </p>
        <Select
          label={t("settings.screen.label")}
          size="small"
          value={s.screen_resolution_mode ?? "fingerprint"}
          onChange={(v) => setS({ ...s, screen_resolution_mode: v })}
          options={[
            { value: "fingerprint", label: t("settings.screen.fingerprint") },
            { value: "real", label: t("settings.screen.real") },
          ]}
        />
      </SettingsCard>

      <SettingsCard title={t("settings.helper.title")}>
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          <Rich text={t("settings.helper.help")} />
        </p>
        <div className="flex flex-col gap-3">
          <Switch
            label={t("settings.helper.enable")}
            checked={s.helper_enabled ?? true}
            onChange={(checked) => setS({ ...s, helper_enabled: checked })}
          />
          {(s.helper_enabled ?? true) && (
            <div>
              <div className="mb-1.5 text-label-xs text-text-sub-600">
                {t("settings.helper.reactTo")}
              </div>
              <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
                {t("settings.helper.triggersHelp")}
              </p>
              <div className="flex flex-wrap gap-1.5">
                {HELPER_KINDS.map((k) => {
                  const picked = (s.helper_triggers ?? []).includes(k.value);
                  return (
                    <button
                      key={k.value}
                      type="button"
                      onClick={() => {
                        const cur = s.helper_triggers ?? [];
                        setS({
                          ...s,
                          helper_triggers: picked
                            ? cur.filter((x) => x !== k.value)
                            : [...cur, k.value],
                        });
                      }}
                      className={`rounded-6 px-2 py-1 text-paragraph-xs ring-1 ring-inset transition-colors ${
                        picked
                          ? "bg-primary-alpha-10 text-primary-base ring-primary-alpha-24"
                          : "text-text-sub-600 ring-stroke-soft-200 hover:bg-bg-weak-50"
                      }`}
                    >
                      {k.label}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>
      </SettingsCard>

      <SettingsCard title={t("settings.camera.title")}>
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          <Rich text={t("settings.camera.help")} />
        </p>
        <Switch
          label={t("settings.camera.substitute")}
          checked={s.camera_enabled ?? true}
          onChange={(checked) => setS({ ...s, camera_enabled: checked })}
        />
      </SettingsCard>

      <SettingsCard title={t("settings.dataRoot.title")}>
        <DataRootCard />
      </SettingsCard>

      <SettingsCard title={t("settings.args.title")}>
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          <Rich text={t("settings.args.help")} />
        </p>
        <Textarea
          rows={3}
          className="mono"
          value={s.extra_args ?? ""}
          onChange={(e) => setS({ ...s, extra_args: e.target.value })}
          placeholder={"--disable-background-timer-throttling\n--window-size=1280,800"}
        />
      </SettingsCard>

      <SettingsCard title={t("settings.api.title")}>
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          <Rich text={t("settings.api.help")} />{" "}
          <a
            href="#"
            className="text-primary-base hover:underline"
            onClick={(e) => {
              e.preventDefault();
              openUrl(withUtm("https://docs.proxyshard.com/eng/shardx-launcher-api/binding-and-lifecycle?fallback=true")).catch(() => {});
            }}
          >
            {t("settings.api.reference")}
          </a>
        </p>
        <div className="flex flex-col gap-3">
          <Switch
            label={t("settings.api.enable")}
            checked={s.api_enabled ?? true}
            onChange={(checked) => setS({ ...s, api_enabled: checked })}
          />
          <Input
            label={t("settings.api.port")}
            inputSize="small"
            type="number"
            value={s.api_port ?? 40325}
            onChange={(e) => setS({ ...s, api_port: Number(e.target.value) || 40325 })}
          />
          {api && (
            <>
              <label className="flex flex-col gap-1.5">
                <span className="text-label-xs text-text-sub-600">{t("settings.api.baseUrl")}</span>
                <CopyField value={api.base_url} />
              </label>
              <label className="flex flex-col gap-1.5">
                <span className="text-label-xs text-text-sub-600">{t("settings.api.token")}</span>
                <CopyField value={api.token} secret />
              </label>
              <div className="mt-1 flex items-center gap-2.5">
                <Button variant="neutral" mode="stroke" size="small" onClick={regenToken}>
                  {t("settings.api.regenerate")}
                </Button>
                <span className="text-paragraph-xs text-text-soft-400">{t("settings.api.regenerateHelp")}</span>
              </div>
              <p className="m-0 text-paragraph-xs text-text-soft-400">
                Send it as <code>Authorization: Bearer &lt;token&gt;</code>.
              </p>
            </>
          )}
        </div>
      </SettingsCard>



      <SettingsCard title={t("settings.whatsNew.title")}>
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          <Rich text={t("settings.whatsNew.help")} />
        </p>
        <div className="flex items-center gap-2.5">
          <Button
            variant="neutral"
            mode="stroke"
            size="small"
            onClick={() => setSection("patchlog")}
          >
            {t("settings.whatsNew.view")}
          </Button>
          <span className="text-paragraph-xs text-text-soft-400">
            {t("settings.whatsNew.alsoInSidebar")}
          </span>
        </div>
      </SettingsCard>

      <div
        role="region"
        aria-label={t("settings.save.region")}
        className="sticky bottom-0 z-10 mt-2 flex items-center justify-between gap-3 rounded-lg bg-bg-white-0 px-4 py-3 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200"
      >
        <div className="flex flex-col gap-0.5">
          <strong className="text-label-xs text-text-strong-950">
            {dirty ? t("settings.save.dirty") : t("settings.save.clean")}
          </strong>
          {restartPending && (
            <span className="text-paragraph-xs text-warning-base">
              {t("settings.save.restartRequired")}
            </span>
          )}
        </div>
        <Button size="xsmall" onClick={save} disabled={!dirty}>{t("settings.save.button")}</Button>
      </div>
</section>
  );
}
