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
    try { setApi(await apiRegenerateToken()); toast.ok("Token regenerated"); }
    catch (e) { toast.err(String(e)); }
  };

  const [mcpBusy, setMcpBusy] = useState(false);
  // Download MCP server source; user manages install + client setup.
  const downloadMcp = async () => {
    const dir = await open({ directory: true, title: "Where to download the MCP server" });
    if (typeof dir !== "string") return;
    setMcpBusy(true);
    try {
      const path = await mcpDownload(dir);
      toast.ok(`MCP downloaded to ${path}`);
    } catch (e) { toast.err("MCP download failed: " + String(e)); }
    finally { setMcpBusy(false); }
  };
  // Adopt an MCP server the operator already has, instead of downloading a
  // duplicate copy next to it.
  const useExistingMcp = async () => {
    const dir = await open({ directory: true, title: "Select an existing ShardX MCP folder" });
    if (typeof dir !== "string") return;
    setMcpBusy(true);
    try {
      const status = await mcpSetPath(dir);
      setMcp(status);
      setMcpError(null);
      toast.ok(`Using MCP server at ${status.path ?? dir}`);
    } catch (e) { toast.err(safeUiError(e)); }
    finally { setMcpBusy(false); }
  };
  const save = async () => {
    try {
      await settingsSave(s);
      setBaseline({ ...s });
      // Saving is what registers the startup entry, so re-read the truth.
      await Promise.all([refreshApi(), refreshStartup()]);
      toast.ok("Settings saved");
    } catch (e) { toast.err(safeUiError(e)); }
  };

  const dirty = !!baseline && JSON.stringify(s) !== JSON.stringify(baseline);
  const restartPending =
    !!api && ((s.api_enabled ?? true) !== api.enabled || (s.api_port ?? 40325) !== api.port);
  return (
    <section className="flex flex-col">
      <Topbar crumbs={["System", "Settings"]} />
      <div className="mb-3.5 flex items-end justify-between gap-4">
        <h1 className="m-0 text-title-h5 text-text-strong-950">Settings</h1>
      </div>

      <SettingsCard title="Startup &amp; background services">
        <StartupCard settings={s} onChange={setS} status={startup} error={startupError} />
      </SettingsCard>

      <SettingsCard title="MCP server">
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
          Download the <strong>MCP</strong> server source (lets an AI client drive
          profiles and a CDP browser) into a folder you choose. The app does not run
          it — install its deps and register it with your MCP client per the included
          README. Requires Node.js.
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
            {mcpBusy ? "Downloading…" : "Download MCP server"}
          </Button>
          <Button
            variant="neutral"
            mode="stroke"
            size="small"
            onClick={useExistingMcp}
            disabled={mcpBusy}
          >
            Use existing MCP folder
          </Button>
        </div>
        {mcp?.path && (
          <p className="m-0 mt-2 text-paragraph-xs text-text-sub-600">
            Current folder: <code>{mcp.path}</code>
          </p>
        )}
      </SettingsCard>

      <SettingsCard title="Team">
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

      <SettingsCard title="Proxy geo checker">
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          Which free public IP-geo service to hit when you press the proxy <strong>Test</strong> button. All three are no-key, rate-limited.
        </p>
        <Select
          label="Provider"
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

      <SettingsCard title="Screen resolution">
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          <strong>From fingerprint</strong> reports the screen carried in the bound profile (recommended for anti-detect coherence).
          <strong> Real</strong> lets ShardX expose the host monitor's actual size.
        </p>
        <Select
          label="Mode"
          size="small"
          value={s.screen_resolution_mode ?? "fingerprint"}
          onChange={(v) => setS({ ...s, screen_resolution_mode: v })}
          options={[
            { value: "fingerprint", label: "From fingerprint" },
            { value: "real", label: "Real (host monitor)" },
          ]}
        />
      </SettingsCard>

      <SettingsCard title="Shard Helper">
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          Watches each page for fields a generated identity fits — names, email,
          phone, date of birth — and offers to fill them. It only ever
          <strong> offers</strong>: nothing is typed until you press the button
          on the panel that appears. Values come from the profile's own language,
          and go in through the same human typing the rest of the browser uses.
          <br />
          <strong>Never runs on a synchronised launch.</strong> In a group whatever
          you type in one window is mirrored into the others already, so a helper
          per window would find the same form ten times and offer ten prompts for
          one page.
        </p>
        <div className="flex flex-col gap-3">
          <Switch
            label="Enable Shard Helper"
            checked={s.helper_enabled ?? true}
            onChange={(checked) => setS({ ...s, helper_enabled: checked })}
          />
          {(s.helper_enabled ?? true) && (
            <div>
              <div className="mb-1.5 text-label-xs text-text-sub-600">
                React to
              </div>
              <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
                Nothing selected means every kind. Narrow it if the panel appears
                on forms you do not care about — a login page with an email field
                is still a form.
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

      <SettingsCard title="Profile camera">
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          The profile gets ShardX's camera instead of the machine's, and shows the
          picture or clip you pick from the control left of the browser's app menu.
          <strong> Leave this on.</strong> The profile's fingerprint already names a
          particular camera, so handing a page the host's real one contradicts the
          profile and identifies the machine behind every profile on it.
        </p>
        <Switch
          label="Substitute the camera"
          checked={s.camera_enabled ?? true}
          onChange={(checked) => setS({ ...s, camera_enabled: checked })}
        />
      </SettingsCard>

      <SettingsCard title="Profile data location">
        <DataRootCard />
      </SettingsCard>

      <SettingsCard title="Extra launch arguments">
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          Appended to every profile launch, one per line or space-separated.
          They go on <strong>last</strong>, so a switch repeated here is the one the
          engine sees — which is also how you get to undo one of the launcher's own.
          Quote a value with spaces.
          <br />
          Anything that changes what a page can measure belongs in the profile, not
          here: a switch applied to every profile at once makes them all alike, which
          is the opposite of what a profile is for.
        </p>
        <Textarea
          rows={3}
          className="mono"
          value={s.extra_args ?? ""}
          onChange={(e) => setS({ ...s, extra_args: e.target.value })}
          placeholder={"--disable-background-timer-throttling\n--window-size=1280,800"}
        />
      </SettingsCard>

      <SettingsCard title="Automation API">
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          Local HTTP API (axum) for scripting — create/launch/close profiles
          and get a CDP WebSocket URL. Binds <strong>127.0.0.1</strong> only,
          JWT Bearer auth. Changes to enable/port apply after restarting the app.{" "}
          <a
            href="#"
            className="text-primary-base hover:underline"
            onClick={(e) => {
              e.preventDefault();
              openUrl(withUtm("https://docs.proxyshard.com/eng/shardx-launcher-api/binding-and-lifecycle?fallback=true")).catch(() => {});
            }}
          >
            Full API reference →
          </a>
        </p>
        <div className="flex flex-col gap-3">
          <Switch
            label="Enable API server"
            checked={s.api_enabled ?? true}
            onChange={(checked) => setS({ ...s, api_enabled: checked })}
          />
          <Input
            label="Port"
            inputSize="small"
            type="number"
            value={s.api_port ?? 40325}
            onChange={(e) => setS({ ...s, api_port: Number(e.target.value) || 40325 })}
          />
          {api && (
            <>
              <label className="flex flex-col gap-1.5">
                <span className="text-label-xs text-text-sub-600">Base URL</span>
                <CopyField value={api.base_url} />
              </label>
              <label className="flex flex-col gap-1.5">
                <span className="text-label-xs text-text-sub-600">Bearer token</span>
                <CopyField value={api.token} secret />
              </label>
              <div className="mt-1 flex items-center gap-2.5">
                <Button variant="neutral" mode="stroke" size="small" onClick={regenToken}>
                  Regenerate token
                </Button>
                <span className="text-paragraph-xs text-text-soft-400">Invalidates the current token immediately.</span>
              </div>
              <p className="m-0 text-paragraph-xs text-text-soft-400">
                Send it as <code>Authorization: Bearer &lt;token&gt;</code>.
              </p>
            </>
          )}
        </div>
      </SettingsCard>



      <SettingsCard title="What's new">
        <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
          After an update the launcher opens the patch log once, so the changes
          get seen before they surprise anyone. This reopens it on demand —
          useful when that first run went by in a hurry, or when someone else
          installed the update on this machine.
        </p>
        <div className="flex items-center gap-2.5">
          <Button
            variant="neutral"
            mode="stroke"
            size="small"
            onClick={() => setSection("patchlog")}
          >
            View the update notes
          </Button>
          <span className="text-paragraph-xs text-text-soft-400">
            Also in the sidebar, under Patch log.
          </span>
        </div>
      </SettingsCard>

      <div
        role="region"
        aria-label="Settings save status"
        className="sticky bottom-0 z-10 mt-2 flex items-center justify-between gap-3 rounded-lg bg-bg-white-0 px-4 py-3 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200"
      >
        <div className="flex flex-col gap-0.5">
          <strong className="text-label-xs text-text-strong-950">
            {dirty ? "Unsaved changes" : "All changes saved"}
          </strong>
          {restartPending && (
            <span className="text-paragraph-xs text-warning-base">
              Restart required for Automation API changes
            </span>
          )}
        </div>
        <Button size="xsmall" onClick={save} disabled={!dirty}>Save settings</Button>
      </div>
</section>
  );
}
