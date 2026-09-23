import { useState } from "react";
import { Button } from "@proxyshard/shardx-ui-kit";
import { clip } from "../../../shared/lib/clipboard";
import type { ApiInfo, McpStatus, CodexMcpStatus, HermesMcpStatus } from "../../../entities/settings";
import { useT } from "../../../shared/i18n";

/// MCP readiness, plus the single honest Codex action for the current state.
///
/// Every prerequisite is listed separately: "not working" is not useful when
/// four different things can be missing.
///
/// Codex and Hermes are reported side by side: either can host this MCP
/// server, so a problem in one must not be drawn as a global failure.
export function McpCard({
  status,
  statusError,
  codex,
  codexError,
  hermes,
  hermesError,
  api,
  onRefresh,
  onCheckCodex,
  onCheckHermes,
}: {
  status: McpStatus | null;
  statusError: string | null;
  codex: CodexMcpStatus | null;
  codexError: string | null;
  hermes: HermesMcpStatus | null;
  hermesError: string | null;
  api: ApiInfo | null;
  onRefresh: () => Promise<void>;
  onCheckCodex: () => Promise<void>;
  onCheckHermes: () => Promise<void>;
}) {
  const t = useT();
  const [busy, setBusy] = useState(false);
  const [advanced, setAdvanced] = useState(false);

  const filesDownloaded = !!status?.files_downloaded;
  const ready = !!status?.ready;
  const versionLabel = status?.version ? `v${status.version}` : "Unknown";
  const requiredLabel = status?.required_version ? `v${status.required_version}` : "this Launcher";
  const runtimeApiUrl = api?.runtime_base_url ?? api?.base_url ?? "";
  const hermesChecked = !!hermes || !!hermesError;

  const copyRepair = async () => {
    if (codex?.repair_command) await clip.write(codex.repair_command);
  };

  // Built from the same values the Rust side compares against, so the copied
  // command repairs exactly the mismatch that was reported.
  const hermesAddCommand = () => {
    const index = hermes?.expected_index_path ?? hermes?.index_path ?? "";
    const apiUrl = hermes?.expected_api ?? "";
    return `hermes mcp remove shardbrowser; hermes mcp add shardbrowser --env "SHARDX_API=${apiUrl}" --command node --args "${index}"`;
  };

  const copyHermesAdd = async () => {
    await clip.write(hermesAddCommand());
  };

  const run = async (fn: () => Promise<void>) => {
    setBusy(true);
    try { await fn(); } finally { setBusy(false); }
  };

  const hermesNeedsRepair =
    hermes?.state === "needs_repair" || hermes?.state === "disabled";

  // One primary action, chosen by what is actually missing. Hermes is the
  // primary host, so its check leads; Codex stays available under Advanced.
  const primary = !hermesChecked
    ? { label: busy ? "Checking Hermes…" : "Check Hermes registration", run: onCheckHermes }
    : hermesNeedsRepair || hermes?.state === "not_registered"
      ? { label: "Copy Hermes add command", run: copyHermesAdd }
      : { label: busy ? "Refreshing…" : "Refresh status", run: onRefresh };

  const items: [boolean, string, string][] = [
    [filesDownloaded, "Files downloaded", filesDownloaded ? "Detected" : "Not detected"],
    [
      !!status?.version_current,
      "Version current",
      status?.version_current ? versionLabel : filesDownloaded ? `${versionLabel}; repair to ${requiredLabel}` : "No files yet",
    ],
    [
      !!status?.dependencies_installed,
      "Dependencies installed",
      status?.dependencies_installed ? "node_modules ready" : status?.lockfile_present ? "npm ci required" : "Legacy setup: npm install required",
    ],
    [
      !!status?.api_reachable,
      "API reachable",
      status?.api_reachable ? runtimeApiUrl : api?.error ? "Bind failed" : "Unavailable",
    ],
  ];

  return (
    <div className="flex flex-col gap-3">
      <div role={statusError ? "alert" : "status"} className="flex flex-col gap-0.5">
        <strong className="text-label-xs text-text-strong-950">
          {!status
            ? "Checking MCP status"
            : ready
              ? "MCP ready"
              : status.state === "update_available"
                ? "MCP update available"
                : status.state === "missing"
                  ? "MCP folder missing"
                  : filesDownloaded
                    ? "MCP setup incomplete"
                    : "MCP server not downloaded"}
        </strong>
        <span className="text-paragraph-xs text-text-sub-600">
          {statusError ?? status?.message ?? "Checking MCP status…"}
        </span>
      </div>

      <div aria-label={t("settings.mcpSetupReadiness")} className="grid gap-2 sm:grid-cols-2">
        {items.map(([ok, label, detail]) => (
          <div key={label} className="flex flex-col gap-0.5 rounded-lg bg-bg-weak-50 px-3 py-2">
            <strong className="text-label-xs text-text-strong-950">{ok ? "✓" : "○"} {label}</strong>
            <span className="text-paragraph-xs text-text-sub-600">{detail}</span>
          </div>
        ))}
      </div>

      {codex && codex.issues.length > 0 && (
        <p className="m-0 text-paragraph-xs text-text-sub-600">
          {codex.issues.join("; ")}. Use <strong>Copy Codex repair command</strong>, restart Codex,
          then run <code>health_check</code>.
        </p>
      )}
      {codexError && (
        <p className="m-0 text-paragraph-xs text-text-sub-600">{codexError}</p>
      )}

      <div className="flex flex-col gap-0.5 rounded-lg bg-bg-weak-50 px-3 py-2">
        <strong className="text-label-xs text-text-strong-950">
          {hermes?.ready ? "✓" : "○"} Hermes registration
        </strong>
        <span className="text-paragraph-xs text-text-sub-600">
          {hermesError
            ? hermesError
            : hermes
              ? hermes.message
              : "Not checked yet"}
        </span>
      </div>

      {hermes && hermes.issues.length > 0 && (
        <p className="m-0 text-paragraph-xs text-text-sub-600">
          {hermes.issues.join("; ")}. Use <strong>Copy Hermes add command</strong>, restart Hermes,
          then run <code>health_check</code>.
        </p>
      )}

      <div className="flex flex-wrap items-center gap-2">
        <Button size="xsmall" disabled={busy} onClick={() => void run(primary.run)}>
          {primary.label}
        </Button>
      </div>

      <details open={advanced} onToggle={(e) => setAdvanced((e.target as HTMLDetailsElement).open)}>
        <summary className="cursor-pointer text-label-xs text-text-sub-600">Advanced actions</summary>
        <div className="mt-2 flex flex-col gap-2">
          <Button size="xsmall" variant="neutral" mode="stroke" onClick={copyRepair} disabled={!codex?.repair_command}>
            {t("settings.copyCodexRepairCommand")}
          </Button>
          <Button size="xsmall" variant="neutral" mode="stroke" disabled={busy} onClick={() => void run(onCheckCodex)}>
            {busy ? "Checking Codex…" : "Check Codex registration"}
          </Button>
          {primary.label !== "Copy Hermes add command" && (
            <Button size="xsmall" variant="neutral" mode="stroke" onClick={copyHermesAdd} disabled={!hermesChecked}>
              {t("settings.copyHermesAddCommand")}
            </Button>
          )}
          <p className="m-0 text-paragraph-xs text-text-sub-600">
            {t("settings.theCommandIsCopiedForYouToRunNoConfi")}
          </p>
        </div>
      </details>
    </div>
  );
}
