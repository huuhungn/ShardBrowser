import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import { Button } from "@proxyshard/shardx-ui-kit";
import { DownloadIcon } from "../../shared/icons";
import { toast } from "../../shared/model/toast";
import { t } from "../../shared/i18n";
import { safeUiError } from "../../shared/lib/utils";

export function DownloadMcp() {
  const [mcpBusy, setMcpBusy] = useState(false);

  const downloadMcp = async () => {
    const dir = await open({ directory: true, title: t("mcp.whereToDownloadTheMcpServer") });
    if (typeof dir !== "string") return;
    setMcpBusy(true);
    try {
      const p = await invoke<string>("mcp_download", { dir });
      toast.ok(t("mcp.downloadedTo", { path: p }));
    } catch (e) {
      toast.err(t("mcp.mcpDownloadFailed") + safeUiError(e));
    } finally {
      setMcpBusy(false);
    }
  };

  return (
    <Button
      variant="primary"
      mode="lighter"
      size="xsmall"
      className="w-full"
      isLoading={mcpBusy}
      leftIcon={<DownloadIcon className="size-4" />}
      onClick={downloadMcp}
    >
      {mcpBusy ? "Downloading…" : t("mcp.downloadMCP")}
    </Button>
  );
}
