import { useEffect, useRef, useState } from "react";
import { Channel, invoke } from "@tauri-apps/api/core";
import { Alert, Button, Modal, ProgressBar, cn } from "@proxyshard/shardx-ui-kit";
import { safeUiError } from "../../shared/lib/utils";
import { ShardMini } from "../../shared/icons";
import type { RtUpdate } from "../../shared/types";
import { useT } from "../../shared/i18n";

/// Sidebar status and consent surface for signed Tauri updates.
///
/// An update is never downloaded or installed without an explicit click:
/// the Launcher runs browser profiles, so a silent swap of the binary is
/// not something the user should discover after the fact.
type UpdatePhase =
  | "checking"
  | "up_to_date"
  | "available"
  | "downloading"
  | "ready"
  | "installing"
  | "error";

type UpdateDownloadEvent =
  | { event: "started"; data: { content_length: number | null } }
  | { event: "progress"; data: { chunk_length: number } }
  | { event: "finished" };

export function UpdaterPill() {
  const t = useT();
  const [info, setInfo] = useState<RtUpdate | null>(null);
  const [phase, setPhase] = useState<UpdatePhase>("checking");
  const [open, setOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<{ received: number; total: number | null }>({
    received: 0,
    total: null,
  });
  const trigger = useRef<HTMLButtonElement>(null);

  const check = () => {
    setPhase("checking");
    setError(null);
    setProgress({ received: 0, total: null });
    invoke<RtUpdate>("launcher_update_check")
      .then((next) => {
        setInfo(next);
        setPhase(next.update_available ? "available" : "up_to_date");
      })
      .catch((e) => {
        setError(safeUiError(e));
        setPhase("error");
      });
  };

  useEffect(check, []);

  const busy = phase === "downloading" || phase === "installing";

  const close = () => {
    // Never abandon an in-flight download/install: the binary is mid-swap.
    if (busy) return;
    setOpen(false);
    // Returning focus to the pill keeps the dialog usable from the keyboard.
    trigger.current?.focus();
  };

  const download = async () => {
    setPhase("downloading");
    setError(null);
    setProgress({ received: 0, total: null });
    const events = new Channel<UpdateDownloadEvent>();
    events.onmessage = (event) => {
      if (event.event === "started") {
        setProgress({ received: 0, total: event.data.content_length });
      } else if (event.event === "progress") {
        setProgress((c) => ({ ...c, received: c.received + event.data.chunk_length }));
      }
    };
    try {
      await invoke("launcher_update_download", { onEvent: events });
      setPhase("ready");
    } catch (e) {
      // Signature failures land here; they must stay on screen, not in a toast.
      setError(safeUiError(e));
      setPhase("error");
    }
  };

  const install = async () => {
    setPhase("installing");
    setError(null);
    try {
      await invoke("launcher_update_install");
      await invoke("launcher_update_restart");
    } catch (e) {
      setError(safeUiError(e));
      setPhase("error");
    }
  };

  const percent =
    progress.total && progress.total > 0
      ? Math.min(100, Math.round((progress.received / progress.total) * 100))
      : null;

  const statusText =
    phase === "checking"
      ? "checking for updates…"
      : phase === "available"
        ? `Update available → ${info?.latest}`
        : phase === "downloading"
          ? percent === null
            ? "downloading update…"
            : `downloading… ${percent}%`
          : phase === "ready"
            ? "ready to install"
            : phase === "installing"
              ? "installing update…"
              : phase === "error"
                ? "update check needs attention"
                : "up to date";

  return (
    <>
      <button
        ref={trigger}
        type="button"
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={() => setOpen(true)}
        title={`ShardX Launcher update status: ${statusText}`}
        className={cn(
          "flex w-full cursor-pointer items-center gap-2.5 rounded-lg border border-transparent bg-transparent px-2.5 py-2 text-left text-text-strong-950 transition-colors hover:bg-bg-weak-50",
          (phase === "available" || phase === "ready") &&
            "border-warning-base/40 bg-warning-alpha-16 hover:border-warning-base",
          phase === "error" && "border-error-base/40 bg-error-alpha-16",
        )}
      >
        <span className="text-icon-strong-950"><ShardMini /></span>
        <div className="flex min-w-0 flex-col">
          <div className="text-label-xs">ShardX Launcher v{info?.current ?? "…"}</div>
          <div className="text-paragraph-xs text-text-soft-400" aria-live="polite">{statusText}</div>
        </div>
      </button>

      <Modal
        open={open}
        onClose={close}
        title={t("updater.shardxLauncherUpdate")}
        maxWidthClassName="max-w-md"
        showClose={!busy}
      >
        <div className="flex flex-col gap-3 px-5 py-4" aria-busy={busy}>
          <div className="text-paragraph-sm text-text-sub-600">
            Installed v{info?.current ?? "…"}
            {info?.latest ? ` · latest v${info.latest}` : ""}
          </div>

          {phase === "up_to_date" && (
            <p className="m-0 text-paragraph-sm text-text-sub-600">
              {t("updater.launcherIsUpToDate")}
            </p>
          )}

          {info?.notes && (
            <pre className="m-0 max-h-40 overflow-auto whitespace-pre-wrap rounded-lg bg-bg-weak-50 p-3 text-paragraph-xs text-text-sub-600">
              {info.notes}
            </pre>
          )}

          {phase === "downloading" && (
            <ProgressBar
              value={percent ?? 0}
              aria-label={t("updater.downloadLauncherUpdate")}
            />
          )}

          {phase === "ready" && (
            <Alert status="success" variant="light">
              {t("updater.signatureVerifiedReadyToInstall")}
            </Alert>
          )}

          {phase === "error" && error && (
            <Alert status="error" variant="light">
              Update could not be completed: {error}
            </Alert>
          )}
        </div>

        <div className="flex justify-end gap-2 px-5 pb-5">
          {(phase === "available" || (phase === "error" && info?.update_available)) && (
            <Button size="xsmall" onClick={download}>Download update</Button>
          )}
          {phase === "ready" && (
            <Button size="xsmall" onClick={install}>Install and restart</Button>
          )}
          {phase === "up_to_date" && (
            <Button size="xsmall" variant="neutral" mode="stroke" onClick={check}>
              {t("updater.checkAgain")}
            </Button>
          )}
          {phase === "error" && !info?.update_available && (
            <Button size="xsmall" variant="neutral" mode="stroke" onClick={check}>
              {t("common.retry")}
            </Button>
          )}
        </div>
      </Modal>
    </>
  );
}
