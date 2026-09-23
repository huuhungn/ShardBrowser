import { useEffect, useRef, useState, type ReactNode } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { Alert, Button, ProgressBar } from "@proxyshard/shardx-ui-kit";
import type { RtStatus, RtProgress } from "../../shared/types";
import { useT } from "../../shared/i18n";

export function FirstRunGate({ children }: { children: ReactNode }) {
  const t = useT();
  // null = querying backend; true = reveal; false = show overlay.
  const [installed, setInstalled] = useState<boolean | null>(null);
  const [prog, setProg] = useState<RtProgress | null>(null);
  const [err, setErr] = useState<string | null>(null);
  // Bumped to re-run the check; a failed setup must be retryable.
  const [attempt, setAttempt] = useState(0);
  // Single in-flight check at a time, so an impatient double-click on Retry
  // does not start two downloads.
  const checking = useRef(false);
  // Single in-flight install at a time.
  const installing = useRef(false);

  const fmt = (b: number) =>
    b < 1024 * 1024 ? `${(b / 1024).toFixed(0)} KB` : `${(b / (1024 * 1024)).toFixed(1)} MB`;

  useEffect(() => {
    let cancelled = false;
    let unProg: (() => void) | undefined;
    let unDone: (() => void) | undefined;
    if (checking.current) return;
    checking.current = true;

    // Plain-browser dev (vite without Tauri): no IPC — skip the gate so the
    // UI can be previewed; launch attempts will surface their own errors.
    if (!("__TAURI_INTERNALS__" in window)) {
      setInstalled(true);
      return;
    }

    (async () => {
      // Subscribe BEFORE invoking so we don't miss the first event.
      unProg = await listen<RtProgress>("runtime:progress", (e) => {
        if (!cancelled) setProg(e.payload);
      });
      unDone = await listen("runtime:done", () => {
        if (!cancelled) { setProg(null); setInstalled(true); }
      });

      let status: RtStatus;
      try {
        status = await invoke<RtStatus>("runtime_status");
      } catch (e: any) {
        if (!cancelled) { setErr(String(e)); setInstalled(false); }
        checking.current = false;
        return;
      }
      if (cancelled) return;

      // Unsupported platform: let the user in; launch will error if attempted.
      if (!status.spec) {
        setInstalled(true);
        checking.current = false;
        return;
      }
      // Reveal only when the engine + fingerprints are installed AND up to
      // date. An available engine update (chromium version bump) falls through
      // to the install path below, which re-downloads the changed archives.
      if (status.installed && status.fingerprints_installed && !status.update_available) {
        setInstalled(true);
        checking.current = false;
        return;
      }

      setInstalled(false);
      if (installing.current) return;
      installing.current = true;
      try {
        await invoke<RtStatus>("runtime_install", { force: false });
        if (!cancelled) setInstalled(true);
      } catch (e: any) {
        if (!cancelled) setErr(typeof e === "string" ? e : (e?.message ?? String(e)));
      } finally {
        installing.current = false;
        checking.current = false;
      }
    })();

    return () => {
      cancelled = true;
      unProg?.();
      unDone?.();
    };
  }, [attempt]);

  if (installed === null) {
    return null;
  }
  if (installed) {
    return <>{children}</>;
  }

  return (
    <div className="fixed inset-0 z-1000 flex items-center justify-center bg-bg-weak-50 text-text-strong-950">
      <div className="w-[460px] px-9 py-8 text-center">
        <div className="mb-2 text-title-h6">{t("firstRun.settingUpShardXBrowser")}</div>
        <div className="mb-6 text-paragraph-xs text-text-soft-400">
          {t("firstRun.firstRunDownloadFromOurCdnDoneOncePe")}
          (~{prog?.total ? fmt(prog.total) : "150 MB"}).
        </div>

        {prog && (
          <>
            <div className="mb-1.5 text-left text-paragraph-xs text-text-soft-400">
              {prog.label} —{" "}
              {prog.phase === "download"
                ? `${fmt(prog.received)} / ${fmt(prog.total)}  (${prog.percent}%)`
                : "extracting…"}
            </div>
            <ProgressBar value={prog.percent} color="primary" />
          </>
        )}
        {!prog && !err && (
          <div className="text-paragraph-xs text-text-soft-400">Contacting CDN…</div>
        )}
        {err && (
          <div className="mt-3">
            <Alert status="error" variant="light" className="text-left">
              Setup failed. {err}
            </Alert>
            <Button
              variant="neutral"
              mode="stroke"
              size="xsmall"
              className="mt-3"
              onClick={() => {
                // Ignored while a check is still running, so double-clicking
                // Retry cannot launch two downloads.
                if (checking.current) return;
                setErr(null);
                setProg(null);
                setAttempt((n) => n + 1);
              }}
            >
              {t("firstRun.retrySetup")}
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
