import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { open } from "@tauri-apps/plugin-dialog";
import { openPath } from "@tauri-apps/plugin-opener";
import { Button, ProgressBar } from "@proxyshard/shardx-ui-kit";
import { FolderIcon } from "../../../shared/icons";
import { toast } from "../../../shared/model/toast";
import { confirmModal } from "../../../shared/lib/confirm";
import {
  dataRootGet, dataRootMigrate,
  type DataRootInfo, type MigrationProgress,
} from "../../../entities/settings";
import { useT } from "../../../shared/i18n";
import { safeUiError } from "../../../shared/lib/utils";

// Keys, not translated text: this table is built once when the module loads,
// so holding finished strings would pin the card to whichever language
// happened to be active at startup.
const PHASE_KEY: Record<MigrationProgress["phase"], string> = {
  scan: "dataRoot.phaseScan",
  copy: "profile.copying",
  verify: "dataRoot.phaseVerify",
  cleanup: "dataRoot.phaseCleanup",
  done: "profile.done",
};

/** Where profiles, user-data, extensions and the trash live. The move copies,
 *  verifies, then deletes; the backend refuses launches while it runs. */
export function DataRootCard() {
  const t = useT();
  const [info, setInfo] = useState<DataRootInfo | null>(null);
  const [progress, setProgress] = useState<MigrationProgress | null>(null);

  const refresh = () => dataRootGet().then(setInfo).catch(() => {});
  useEffect(() => { refresh(); }, []);

  useEffect(() => {
    let un: (() => void) | undefined;
    let disposed = false;
    listen<MigrationProgress>("data-migration", (e) => {
      setProgress(e.payload.phase === "done" ? null : e.payload);
    }).then((fn) => { if (disposed) fn(); else un = fn; });
    return () => { disposed = true; un?.(); };
  }, []);

  const running = progress !== null;

  const move = async () => {
    const dir = await open({ directory: true, title: t("dataRoot.pickFolderTitle") });
    if (typeof dir !== "string") return;
    const ok = await confirmModal({
      title: t("profile.moveProfileData"),
      message: t("dataRoot.moveAsk", { dir }),
      buttons: [
        { label: t("common.cancel"), value: false },
        { label: t("profile.move"), value: true, primary: true },
      ],
    });
    if (ok !== true) return;
    setProgress({ phase: "scan", done: 0, total: 0, percent: 0, current: "" });
    try {
      const n = await dataRootMigrate(dir);
      toast.ok(t(n === 1 ? "dataRoot.movedOne" : "dataRoot.movedMany", { n }));
    } catch (e) {
      toast.err(safeUiError(e));
    } finally {
      setProgress(null);
      refresh();
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <p className="m-0 text-paragraph-xs text-text-soft-400">
        {t("profile.profilesTheirUserDataDirsTheExtensio")}
      </p>

      <label className="flex flex-col gap-1.5">
        <span className="text-label-xs text-text-sub-600">
          {t("dataRoot.currentLocation")}
          {info && !info.custom && (
            <span className="text-text-soft-400">{t("dataRoot.defaultSuffix")}</span>
          )}
        </span>
        <div className="flex items-center gap-2">
          <span className="mono min-w-0 flex-1 truncate rounded-8 bg-bg-weak-50 px-[11px] py-[9px] text-paragraph-xs text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200">
            {info?.path ?? "…"}
          </span>
          <Button
            variant="neutral" mode="stroke" size="small" disabled={!info || running}
            onClick={() => info && openPath(info.path).catch(() => toast.err(t("profile.couldNotOpenThatFolder")))}
          >
            {t("profile.reveal")}
          </Button>
          <Button
            variant="primary" mode="stroke" size="small" disabled={running}
            leftIcon={<FolderIcon className="size-4" />}
            onClick={move}
          >
            Change…
          </Button>
        </div>
      </label>

      {progress && (
        <div className="flex flex-col gap-1.5 rounded-8 bg-bg-weak-50 p-3 ring-1 ring-inset ring-stroke-soft-200">
          <div className="flex items-baseline justify-between gap-3">
            <span className="text-label-xs text-text-strong-950">
              {t(PHASE_KEY[progress.phase])}
            </span>
            <span className="mono text-paragraph-xs text-text-soft-400">
              {progress.total > 0 ? `${progress.done} / ${progress.total}` : ""}
            </span>
          </div>
          <ProgressBar value={progress.percent} max={100} />
          {progress.current && (
            <span className="mono truncate text-[10.5px] text-text-disabled-300">
              {progress.current}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
