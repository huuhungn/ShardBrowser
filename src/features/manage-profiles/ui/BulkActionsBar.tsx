import { Button } from "@proxyshard/shardx-ui-kit";
import {
  PlayIcon,
  StopIcon,
  UploadIcon,
  DeleteIcon,
  SyncIcon,
  LockedIcon,
} from "../../../shared/icons";
import { useProfile } from "../../../entities/profile";
import { useNav } from "../../../shared/model/navigation";
import { useT } from "../../../shared/i18n";

export function BulkActionsBar() {
  const t = useT();
  const count = useProfile((s) => s.selected.size);
  const bulkLaunch = useProfile((s) => s.bulkLaunch);
  const goToPatchLog = useNav((s) => s.setSection);
  const bulkStop = useProfile((s) => s.bulkStop);
  const bulkExport = useProfile((s) => s.bulkExport);
  const bulkDelete = useProfile((s) => s.bulkDelete);
  const clearSelected = useProfile((s) => s.clearSelected);

  if (count === 0) return null;

  return (
    <div className="flex items-center gap-2 rounded-8 bg-primary-alpha-10 py-1 pl-3 pr-1 text-label-xs text-primary-base ring-1 ring-inset ring-primary-alpha-24">
      <span>{count} selected</span>
      <Button variant="neutral" mode='stroke' className="pr-4" size="2xsmall" leftIcon={<PlayIcon className="size-3.5" />} onClick={bulkLaunch}>Launch</Button>
      {/* Meaningless for a single profile, so it only appears for a group.
          Locked for now — the button explains itself in the patch log. */}
      {count >= 2 && (
        <Button
          variant="neutral"
          mode="stroke"
          className="pr-4"
          size="2xsmall"
          title={t("profile.notReleasedYetReadWhyInThePatchLog")}
          leftIcon={<LockedIcon className="size-3.5" />}
          onClick={() => goToPatchLog("patchlog")}
        >
          <span className="inline-flex items-center gap-1.5">
            <SyncIcon className="size-3.5" />
            {t("profile.launchSynced")}
          </span>
        </Button>
      )}
      <Button variant="neutral" mode="stroke" className="pr-2" size="2xsmall" leftIcon={<StopIcon className="size-3.5" />} onClick={bulkStop}>Stop</Button>
      <Button variant="neutral" mode="stroke" className="pl-2" size="2xsmall" leftIcon={<UploadIcon className="size-3.5" />} onClick={bulkExport}>Export</Button>
      <Button variant="error" mode="stroke" className="pr-2" size="2xsmall" leftIcon={<DeleteIcon className="size-3.5" />} onClick={bulkDelete}>Delete</Button>
      <Button variant="neutral" mode="ghost" className="pr-2" size="2xsmall" onClick={clearSelected}>Clear</Button>
    </div>
  );
}
