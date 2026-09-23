import { Button } from "@proxyshard/shardx-ui-kit";
import {
  PinIconApp,
  EditIcon,
  CopyIcon,
  DeleteIcon,
  MoreIcon,
  PlayIcon,
  StopIcon,
} from "../../../shared/icons";
import { useProfile, type ProfileMeta } from "../../../entities/profile";
import { useMediaQuery, WIDE_ACTIONS_QUERY } from "../../../shared/hooks/useMediaQuery";
import { useT } from "../../../shared/i18n";

export function ProfileRowActions({ profile, onMore }: {
  profile: ProfileMeta;
  onMore: (e: React.MouseEvent) => void;
}) {
  const t = useT();
  const p = profile;
  const isRunning = useProfile((s) => !!s.running[p.id]);
  const isStarting = useProfile((s) => s.startBusy.has(p.id));
  const startStop = useProfile((s) => s.startStop);
  const togglePin = useProfile((s) => s.togglePin);
  const cloneProfile = useProfile((s) => s.cloneProfile);
  const remove = useProfile((s) => s.remove);
  const expand = useProfile((s) => s.expand);

  // Copy actions live here too so a wide window does not force a menu trip for
  // the URL an automation user grabs constantly.
  const copyCdp = useProfile((s) => s.copyCdpHttpUrl);
  const wide = useMediaQuery(WIDE_ACTIONS_QUERY);

  return (
    <div className="flex justify-end gap-1">
      <Button
        variant={isRunning ? "error" : "primary"}
        mode="lighter"
        size="xsmall"
        fullRadius
        className="min-w-[84px]"
        leftIcon={
          isRunning
            ? <StopIcon className="size-3.5" />
            : <span className={isStarting ? "spin-icon inline-grid place-items-center" : "inline-grid place-items-center"}><PlayIcon className="size-3.5" /></span>
        }
        onClick={() => startStop(p)}
        aria-label={`${isRunning ? "Stop" : "Start"} profile ${p.name}`}
        disabled={!isRunning && isStarting}
        title={!isRunning && isStarting ? "Starting (UDP probe + geo + spawn)…" : undefined}
      >
        {isRunning ? "Stop" : isStarting ? "Starting…" : "Start"}
      </Button>
      {wide && <Button
        variant={p.pinned ? "primary" : "neutral"}
        mode={p.pinned ? "lighter" : "stroke"}
        size="xsmall"
        onlyIcon
        onClick={() => togglePin(p)}
        aria-label={`${p.pinned ? "Unpin" : "Pin"} profile ${p.name}`}
        title={p.pinned ? "Unpin" : "Pin to top"}
        leftIcon={<PinIconApp className="size-4" />}
      >
      </Button>}
      <Button variant="neutral" mode="stroke" size="xsmall" onlyIcon onClick={() => expand(p.id)} title={t("common.edit")} aria-label={`Edit profile ${p.name}`}
        leftIcon={<EditIcon className="size-4" />}
      >
      </Button>
      {wide && <Button variant="neutral" mode="stroke" size="xsmall" onlyIcon onClick={() => cloneProfile(p.id)} title={t("common.clone")} aria-label={`Clone profile ${p.name}`}
        leftIcon={<CopyIcon className="size-4" />}
      >
      </Button>}
      {wide && <Button variant="error" mode='filled' size="xsmall" onlyIcon onClick={() => remove(p.id)} title={t("common.delete")} aria-label={`Delete profile ${p.name}`}
        leftIcon={<DeleteIcon className="size-4" />}
      >
      </Button>}
      {wide && <Button
        variant="neutral"
        mode="stroke"
        size="xsmall"
        onlyIcon
        onClick={() => { void copyCdp(p.id); }}
        aria-label={`Copy CDP HTTP URL for ${p.name}`}
        title={t("profile.copyCdpHttpUrl")}
        leftIcon={<CopyIcon className="size-4" />}
      >
      </Button>}
      <Button
        variant="neutral"
        mode="stroke"
        size="xsmall"
        onlyIcon
        onClick={onMore}
        aria-label={`More actions for profile ${p.name}`}
        title={t("profile.moreActions")}
        leftIcon={<MoreIcon className="size-4" />}
      >
      </Button>
    </div>
  );
}
