import { useEffect } from "react";
import { Button } from "@proxyshard/shardx-ui-kit";
import Badge, { type BadgeColor } from "../../../shared/ui/Badge";
import { RefreshIcon, WarningIcon } from "../../../shared/icons";
import { useProfile } from "../../../entities/profile";
import { useTeamProfiles, type TeamProfileStatus } from "../../../entities/team";
import { useT } from "../../../shared/i18n";

type BadgeKind = "local" | "available" | "checkedOutHere" | "leaseAtRisk" | "uploading" | "quarantined";

const BADGE_COLOR: Record<BadgeKind, BadgeColor> = {
  local: "gray",
  available: "success",
  checkedOutHere: "primary",
  leaseAtRisk: "warning",
  uploading: "information",
  quarantined: "error",
};

/** The badge a profile shows; null for states no production code writes yet. */
function badgeOf(b: TeamProfileStatus | undefined): BadgeKind | null {
  if (!b || b.sync_state === "LOCAL") return "local";
  if (b.sync_state === "QUARANTINED") return "quarantined";
  if (b.lease_at_risk) return "leaseAtRisk";
  if (b.sync_state === "UPLOADING") return "uploading";
  if (b.sync_state === "CHECKED_OUT") return "checkedOutHere";
  if (b.sync_state === "AVAILABLE") return "available";
  return null;
}

/** Each profile's binding state on this device, with the custodian alerts above it. */
export function TeamProfiles() {
  const t = useT();
  const profiles = useProfile((s) => s.profiles);
  const initProfiles = useProfile((s) => s.init);
  const status = useTeamProfiles((s) => s.status);
  const error = useTeamProfiles((s) => s.error);
  const busy = useTeamProfiles((s) => s.busy);
  const refresh = useTeamProfiles((s) => s.refresh);
  useEffect(() => { void initProfiles(); void refresh(); }, [initProfiles, refresh]);

  const bindings = new Map((status?.profiles ?? []).map((b) => [b.profile_id, b]));

  return (
    <div className="mb-3.5 flex flex-col gap-2.5">
      {status?.alerts.map((a) => (
        <p
          key={`${a.signing_key_id}-${a.raised_at_ms}`}
          role="alert"
          data-testid="team-alert"
          className="m-0 flex items-start gap-2 rounded-10 bg-warning-alpha-16 px-3 py-2 text-paragraph-xs text-text-sub-600"
        >
          <WarningIcon className="mt-px size-4 flex-none text-warning-base" />
          {t("team.alert.renewedAfterRevocation", { key: a.signing_key_id.slice(0, 8) })}
        </p>
      ))}
      {error && (
        <p role="alert" className="m-0 text-paragraph-xs text-error-base">{error}</p>
      )}

      <div className="overflow-hidden rounded-12 bg-bg-white-0 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
        <div className="flex items-center justify-between gap-3 border-b border-stroke-soft-200 bg-bg-weak-50 px-4 py-2">
          <span className="text-subheading-2xs text-text-soft-400">{t("common.profiles")}</span>
          <Button
            variant="neutral" mode="ghost" size="xsmall"
            leftIcon={<RefreshIcon className="size-4" />}
            disabled={busy}
            onClick={() => { void refresh(); }}
          >
            {t("team.refresh")}
          </Button>
        </div>
        {profiles.length === 0 && (
          <div className="px-4 py-6 text-center text-paragraph-xs text-text-soft-400">{t("profileTable.noProfilesYet")}</div>
        )}
        {profiles.map((p) => {
          const b = bindings.get(p.id);
          const kind = badgeOf(b);
          return (
            <div
              key={p.id}
              data-testid="team-profile"
              className="flex items-center justify-between gap-3 border-t border-stroke-soft-200 px-4 py-2.5 first:border-t-0"
            >
              <div className="min-w-0">
                <div className="truncate text-label-xs text-text-strong-950">{p.name}</div>
                <div className="mono truncate text-[11px] text-text-soft-400">{p.id.slice(0, 8)}</div>
              </div>
              {kind && (
                <div className="flex items-center gap-1.5">
                  <Badge color={BADGE_COLOR[kind]} variant="filled" size="small">{t(`team.badge.${kind}`)}</Badge>
                  {kind === "quarantined" && b?.last_error_code && (
                    <span className="mono text-[11px] text-text-soft-400">{b.last_error_code}</span>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
