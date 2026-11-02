import { useEffect } from "react";
import { Button } from "@proxyshard/shardx-ui-kit";
import Badge, { type BadgeColor } from "../../../shared/ui/Badge";
import { RefreshIcon, WarningIcon } from "../../../shared/icons";
import { useProfile } from "../../../entities/profile";
import { useTeamProfiles, type TeamProfileStatus, type TeamSyncState } from "../../../entities/team";
import { useT } from "../../../shared/i18n";

type BadgeKind =
  | "local" | "available" | "checkedOutHere" | "leaseAtRisk" | "uploading" | "quarantined" | "other";

const BADGE_COLOR: Record<BadgeKind, BadgeColor> = {
  local: "gray",
  available: "success",
  checkedOutHere: "primary",
  leaseAtRisk: "warning",
  uploading: "information",
  quarantined: "error",
  other: "gray",
};

// No production code writes OFFLINE_FORK, RESTORE_REQUIRED or CONFLICT yet, so they share a neutral badge.
const BADGE_OF_STATE: Record<TeamSyncState, BadgeKind> = {
  LOCAL: "local",
  AVAILABLE: "available",
  CHECKED_OUT: "checkedOutHere",
  LEASE_AT_RISK: "leaseAtRisk",
  UPLOADING: "uploading",
  QUARANTINED: "quarantined",
  OFFLINE_FORK: "other",
  RESTORE_REQUIRED: "other",
  CONFLICT: "other",
};

/** The quarantine reasons team/sync.rs writes; any other code is shown as is. */
const REASON_KEY: Record<string, string> = {
  SIGNER_REVOKED: "team.reason.signerRevoked",
  HEAD_ROLLBACK_DETECTED: "team.reason.headRollbackDetected",
  RESTORE_EPOCH_TRANSITION_REQUIRED: "team.reason.restoreEpochTransitionRequired",
  RESTORE_EPOCH_TRANSITION_INVALID: "team.reason.restoreEpochTransitionInvalid",
  RESTORE_EPOCH_PROOF_MISSING: "team.reason.restoreEpochProofMissing",
  RESTORE_EPOCH_CROSS_TENANT: "team.reason.restoreEpochCrossTenant",
  STORED_REQUEST_MISMATCH: "team.reason.storedRequestMismatch",
};

/** The badge a profile shows once the statuses are loaded; no binding means local. */
function badgeOf(b: TeamProfileStatus | undefined): BadgeKind {
  if (!b) return "local";
  if (b.sync_state !== "QUARANTINED" && b.lease_at_risk) return "leaseAtRisk";
  return BADGE_OF_STATE[b.sync_state];
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
          // Until the first read lands, a missing binding proves nothing.
          const kind = status ? badgeOf(b) : null;
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
                    <span className="text-[11px] text-text-soft-400">
                      {REASON_KEY[b.last_error_code] ? t(REASON_KEY[b.last_error_code]) : b.last_error_code}
                    </span>
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
