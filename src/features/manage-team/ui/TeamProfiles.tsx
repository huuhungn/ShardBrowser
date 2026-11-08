import { useEffect, useState } from "react";
import { Button, Input } from "@proxyshard/shardx-ui-kit";
import Badge, { type BadgeColor } from "../../../shared/ui/Badge";
import { RefreshIcon, WarningIcon } from "../../../shared/icons";
import { defaultForm, profileDelete, profileSave, toStored, useProfile } from "../../../entities/profile";
import {
  useTeamProfiles, teamProfilesStatus, teamFleetProfiles, teamJoinProfile,
  teamPublishProfile, teamCancelPublish, teamCheckIn, teamPull, teamRevert, teamUnbindProfile,
  type TeamProfileStatus, type TeamFleetProfile, type TeamSyncState,
} from "../../../entities/team";
import { toast } from "../../../shared/model/toast";
import { confirmModal } from "../../../shared/model/confirm";
import { safeUiError } from "../../../shared/lib/utils";
import { t as tNow, useT } from "../../../shared/i18n";

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

// The refusals a publish meets on its stored request, which only a cancel clears (team/sync.rs `send_publish`).
const CANCELLABLE_PUBLISH = [
  "sync.commitBlockedCompromised", "sync.noVerifiedFleetKey", "sync.fleetKeyRecollect",
  "sync.publishPendingElsewhere", "sync.storedRequestMismatch",
];

const ask = (title: string, message: string, confirm: string) =>
  confirmModal({
    title,
    message,
    buttons: [
      { label: tNow("common.cancel"), value: false },
      { label: confirm, value: true, danger: true },
    ],
  }).then((v) => v === true);

/** Each profile's binding state and team actions, with the custodian alerts above it. */
export function TeamProfiles() {
  const t = useT();
  const profiles = useProfile((s) => s.profiles);
  const initProfiles = useProfile((s) => s.init);
  const reloadProfiles = useProfile((s) => s.reload);
  const status = useTeamProfiles((s) => s.status);
  const error = useTeamProfiles((s) => s.error);
  const busy = useTeamProfiles((s) => s.busy);
  const refresh = useTeamProfiles((s) => s.refresh);
  useEffect(() => { void initProfiles(); void refresh(); }, [initProfiles, refresh]);

  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [acting, setActing] = useState<string | null>(null);
  // A publish refused here may have left a stored request behind; status does
  // not report one, so Cancel is offered where this session saw it refused.
  const [publishRefused, setPublishRefused] = useState<Set<string>>(new Set());
  const [fleet, setFleet] = useState<TeamFleetProfile[] | null>(null);

  const bindings = new Map((status?.profiles ?? []).map((b) => [b.profile_id, b]));
  const signedIn = !!username.trim() && !!password;

  /** Run one action; status is refetched after every one, failed or not. */
  const run = async (key: string, fn: (pw: string) => Promise<string | void>, needsLogin = true) => {
    // Cleared before a call that logs in, so a failed attempt does not keep it either.
    const typed = password;
    if (needsLogin) setPassword("");
    setActing(key);
    try {
      const done = await fn(typed);
      if (done) toast.ok(done);
    } catch (e) {
      toast.err(safeUiError(e));
    } finally {
      setActing(null);
      await refresh();
    }
  };

  const publish = (id: string) => run(`publish:${id}`, async (pw) => {
    try {
      await teamPublishProfile(id, username.trim(), pw);
    } catch (e) {
      if (CANCELLABLE_PUBLISH.some((c) => String(e).includes(c))) setPublishRefused((s) => new Set(s).add(id));
      throw e;
    }
    setPublishRefused((s) => { const n = new Set(s); n.delete(id); return n; });
    return t("team.action.published");
  });

  const cancelPublish = (id: string) => run(`cancel:${id}`, async () => {
    await teamCancelPublish(id);
    setPublishRefused((s) => { const n = new Set(s); n.delete(id); return n; });
    return t("team.action.publishCancelled");
  }, false);

  /** A sync the server refused under a rotated fleet key collected the new key and ran again. */
  const collected = (r: { collected_generation?: number } | null) => {
    if (r?.collected_generation != null) toast.info(t("team.fleetKeyCollected", { n: r.collected_generation }));
  };

  const checkIn = (id: string) => run(`checkIn:${id}`, async (pw) => {
    collected(await teamCheckIn(id, username.trim(), pw));
    return t("team.action.checkedIn");
  });

  const pull = (id: string) => run(`pull:${id}`, async (pw) => {
    await teamPull(id, username.trim(), pw);
    return t("team.action.pulled");
  });

  const revert = async (id: string) => {
    if (!(await ask(t("team.action.revertTitle"), t("team.action.revertConfirm"), t("team.action.revert")))) return;
    await run(`revert:${id}`, async (pw) => {
      collected(await teamRevert(id, username.trim(), pw));
      return t("team.action.reverted");
    });
  };

  const unbind = async (id: string) => {
    if (!(await ask(t("team.action.unbindTitle"), t("team.action.unbindConfirm"), t("team.action.unbind")))) return;
    await run(`unbind:${id}`, async () => {
      await teamUnbindProfile(id);
      setFleet((f) => f?.map((x) => (x.bound_to === id ? { ...x, bound_to: null } : x)) ?? null);
      return t("team.action.unbound");
    }, false);
  };

  const listFleet = () => run("fleet", async (pw) => {
    setFleet(await teamFleetProfiles(username.trim(), pw));
  });

  const join = (f: TeamFleetProfile) => run(`join:${f.remote_profile_id}`, async (pw) => {
    const fallback = t("team.join.unnamed", { id: f.remote_profile_id.slice(0, 8) });
    const create = (name: string) => profileSave(toStored({ ...defaultForm(), name }, null));
    // A label the launcher refuses as a name (taken, say, after an unbind)
    // falls back once to a name the remote id keeps unique.
    const created = await create(f.label?.trim() || fallback)
      .catch(() => create(t("team.join.unnamed", { id: f.remote_profile_id.slice(0, 16) })));
    try {
      await teamJoinProfile(f.remote_profile_id, created.id, username.trim(), pw);
    } catch (e) {
      // Only a profile no binding names is ours to remove; once bound, the
      // first pull failed and a retry pulls into it (plan §3).
      const after = await teamProfilesStatus().catch(() => null);
      if (after && !after.profiles.some((b) => b.profile_id === created.id)) {
        await profileDelete(created.id).catch((d) => toast.err(safeUiError(d)));
      }
      throw e;
    } finally {
      await reloadProfiles();
    }
    setFleet((l) => l?.map((x) => (x.remote_profile_id === f.remote_profile_id ? { ...x, bound_to: created.id } : x)) ?? null);
    return t("team.join.done", { name: created.name });
  });

  const action = (key: string, label: string, onClick: () => void, needsLogin = true) => (
    <Button
      variant="neutral" mode="stroke" size="xsmall"
      disabled={!!acting || (needsLogin && !signedIn)}
      onClick={onClick}
      aria-busy={acting === key || undefined}
    >
      {label}
    </Button>
  );

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

      <div data-testid="team-account" className="flex flex-col gap-2 rounded-12 bg-bg-white-0 px-4 py-3 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          <Input
            label={t("team.accountUsername")}
            inputSize="small"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <Input
            label={t("team.accountPassword")}
            inputSize="small"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <p className="m-0 text-paragraph-xs text-text-soft-400">{t("team.account.hint")}</p>
      </div>

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
          // Until the first read lands, a missing binding proves nothing: no badge, no actions.
          const kind = status ? badgeOf(b) : null;
          const bound = !!b && b.sync_state !== "LOCAL";
          const quarantined = b?.sync_state === "QUARANTINED";
          return (
            <div
              key={p.id}
              data-testid="team-profile"
              className="flex flex-wrap items-center justify-between gap-3 border-t border-stroke-soft-200 px-4 py-2.5 first:border-t-0"
            >
              <div className="min-w-0">
                <div className="truncate text-label-xs text-text-strong-950">{p.name}</div>
                <div className="mono truncate text-[11px] text-text-soft-400">{p.id.slice(0, 8)}</div>
              </div>
              {kind && (
                <div className="flex flex-wrap items-center gap-1.5">
                  <Badge color={BADGE_COLOR[kind]} variant="filled" size="small">{t(`team.badge.${kind}`)}</Badge>
                  {kind === "quarantined" && b?.last_error_code && (
                    <span className="text-[11px] text-text-soft-400">
                      {REASON_KEY[b.last_error_code] ? t(REASON_KEY[b.last_error_code]) : b.last_error_code}
                    </span>
                  )}
                  {!bound && action(`publish:${p.id}`, t("team.action.publish"), () => { void publish(p.id); })}
                  {!bound && publishRefused.has(p.id)
                    && action(`cancel:${p.id}`, t("team.action.cancelPublish"), () => { void cancelPublish(p.id); }, false)}
                  {(b?.revert_available || b?.revert_in_progress) && action(
                    `revert:${p.id}`,
                    b.revert_in_progress ? t("team.action.resumeRevert") : t("team.action.revert"),
                    () => { void revert(p.id); },
                  )}
                  {bound && !quarantined && !b.revert_in_progress
                    && action(`checkIn:${p.id}`, t("team.action.checkIn"), () => { void checkIn(p.id); })}
                  {bound && (!quarantined || b.last_error_code === "SIGNER_REVOKED")
                    && action(`pull:${p.id}`, t("team.action.pull"), () => { void pull(p.id); })}
                  {bound && action(`unbind:${p.id}`, t("team.action.unbind"), () => { void unbind(p.id); }, false)}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div data-testid="team-fleet" className="overflow-hidden rounded-12 bg-bg-white-0 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
        <div className="flex items-center justify-between gap-3 border-b border-stroke-soft-200 bg-bg-weak-50 px-4 py-2">
          <span className="text-subheading-2xs text-text-soft-400">{t("team.join.title")}</span>
          {action("fleet", t("team.join.list"), () => { void listFleet(); })}
        </div>
        {fleet?.length === 0 && (
          <div className="px-4 py-6 text-center text-paragraph-xs text-text-soft-400">{t("team.join.empty")}</div>
        )}
        {fleet?.map((f) => (
          <div
            key={f.remote_profile_id}
            data-testid="team-fleet-profile"
            className="flex items-center justify-between gap-3 border-t border-stroke-soft-200 px-4 py-2.5 first:border-t-0"
          >
            <div className="min-w-0">
              <div className="truncate text-label-xs text-text-strong-950">
                {f.label ?? t("team.join.unnamed", { id: f.remote_profile_id.slice(0, 8) })}
              </div>
              <div className="truncate text-[11px] text-text-soft-400">{t("team.join.version", { n: f.current_version })}</div>
            </div>
            {f.bound_to
              ? <Badge color="success" variant="lighter" size="small">{t("team.join.joined")}</Badge>
              : action(`join:${f.remote_profile_id}`, t("team.join.join"), () => { void join(f); })}
          </div>
        ))}
      </div>
    </div>
  );
}
