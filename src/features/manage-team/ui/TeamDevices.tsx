import { useEffect, useState } from "react";
import { Button, Checkbox, Select } from "@proxyshard/shardx-ui-kit";
import Badge, { type BadgeColor } from "../../../shared/ui/Badge";
import { toast } from "../../../shared/model/toast";
import { confirmModal } from "../../../shared/model/confirm";
import { useT } from "../../../shared/i18n";
import { safeUiError } from "../../../shared/lib/utils";
import { useProfile } from "../../../entities/profile";
import {
  teamFleetCustodyStatus, teamFleetKeySetup, teamDevices, teamApproveDevice, teamRevokeDevice,
  teamFleetKeyRotate, teamProfilesUnderOlderKey, teamCheckIn, teamResealAll, useTeamProfiles,
  type FleetCustodyStatus, type TeamDevice, type TeamRevokeReason, type OlderKeyProfile, type HandoverStatus,
} from "../../../entities/team";

/** The account login TeamCard holds; `take` hands over the password and clears it. */
export type TeamAccount = { username: string; signedIn: boolean; take: () => string };

export type TeamActionProps = {
  account: TeamAccount;
  busy: string | null;
  run: (what: string, fn: () => Promise<void>) => Promise<void>;
};

/** Minutes and seconds left until `until`, by this computer's clock. */
export const timeLeft = (until: number, now: number) => {
  const s = Math.max(0, Math.floor((until - now) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
};

const STATUS_COLOR: Record<string, BadgeColor> = { pending: "warning", active: "success", revoked: "error" };

/** A re-seal outcome the next run resumes. */
const resealPending = (o: string) => o === "walking" || o.startsWith("sealing:");

/** The locale key and values that describe a re-seal outcome (team/sync.rs `reseal_all`). */
const resealOutcome = (o: string): [string, Record<string, string>?] => {
  if (o.startsWith("resealed:")) return ["team.reseal.outcome.resealed", { n: o.slice("resealed:".length) }];
  if (o === "current") return ["team.reseal.outcome.current"];
  if (resealPending(o)) return ["team.reseal.outcome.pending"];
  if (o === "skipped:in-use") return ["team.reseal.outcome.inUse"];
  if (o === "skipped:quarantined") return ["team.reseal.outcome.quarantined"];
  if (o === "skipped:older-key-not-held") return ["team.reseal.outcome.olderKeyNotHeld"];
  return ["team.reseal.outcome.error", { code: o.replace(/^skipped:(error:)?/, "") }];
};

/** The hand-over checklist's steps, in order (`team.handover.step.*`). */
const HANDOVER_STEPS = ["export", "rotate", "reseal", "exportAgain", "revoke"] as const;

/** The profiles a `fleet.handoverNotReady` refusal of the old root's revoke lists, if it names any. */
const handoverBlockers = (e: unknown) => {
  const m = /\[\[shardx:fleet\.handoverNotReady\|step=heads\|profiles=([^\]|]*)\]\]/.exec(String(e));
  return m ? m[1].split(",").map((p) => p.trim()).filter(Boolean) : null;
};

/** The locale key and values that describe a `lost` path revert outcome (fleet_custody.rs `revoke_outgoing`). */
const revertOutcome = (o: string): [string, Record<string, string>?] =>
  o.startsWith("reverted:") ? ["team.handover.revert.reverted", { n: o.slice("reverted:".length) }]
  : o.startsWith("error:") ? ["team.handover.revert.error", { code: o.slice("error:".length) }]
  : ["team.handover.revert.pending"];

/**
 * The root custodian's fleet key and device list: approve a pending device
 * whose code matches, inside this computer's ten-minute window, and revoke
 * any other active one.
 */
export function TeamDevices({
  account, busy, run, anchor, selfId, hasFleetKey, fleetKeyBlocked, onFleetKey, handedOverTo, handover, onReset,
}: TeamActionProps & {
  /** This custodian's bootstrap anchor A0. */
  anchor: string;
  /** This device's id, which is never offered Revoke. */
  selfId: string;
  /** `team_status`: this computer holds a fleet key that verifies and may seal. */
  hasFleetKey: boolean;
  /** `team_status`: it holds a verified key, but Q-18 blocks sealing under it. */
  fleetKeyBlocked: boolean;
  /** Create fleet key may have kept a key: reload `team_status`. */
  onFleetKey: () => void;
  /** `team_fleet_custody_status`: the device this custodian appointed (v2.10 hand-over); empty if none. */
  handedOverTo: string;
  /** The hand-over this device accepted; TeamCard reloads both on `onFleetKey` and after an export. */
  handover: HandoverStatus | null;
  /** Reset of this device (v2.11): the old root once the new custodian revoked it. */
  onReset: () => void;
}) {
  const t = useT();
  const [fleet, setFleet] = useState<FleetCustodyStatus | null>(null);
  const [rows, setRows] = useState<TeamDevice[] | null>(null);
  const [matched, setMatched] = useState<Set<string>>(new Set());
  const [full, setFull] = useState<Set<string>>(new Set());
  const [reasons, setReasons] = useState<Record<string, TeamRevokeReason>>({});
  const [now, setNow] = useState(Date.now());
  const [older, setOlder] = useState<OlderKeyProfile[]>([]);
  const [olderErrors, setOlderErrors] = useState<Record<string, string>>({});
  // The heads the old root's last refused revoke named.
  const [blockers, setBlockers] = useState<string[]>([]);
  const profiles = useProfile((s) => s.profiles);
  const bindings = useTeamProfiles((s) => s.status);
  const refreshBindings = useTeamProfiles((s) => s.refresh);
  const loadOlder = () => teamProfilesUnderOlderKey().then(setOlder).catch(() => {});
  const nameOf = (id: string) => profiles.find((x) => x.id === id)?.name ?? id;
  useEffect(() => {
    teamFleetCustodyStatus().then(setFleet).catch(() => {});
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  // A Check in, Pull or Unbind from the profile list refreshes the bindings,
  // and may move a profile off an older key.
  useEffect(() => { void loadOlder(); }, [bindings]);

  // The journal says how far Create fleet key got; whether the key is usable
  // now is team_status's live check. Approve hands that key on.
  const done = !!fleet?.created && !fleet.setup_key_held;
  const ready = done && hasFleetKey;
  // v2.10 hand-over: this root custodian appointed another device, or accepted custody from one.
  const handedOver = !!handedOverTo;
  const accepted = handover?.phase === "granted" || handover?.phase === "done";
  const rotated = !!handover && handover.rotated_generation > handover.accepted_generation;
  const resealed = rotated && handover.resealed_generation === handover.rotated_generation;
  // The checklist (4.H steps 3-7), each step done or not, in order.
  const steps = handover ? [
    handover.first_exported, rotated, resealed,
    resealed && handover.exported_generation >= handover.rotated_generation, handover.phase === "done",
  ] : [];
  // A step is enabled once Accept and every step before it are done; without a hand-over nothing waits.
  const canStep = (i: number) => !handover || (accepted && steps.slice(0, i).every(Boolean));
  const isOldRoot = (r: TeamDevice) => !!handover && r.signing_key_id.toLowerCase() === handover.outgoing.toLowerCase();
  const isAppointee = (r: TeamDevice) => handedOver && r.device_id.toLowerCase() === handedOverTo.toLowerCase();
  const isExpired = (r: TeamDevice) => r.status === "pending" && (r.approve_until_ms == null || now > r.approve_until_ms);
  // Why an open pending row's Approve is off when nothing on the row says so.
  const approvable = rows?.some((r) => r.status === "pending" && !isExpired(r));
  const hint = !approvable ? null
    : !account.signedIn ? t("team.devices.needPassword")
    : fleet && !done ? t("team.devices.needFleetKey")
    : null;
  // A tick vouches for the exact code shown, so a refreshed code needs a new one.
  const tick = (r: TeamDevice) => `${r.device_id} ${r.sas}`;
  const login = () => [account.username.trim(), account.take()] as const;
  const toggle = (set: Set<string>, id: string) => {
    const next = new Set(set);
    if (!next.delete(id)) next.add(id);
    return next;
  };
  const mark = (id: string, status: string) =>
    setRows((l) => l?.map((r) => (r.device_id === id ? { ...r, status, approve_until_ms: null } : r)) ?? null);

  const setup = () => run("fleetKey", async () => {
    const [u, p] = login();
    try {
      setFleet(await teamFleetKeySetup(u, p));
      onFleetKey();
      toast.ok(t("team.devices.fleetKeyReady"));
    } catch (e) {
      // Whatever step it reached is saved; show where the next try resumes.
      teamFleetCustodyStatus().then(setFleet).catch(() => {});
      onFleetKey();
      throw e;
    }
  });

  const rotation = fleet?.rotation ?? null;
  const unfinished = rotation?.phase === "preparing" || rotation?.phase === "activated";
  const stuck = rotation?.phase === "expired";
  const rotate = async (skipMember?: string) => {
    // Skipping is its own decision: the member must be revoked and enroll again.
    const ok = await confirmModal(skipMember ? {
      title: t("team.rotation.skipMember"),
      message: t("team.rotation.skipConfirm", { id: skipMember.slice(0, 8) }),
      buttons: [
        { label: t("common.cancel"), value: false },
        { label: t("team.rotation.skipMember"), value: true, danger: true },
      ],
    } : {
      title: t("team.rotation.confirmTitle"),
      message: `${t("team.rotation.confirm")} ${t("team.rotation.retroactive")}`,
      buttons: [
        { label: t("common.cancel"), value: false },
        { label: t(unfinished ? "team.rotation.resume" : "team.rotation.rotate"), value: true, danger: true },
      ],
    });
    if (ok !== true) return;
    await run("rotate", async () => {
      const [u, p] = login();
      try {
        const next = await teamFleetKeyRotate(u, p, skipMember);
        setFleet(next);
        toast.ok(t("team.rotation.done", { n: next.rotation?.generation ?? 0 }));
        const refused = next.rotation?.members_refused ?? 0;
        if (refused > 0) toast.err(t("team.rotation.membersRefused", { n: refused }));
      } catch (e) {
        // Whatever step it reached is saved; show where the next try resumes.
        teamFleetCustodyStatus().then(setFleet).catch(() => {});
        throw e;
      } finally {
        onFleetKey();
        void loadOlder();
      }
    });
  };

  const reseal = fleet?.reseal ?? null;
  const resealUnfinished = !!reseal && Object.values(reseal.profiles).some(resealPending);
  const resealAll = async () => {
    const label = t(resealUnfinished ? "team.reseal.resume" : "team.reseal.run");
    const ok = await confirmModal({
      title: t("team.reseal.confirmTitle"),
      message: t("team.reseal.confirm"),
      buttons: [
        { label: t("common.cancel"), value: false },
        { label, value: true, danger: true },
      ],
    });
    if (ok !== true) return;
    await run("reseal", async () => {
      const [u, p] = login();
      try {
        const next = await teamResealAll(u, p);
        setFleet(next);
        const outcomes = Object.values(next.reseal?.profiles ?? {});
        const count = (prefix: string) => String(outcomes.filter((o) => o.startsWith(prefix)).length);
        if (outcomes.some(resealPending)) toast.err(t("sync.resealIncomplete"));
        else toast.ok(t("team.reseal.done", { resealed: count("resealed"), current: count("current"), skipped: count("skipped") }));
      } catch (e) {
        // Each outcome is saved; show where the next run resumes.
        teamFleetCustodyStatus().then(setFleet).catch(() => {});
        throw e;
      } finally {
        onFleetKey();
        void loadOlder();
        void refreshBindings();
      }
    });
  };

  // Push only: a copy the server says is behind may hold unpushed changes a
  // pull would replace, so the user pulls it from the profile list first.
  const repush = (o: OlderKeyProfile) => run(`repush:${o.profile_id}`, async () => {
    const [u, p] = login();
    try {
      await teamCheckIn(o.profile_id, u, p);
      setOlderErrors(({ [o.profile_id]: _, ...rest }) => rest);
      toast.ok(t("team.rotation.repushed", { name: nameOf(o.profile_id) }));
    } catch (e) {
      const behind = String(e).includes("sync.remoteAhead");
      setOlderErrors((m) => ({ ...m, [o.profile_id]: behind ? t("team.rotation.behind") : safeUiError(e) }));
    } finally {
      void loadOlder();
      void refreshBindings();
    }
  });

  const list = () => run("devices", async () => {
    const [u, p] = login();
    setRows(await teamDevices(u, p));
  });

  const approve = (r: TeamDevice) => run(`approve:${r.device_id}`, async () => {
    const [u, p] = login();
    await teamApproveDevice(u, p, r.device_id, r.sas);
    mark(r.device_id, "active");
    toast.ok(t("team.devices.approved", { label: r.label }));
  });

  // v2.10 4.H step 1: approve the pending device as the new root custodian and hand custody to it.
  const appoint = async (r: TeamDevice) => {
    const ok = await confirmModal({
      title: t("team.handover.appointTitle", { label: r.label }),
      message: t("team.handover.appointConfirm", { label: r.label }),
      buttons: [
        { label: t("common.cancel"), value: false },
        { label: t("team.handover.appoint"), value: true, danger: true },
      ],
    });
    if (ok !== true) return;
    await run(`approve:${r.device_id}`, async () => {
      const [u, p] = login();
      try {
        await teamApproveDevice(u, p, r.device_id, r.sas, true);
        mark(r.device_id, "active");
        toast.ok(t("team.handover.appointed", { label: r.label }));
      } finally {
        // Once the root grant is filed this computer has handed over, even if a later step failed.
        teamFleetCustodyStatus().then(setFleet).catch(() => {});
        onFleetKey();
      }
    });
  };

  const revoke = async (r: TeamDevice) => {
    const reason = reasons[r.device_id] ?? "retired";
    const old = isOldRoot(r);
    const appointee = isAppointee(r);
    const extra = old ? t("team.handover.revokeConfirm")
      : appointee ? t("team.handover.cancelConfirm")
      : reason === "compromised" ? t("team.devices.compromisedWarning") : null;
    const ok = await confirmModal({
      title: t("team.devices.revokeTitle", { label: r.label }),
      message: extra ? `${t("team.devices.revokeConfirm")} ${extra}` : t("team.devices.revokeConfirm"),
      buttons: [
        { label: t("common.cancel"), value: false },
        { label: t("team.devices.revoke"), value: true, danger: true },
      ],
    });
    if (ok !== true) return;
    await run(`revoke:${r.device_id}`, async () => {
      const [u, p] = login();
      try {
        await teamRevokeDevice(u, p, r.device_id, reason);
      } catch (e) {
        // 4.H step 7: the old root's revoke names the heads that still block it.
        const listed = old ? handoverBlockers(e) : null;
        if (!listed?.length) throw e;
        setBlockers(listed);
        if (reason !== "lost") throw e;
        // `lost` goes ahead only once the user accepted reverting exactly these heads.
        const revert = await confirmModal({
          title: t("team.handover.revertsTitle"),
          message: `${t("team.handover.reverts")} ${listed.map((id) => id.slice(0, 8)).join(", ")}`,
          buttons: [
            { label: t("common.cancel"), value: false },
            { label: t("team.handover.revertsConfirm"), value: true, danger: true },
          ],
        });
        if (revert !== true) return;
        await teamRevokeDevice(u, p, r.device_id, reason, listed);
      } finally {
        if (old || appointee) {
          // A revoke, a cancel, or reverts part-way: show what the hand-over state now says.
          teamFleetCustodyStatus().then(setFleet).catch(() => {});
          onFleetKey();
        }
      }
      setBlockers([]);
      mark(r.device_id, "revoked");
      // A revoked holder of the current fleet key raises the rotation banner.
      teamFleetCustodyStatus().then(setFleet).catch(() => {});
      toast.ok(t("team.devices.revoked", { label: r.label }));
    });
  };

  // Display only: among live rows that share a label, the last the server
  // lists (by created_at, id) is the newest enrollment.
  const live = (rows ?? []).filter((r) => r.status !== "revoked");
  const shared = new Map<string, number>();
  const newest = new Map<string, string>();
  for (const r of live) {
    shared.set(r.label, (shared.get(r.label) ?? 0) + 1);
    newest.set(r.label, r.device_id);
  }

  return (
    <div data-testid="team-devices" className="flex flex-col gap-2 border-t border-stroke-soft-200 pt-2">
      {handedOver ? (
        <div data-testid="team-handed-over" className="flex flex-col gap-1">
          <p className="m-0 text-paragraph-xs text-state-error-base">
            {t("team.handover.handedOver", { id: handedOverTo.slice(0, 8) })}
          </p>
          <p className="m-0 text-paragraph-xs text-text-sub-600">{t("team.handover.cancelHint")}</p>
          <p className="m-0 text-paragraph-xs text-text-sub-600">{t("team.handover.inert")}</p>
          <div>
            <Button
              data-testid="team-reset-old-root"
              size="small"
              variant="error"
              disabled={!!busy || !account.signedIn}
              onClick={onReset}
            >
              {busy === "reset" ? t("busy.resetting") : t("team.handover.resetOldRoot")}
            </Button>
          </div>
        </div>
      ) : done && fleetKeyBlocked ? (
        <p className="m-0 text-paragraph-xs text-state-error-base">{t("team.joinCode.blocked")}</p>
      ) : done && !hasFleetKey ? (
        <p className="m-0 text-paragraph-xs text-state-error-base">{t("team.devices.fleetKeyNotUsable")}</p>
      ) : ready ? (
        <p className="m-0 text-paragraph-xs text-text-sub-600">{t("team.devices.fleetKeyReady")}</p>
      ) : (
        <>
          <p className="m-0 text-paragraph-xs text-text-soft-400">{t("team.devices.fleetKeyHelp")}</p>
          <div>
            <Button size="small" disabled={!!busy || !account.signedIn || !fleet} onClick={setup}>
              {busy === "fleetKey"
                ? t("team.devices.creatingFleetKey")
                : fleet?.started ? t("team.devices.resumeFleetKey") : t("team.devices.createFleetKey")}
            </Button>
          </div>
        </>
      )}

      {fleet?.members_need_server_update ? (
        <p data-testid="team-members-server-update" className="m-0 text-paragraph-xs text-state-error-base">
          {t("fleet.memberRenewalNeedsServerUpdate")}
        </p>
      ) : fleet?.member_renewal_failed ? (
        <p data-testid="team-members-renewal-failed" className="m-0 text-paragraph-xs text-state-error-base">
          {t("fleet.memberRenewalFailed", { code: t(fleet.member_renewal_failed) })}
        </p>
      ) : null}

      {handover && (
        <div data-testid="team-handover-checklist" className="flex flex-col gap-1.5">
          <span className="text-label-xs text-text-strong-950">{t("team.handover.checklistTitle")}</span>
          <p
            data-testid={handover.phase === "done" ? "team-handover-done" : undefined}
            className="m-0 text-paragraph-xs text-text-sub-600"
          >
            {t(handover.phase === "done" ? "team.handover.done" : "team.handover.checklistHelp")}
          </p>
          <ol className="m-0 flex flex-col gap-1 pl-4 text-paragraph-xs text-text-sub-600">
            {HANDOVER_STEPS.map((key, i) => {
              const state = steps[i] ? "done" : canStep(i) ? "next" : "waiting";
              return (
                <li key={key} data-testid="team-handover-step" data-state={state}>
                  {t(`team.handover.step.${key}`)}{" "}
                  <Badge color={state === "done" ? "success" : state === "next" ? "information" : "gray"} variant="lighter" size="small">
                    {t(`team.handover.state.${state}`)}
                  </Badge>
                </li>
              );
            })}
          </ol>
          {Object.entries(handover.reverts).map(([id, o]) => {
            const [key, values] = revertOutcome(o);
            const shown = values?.code ? { ...values, code: t(values.code) } : values;
            return (
              <p key={id} data-testid="team-handover-revert" className="m-0 text-paragraph-xs text-text-sub-600">
                <span className="mono">{id.slice(0, 8)}</span> {t(key, shown)}
              </p>
            );
          })}
          {blockers.length > 0 && (
            <div data-testid="team-handover-blockers" className="flex flex-col gap-1">
              <p className="m-0 text-paragraph-xs text-state-error-base">{t("team.handover.blocked")}</p>
              {blockers.map((id) => (
                <span key={id} className="mono text-paragraph-xs text-text-sub-600">{id.slice(0, 8)}</span>
              ))}
            </div>
          )}
        </div>
      )}

      {done && !handedOver && (
        <div data-testid="team-rotation" className="flex flex-col gap-2">
          {fleet?.rotation_required && !unfinished && (
            <p
              data-testid="team-rotation-banner"
              className={`m-0 text-paragraph-xs ${fleet.rotation_required === "urgent" ? "text-state-error-base" : "text-text-sub-600"}`}
            >
              {t(fleet.rotation_required === "urgent" ? "team.rotation.bannerUrgent" : "team.rotation.bannerRoutine")}
            </p>
          )}
          {rotation && (unfinished || stuck) && (
            <p data-testid="team-rotation-status" className="m-0 text-paragraph-xs text-state-error-base">
              {t(stuck ? "team.rotation.expired" : "team.rotation.unfinished", { n: rotation.generation })}
              {unfinished && rotation.deadline_ms != null
                && ` ${t("team.rotation.deadline", { date: new Date(rotation.deadline_ms).toLocaleString() })}`}
            </p>
          )}
          {rotation?.failing_member && (
            <div data-testid="team-rotation-failing" className="flex flex-wrap items-center gap-2">
              <p className="m-0 text-paragraph-xs text-state-error-base">
                {t("team.rotation.failingMember", { id: rotation.failing_member.slice(0, 8) })}
              </p>
              <Button
                size="xsmall" variant="error" mode="stroke"
                disabled={!!busy || !account.signedIn}
                onClick={() => { void rotate(rotation.failing_member ?? undefined); }}
              >
                {t("team.rotation.skipMember")}
              </Button>
            </div>
          )}
          {rotation?.phase === "done" && (
            <p data-testid="team-rotation-status" className="m-0 text-paragraph-xs text-text-sub-600">
              {t("team.rotation.done", { n: rotation.generation })}{" "}
              {t("team.rotation.members", {
                filed: rotation.members_filed, refused: rotation.members_refused, skipped: rotation.members_skipped,
              })}
            </p>
          )}
          <div>
            <Button
              size="small" mode="stroke"
              disabled={!!busy || !account.signedIn || !(ready || unfinished) || !(unfinished || canStep(1))}
              onClick={() => { void rotate(); }}
            >
              {busy === "rotate"
                ? t("team.rotation.busy")
                : t(unfinished ? "team.rotation.resume" : "team.rotation.rotate")}
            </Button>
          </div>
          <div data-testid="team-reseal" className="flex flex-col gap-1.5">
            <span className="text-label-xs text-text-strong-950">{t("team.reseal.title")}</span>
            <p className="m-0 text-paragraph-xs text-text-soft-400">{t("team.reseal.help")}</p>
            <div>
              <Button
                size="small" mode="stroke"
                disabled={!!busy || !account.signedIn || !(ready || resealUnfinished) || !(resealUnfinished || canStep(2))}
                onClick={() => { void resealAll(); }}
              >
                {busy === "reseal"
                  ? t("team.reseal.busy")
                  : t(resealUnfinished ? "team.reseal.resume" : "team.reseal.run")}
              </Button>
            </div>
            {reseal && Object.entries(reseal.profiles).map(([id, o]) => {
              const [key, values] = resealOutcome(o);
              // An error code reads as its message when the locale has one, else as the code.
              const shown = values?.code ? { ...values, code: t(values.code) } : values;
              return (
                <p key={id} data-testid="team-reseal-profile" className="m-0 text-paragraph-xs text-text-sub-600">
                  <span className="mono">{id.slice(0, 8)}</span> {t(key, shown)}
                </p>
              );
            })}
          </div>
          {older.length > 0 && (
            <div data-testid="team-older-key" className="flex flex-col gap-1.5">
              <span className="text-label-xs text-text-strong-950">{t("team.rotation.olderTitle")}</span>
              <p className="m-0 text-paragraph-xs text-text-soft-400">{t("team.rotation.olderCost")}</p>
              {older.map((o) => (
                <div
                  key={o.profile_id}
                  data-testid="team-older-key-profile"
                  className="flex flex-col gap-1 rounded-10 px-3 py-2 ring-1 ring-inset ring-stroke-soft-200"
                >
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-label-xs text-text-strong-950">{nameOf(o.profile_id)}</span>
                    <span className="text-paragraph-xs text-text-soft-400">
                      {t("team.rotation.olderGeneration", { n: o.key_generation })}
                    </span>
                    <Button
                      size="xsmall" mode="stroke"
                      disabled={!!busy || !account.signedIn}
                      onClick={() => { void repush(o); }}
                    >
                      {t("team.rotation.push")}
                    </Button>
                  </div>
                  {olderErrors[o.profile_id] && (
                    <p className="m-0 text-paragraph-xs text-state-error-base">{olderErrors[o.profile_id]}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <div>
        <Button size="small" mode="stroke" disabled={!!busy || !account.signedIn} onClick={list}>
          {t("team.devices.show")}
        </Button>
      </div>
      {rows?.length === 0 && (
        <p className="m-0 text-paragraph-xs text-text-soft-400">{t("team.devices.empty")}</p>
      )}
      {hint && <p className="m-0 text-paragraph-xs text-text-soft-400">{hint}</p>}
      {rows?.map((r) => {
        const self = r.device_id.toLowerCase() === selfId.toLowerCase();
        const expired = isExpired(r);
        const isNewest = r.status !== "revoked" && (shared.get(r.label) ?? 0) > 1 && newest.get(r.label) === r.device_id;
        return (
          <div
            key={r.device_id}
            data-testid="team-device"
            className="flex flex-col gap-1.5 rounded-10 px-3 py-2 ring-1 ring-inset ring-stroke-soft-200"
          >
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-label-xs text-text-strong-950">{r.label}</span>
              <span className="mono text-[11px] text-text-soft-400">{r.device_id.slice(0, 8)}</span>
              <Badge color={STATUS_COLOR[r.status] ?? "gray"} variant="lighter" size="small">
                {t(`team.devices.status.${r.status}`)}
              </Badge>
              {self && <Badge color="gray" variant="lighter" size="small">{t("team.devices.thisComputer")}</Badge>}
              {isNewest && <Badge color="information" variant="filled" size="small">{t("team.devices.newest")}</Badge>}
              {isOldRoot(r) && <Badge color="warning" variant="lighter" size="small">{t("team.handover.oldRoot")}</Badge>}
            </div>
            {r.status === "active" && !self && r.approval_window_ms && (() => {
              // v2.11 member renewal: the warning shows from 75% of the approval's life.
              const [from, until] = r.approval_window_ms;
              const late = now >= from + (until - from) * 0.75;
              return (
                <p
                  data-testid="team-device-approval"
                  className={`m-0 text-paragraph-xs ${late ? "text-state-error-base" : "text-text-soft-400"}`}
                >
                  {t(late ? "team.renewal.memberWarning" : "team.renewal.memberEnds", { date: new Date(until).toLocaleDateString() })}
                </p>
              );
            })()}
            {isNewest && (
              <p className="m-0 text-paragraph-xs text-text-soft-400">
                {t(r.status === "active" ? "team.devices.newestHintActive" : "team.devices.newestHint")}
              </p>
            )}

            {r.status === "pending" && (
              <>
                <div className="flex flex-wrap items-center gap-2">
                  <span data-testid="team-device-sas" className="mono text-label-sm text-text-strong-950">{r.sas}</span>
                  <span className="text-paragraph-xs text-text-soft-400">
                    {expired
                      ? t("team.devices.expired")
                      : t("team.devices.timeLeft", { time: timeLeft(r.approve_until_ms ?? 0, now) })}
                  </span>
                </div>
                <div>
                  <Button
                    variant="neutral" mode="ghost" size="xsmall"
                    onClick={() => setFull((s) => toggle(s, r.device_id))}
                  >
                    {full.has(r.device_id) ? t("team.devices.hideKeyIds") : t("team.devices.showKeyIds")}
                  </Button>
                </div>
                {full.has(r.device_id) && (
                  <dl data-testid="team-device-key-ids" className="mono m-0 break-all text-[11px] text-text-sub-600">
                    <dt className="text-text-soft-400">{t("team.devices.signingKeyId")}</dt><dd className="m-0">{r.signing_key_id}</dd>
                    <dt className="text-text-soft-400">{t("team.devices.hpkeKeyId")}</dt><dd className="m-0">{r.hpke_key_id}</dd>
                    <dt className="text-text-soft-400">{t("team.devices.anchor")}</dt><dd className="m-0">{anchor}</dd>
                  </dl>
                )}
                <Checkbox
                  label={t("team.devices.codeMatches")}
                  checked={matched.has(tick(r))}
                  disabled={expired}
                  onChange={() => setMatched((s) => toggle(s, tick(r)))}
                />
                <div className="flex flex-wrap gap-2">
                  <Button
                    size="small"
                    disabled={!!busy || !account.signedIn || !ready || handedOver || expired || !matched.has(tick(r))}
                    onClick={() => { void approve(r); }}
                  >
                    {t("team.devices.approve")}
                  </Button>
                  {!handedOver && !handover && (
                    <Button
                      size="small" mode="stroke"
                      disabled={!!busy || !account.signedIn || !ready || expired || !matched.has(tick(r))}
                      onClick={() => { void appoint(r); }}
                    >
                      {t("team.handover.appoint")}
                    </Button>
                  )}
                </div>
              </>
            )}

            {/* After an appointment only the appointee may be revoked, which cancels the hand-over. */}
            {r.status === "active" && !self && (!handedOver || isAppointee(r)) && (
              <div className="flex flex-wrap items-end gap-2">
                <div className="w-40">
                  <Select
                    label={t("team.devices.reason")}
                    size="small"
                    value={reasons[r.device_id] ?? "retired"}
                    onChange={(v) => setReasons((m) => ({ ...m, [r.device_id]: v as TeamRevokeReason }))}
                    options={[
                      { value: "retired", label: t("team.devices.reasonRetired") },
                      { value: "lost", label: t("team.devices.reasonLost") },
                      // Q-57: a custodian row is never offered `compromised`.
                      ...(r.custodian || isOldRoot(r) ? [] : [{ value: "compromised", label: t("team.devices.reasonCompromised") }]),
                    ]}
                  />
                </div>
                {/* Revoke needs only the saved Create fleet key, not a usable key: a lost key must not block it. */}
                <Button
                  size="small" variant="error" mode="stroke"
                  disabled={!!busy || !account.signedIn || !fleet?.created || (isOldRoot(r) && !canStep(4))}
                  onClick={() => { void revoke(r); }}
                >
                  {t("team.devices.revoke")}
                </Button>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
