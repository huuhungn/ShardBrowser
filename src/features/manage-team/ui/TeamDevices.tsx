import { useEffect, useState } from "react";
import { Button, Checkbox, Select } from "@proxyshard/shardx-ui-kit";
import Badge, { type BadgeColor } from "../../../shared/ui/Badge";
import { toast } from "../../../shared/model/toast";
import { confirmModal } from "../../../shared/model/confirm";
import { useT } from "../../../shared/i18n";
import {
  teamFleetCustodyStatus, teamFleetKeySetup, teamDevices, teamApproveDevice, teamRevokeDevice,
  type FleetCustodyStatus, type TeamDevice, type TeamRevokeReason,
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

/**
 * The root custodian's fleet key and device list: approve a pending device
 * whose code matches, inside this computer's ten-minute window, and revoke
 * any other active one.
 */
export function TeamDevices({ account, busy, run, anchor, selfId, hasFleetKey, fleetKeyBlocked, onFleetKey }: TeamActionProps & {
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
}) {
  const t = useT();
  const [fleet, setFleet] = useState<FleetCustodyStatus | null>(null);
  const [rows, setRows] = useState<TeamDevice[] | null>(null);
  const [matched, setMatched] = useState<Set<string>>(new Set());
  const [full, setFull] = useState<Set<string>>(new Set());
  const [reasons, setReasons] = useState<Record<string, TeamRevokeReason>>({});
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    teamFleetCustodyStatus().then(setFleet).catch(() => {});
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  // The journal says how far Create fleet key got; whether the key is usable
  // now is team_status's live check. Approve hands that key on.
  const done = !!fleet?.created && !fleet.setup_key_held;
  const ready = done && hasFleetKey;
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

  const revoke = async (r: TeamDevice) => {
    const reason = reasons[r.device_id] ?? "retired";
    const ok = await confirmModal({
      title: t("team.devices.revokeTitle", { label: r.label }),
      message: t("team.devices.revokeConfirm"),
      buttons: [
        { label: t("common.cancel"), value: false },
        { label: t("team.devices.revoke"), value: true, danger: true },
      ],
    });
    if (ok !== true) return;
    await run(`revoke:${r.device_id}`, async () => {
      const [u, p] = login();
      await teamRevokeDevice(u, p, r.device_id, reason);
      mark(r.device_id, "revoked");
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
      {done && fleetKeyBlocked ? (
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
            </div>
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
                <div>
                  <Button
                    size="small"
                    disabled={!!busy || !account.signedIn || !ready || expired || !matched.has(tick(r))}
                    onClick={() => { void approve(r); }}
                  >
                    {t("team.devices.approve")}
                  </Button>
                </div>
              </>
            )}

            {r.status === "active" && !self && (
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
                    ]}
                  />
                </div>
                {/* Revoke needs only the saved Create fleet key, not a usable key: a lost key must not block it. */}
                <Button
                  size="small" variant="error" mode="stroke"
                  disabled={!!busy || !account.signedIn || !fleet?.created}
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
