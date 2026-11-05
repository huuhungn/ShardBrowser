import { useEffect, useState } from "react";
import { Button } from "@proxyshard/shardx-ui-kit";
import { toast } from "../../../shared/model/toast";
import { useT } from "../../../shared/i18n";
import {
  teamJoinCode, teamJoinConfirm, teamEnrollAgain, type TeamJoinCode, type TeamStatus,
} from "../../../entities/team";
import { timeLeft, type TeamActionProps } from "./TeamDevices";

const EXPIRED = "fleet.joinCodeExpired";

/**
 * A joining device's code: shown with the anchor and full key IDs while its
 * ten-minute window is open, then Codes match pins the anchor. An expired
 * code offers Enroll again.
 */
export function TeamJoin({ account, busy, run, onEnrolledAgain }: TeamActionProps & {
  onEnrolledAgain: (status: TeamStatus) => void;
}) {
  const t = useT();
  const [code, setCode] = useState<TeamJoinCode | null>(null);
  const [refusedExpired, setRefusedExpired] = useState(false);
  const [full, setFull] = useState(false);
  const [pinned, setPinned] = useState(false);
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  const expired = refusedExpired || (!!code && !pinned && now > code.expires_at_ms);
  const login = () => [account.username.trim(), account.take()] as const;
  const noteExpired = (e: unknown) => {
    if (String(e).includes(EXPIRED)) setRefusedExpired(true);
    throw e;
  };

  const show = () => run("joinCode", async () => {
    const [u, p] = login();
    const next = await teamJoinCode(u, p).catch(noteExpired);
    setCode(next);
    setRefusedExpired(false);
  });

  const confirm = () => run("joinConfirm", async () => {
    if (!code) return;
    const [u, p] = login();
    await teamJoinConfirm(u, p, code.anchor, code.sas).catch(noteExpired);
    setPinned(true);
    toast.ok(t("team.joinCode.pinned"));
  });

  const again = () => run("enrollAgain", async () => {
    const [u, p] = login();
    onEnrolledAgain(await teamEnrollAgain(u, p));
    toast.ok(t("team.joinCode.enrollAgainDone"));
  });

  return (
    <div data-testid="team-join" className="flex flex-col gap-2 border-t border-stroke-soft-200 pt-2">
      <p className="m-0 text-paragraph-xs text-text-soft-400">{t("team.joinCode.help")}</p>
      {!pinned && (
        <div>
          <Button size="small" mode="stroke" disabled={!!busy || !account.signedIn} onClick={show}>
            {t("team.joinCode.show")}
          </Button>
        </div>
      )}
      {code && !expired && (
        <>
          <div className="flex flex-wrap items-center gap-2">
            <span data-testid="team-join-sas" className="mono text-label-sm text-text-strong-950">{code.sas}</span>
            {!pinned && (
              <span className="text-paragraph-xs text-text-soft-400">
                {t("team.devices.timeLeft", { time: timeLeft(code.expires_at_ms, now) })}
              </span>
            )}
          </div>
          <div>
            <Button variant="neutral" mode="ghost" size="xsmall" onClick={() => setFull((f) => !f)}>
              {full ? t("team.devices.hideKeyIds") : t("team.devices.showKeyIds")}
            </Button>
          </div>
          {full && (
            <dl data-testid="team-join-key-ids" className="mono m-0 break-all text-[11px] text-text-sub-600">
              <dt className="text-text-soft-400">{t("team.devices.signingKeyId")}</dt><dd className="m-0">{code.signing_key_id}</dd>
              <dt className="text-text-soft-400">{t("team.devices.hpkeKeyId")}</dt><dd className="m-0">{code.hpke_key_id}</dd>
              <dt className="text-text-soft-400">{t("team.devices.anchor")}</dt><dd className="m-0">{code.anchor}</dd>
            </dl>
          )}
          {pinned ? (
            <p className="m-0 text-paragraph-xs text-text-sub-600">{t("team.joinCode.pinned")}</p>
          ) : (
            <div>
              <Button size="small" disabled={!!busy || !account.signedIn} onClick={confirm}>
                {t("team.joinCode.codesMatch")}
              </Button>
            </div>
          )}
        </>
      )}
      {expired && (
        <>
          <p className="m-0 text-paragraph-xs text-state-error-base">{t("team.joinCode.expired")}</p>
          <div>
            <Button size="small" disabled={!!busy || !account.signedIn} onClick={again}>
              {t("team.joinCode.enrollAgain")}
            </Button>
          </div>
        </>
      )}
    </div>
  );
}
