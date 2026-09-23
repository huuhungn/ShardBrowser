import { useEffect, useState } from "react";
import { Button, Input } from "@proxyshard/shardx-ui-kit";
import { CopyField } from "../../../shared/ui/CopyField";
import { toast } from "../../../shared/model/toast";
import {
  teamStatus, teamSetConnection, teamTestConnection,
  teamEnrollDevice, teamCollectCustody, useTeam,
  type TeamStatus,
} from "../../../entities/team";
import { t, useT } from "../../../shared/i18n";

/** A tenant id is a UUID the operator picks once; typing one by hand is how
 *  two devices end up in different fleets over a mistyped character. */
function newTenantId(): string {
  try {
    if (typeof crypto?.randomUUID === "function") return crypto.randomUUID();
  } catch { /* not a secure context */ }
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** A default label that says which machine this is without asking. */
function suggestLabel(): string {
  const ua = navigator.userAgent;
  const os = /Windows/i.test(ua) ? t("team.windows")
    : /Macintosh|Mac OS X/i.test(ua) ? "macOS"
    : /Linux|X11|CrOS/i.test(ua) ? t("team.linux") : "device";
  return `${os} ${new Date().toISOString().slice(0, 10)}`;
}

/**
 * Team server connection, device enrolment and key custody.
 *
 * The three states this card has to make obvious, because they look alike and
 * behave nothing alike: not connected, connected but not enrolled, and
 * enrolled but unable to receive custody (a device from before the HPKE seed
 * was kept — the server has its public key, the private half is gone).
 */
export function TeamCard() {
  const t = useT();
  const [st, setSt] = useState<TeamStatus | null>(null);
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [tenant, setTenant] = useState("");
  const [label, setLabel] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const shareStatus = useTeam((s) => s.refresh);

  const refresh = () => teamStatus().then((s) => {
    setSt(s);
    setUrl(s.server_url);
    setTenant(s.tenant_id);
  }).catch(() => {});
  useEffect(() => { refresh(); }, []);

  const run = async (what: string, fn: () => Promise<void>) => {
    setBusy(what);
    try { await fn(); }
    catch (e) { toast.err(String(e)); }
    finally { setBusy(null); }
  };

  const save = () => run("save", async () => {
    // The token is only sent when it was typed: the field is left blank on
    // load, and sending that blank would clear a working token.
    const next = await teamSetConnection(url, token, tenant);
    setSt(next);
    setToken("");
    void shareStatus();
    toast.ok(t("team.connectionSaved"));
  });

  const test = () => run("test", async () => {
    const id = await teamTestConnection();
    toast.ok(`Server identity: ${id}`);
  });

  const enroll = () => run("enroll", async () => {
    const next = await teamEnrollDevice(label.trim() || suggestLabel());
    setSt(next);
    void shareStatus();
    toast.ok(t("team.deviceEnrolled"));
  });

  const collect = () => run("collect", async () => {
    const r = await teamCollectCustody();
    if (r.grants === 0) {
      toast.info(t("team.noGrantsWaitingACustodianDeviceHasToIs"));
    } else if (r.failed > 0) {
      toast.err(`${r.opened} of ${r.grants} opened; ${r.failed} could not be opened`);
    } else {
      // The fleet key is the one sync needs, so lead with that.
      if (r.can_sync_without_passphrase) {
        const gen =
          r.newest_fleet_generation == null
            ? ""
            : ` (generation ${r.newest_fleet_generation})`;
        toast.ok(
          `Fleet key collected${gen} — this device can sync without a passphrase`,
        );
      } else if (r.opened > 0) {
        const gen =
          r.newest_generation == null ? "" : ` (generation ${r.newest_generation})`;
        toast.ok(
          `Root custody in place: ${r.opened} grant(s)${gen}. No fleet key yet — ` +
            `sync still needs a passphrase.`,
        );
      } else {
        toast.err(t("team.noGrantsAreWaitingForThisDeviceYet"));
      }
    }
  });

  const connected = !!st && !!st.server_url && st.has_token;

  return (
    <div className="flex flex-col gap-2">
      <p className="m-0 text-paragraph-xs text-text-soft-400">
        {t("team.enrolThisDeviceWithATeamServerToSync")}
      </p>

      <Input
        label={t("team.serverUrl")}
        inputSize="small"
        placeholder="https://team.example.com"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
      />
      <Input
        label={t("team.apiToken")}
        inputSize="small"
        type="password"
        placeholder={st?.has_token ? "•••••••• (saved — type to replace)" : "paste the token"}
        value={token}
        onChange={(e) => setToken(e.target.value)}
      />

      <div className="flex items-end gap-2">
        <div className="grow">
          <Input
            label={t("team.tenantId")}
            inputSize="small"
            className="mono"
            placeholder={t("team.00000000000000000000000000000000")}
            value={tenant}
            onChange={(e) => setTenant(e.target.value)}
          />
        </div>
        <Button
          size="small"
          mode="stroke"
          disabled={!!busy}
          onClick={() => { setTenant(newTenantId()); toast.info(t("team.generatedSaveToApply")); }}
        >
          {t("common.generate")}
        </Button>
      </div>
      <p className="m-0 text-paragraph-xs text-text-soft-400">
        {t("team.generateOneForANewFleetPasteTheExist")}
      </p>

      <div className="flex gap-2">
        <Button size="small" disabled={!!busy} onClick={save}>
          {busy === "save" ? "Saving…" : t("team.saveConnection")}
        </Button>
        <Button size="small" mode="stroke" disabled={!!busy || !connected} onClick={test}>
          {busy === "test" ? "Testing…" : t("team.testConnection")}
        </Button>
      </div>

      {st && (
        <div className="mt-1 flex flex-col gap-2 border-t border-stroke-soft-200 pt-2">
          {!st.is_enrolled ? (
            <>
              <Input
                label={t("team.deviceLabel")}
                inputSize="small"
                placeholder={suggestLabel()}
                value={label}
                onChange={(e) => setLabel(e.target.value)}
              />
              <div>
                <Button size="small" disabled={!!busy || !connected} onClick={enroll}>
                  {busy === "enroll" ? "Enrolling…" : t("team.enrolThisDevice")}
                </Button>
              </div>
              {!connected && (
                <p className="m-0 text-paragraph-xs text-text-soft-400">
                  {t("team.saveAServerUrlAndTokenFirst")}
                </p>
              )}
            </>
          ) : (
            <>
              <div>
                <span className="text-paragraph-xs text-text-soft-400">Device ID</span>
                <CopyField value={st.device_id} />
              </div>

              {st.can_receive_custody ? (
                <>
                  <div>
                    <Button size="small" disabled={!!busy} onClick={collect}>
                      {busy === "collect" ? "Collecting…" : t("team.collectKeyCustody")}
                    </Button>
                  </div>
                  <p className="m-0 text-paragraph-xs text-text-soft-400">
                    {t("team.picksUpTheRootKeyGrantsACustodianHas")}
                  </p>
                </>
              ) : (
                <p className="m-0 text-paragraph-xs text-state-error-base">
                  {t("team.thisDeviceWasEnrolledBeforeItsKeyMat")}
                </p>
              )}

              {!st.can_sync && (
                <p className="m-0 text-paragraph-xs text-state-error-base">
                  {t("team.enrolledBeforeProfileSyncExistedReEn")}
                </p>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
