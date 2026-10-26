import { useEffect, useState } from "react";
import { Button, Input } from "@proxyshard/shardx-ui-kit";
import { CopyField } from "../../../shared/ui/CopyField";
import { toast } from "../../../shared/model/toast";
import {
  teamStatus, teamSetConnection, teamTestConnection,
  teamEnrollDevice, teamCollectCustody, useTeam,
  teamCustodyBootstrapStatus, teamBootstrapCustody,
  teamKeysCreateFile, teamKeysUnlock,
  type TeamStatus, type CustodyBootstrapStatus,
} from "../../../entities/team";
import { save as saveDialog } from "@tauri-apps/plugin-dialog";

/** The recovery bundle's passphrase floor, as the backend seals it. */
const MIN_RECOVERY_PASSPHRASE = 8;
import { t, useT } from "../../../shared/i18n";
import { safeUiError } from "../../../shared/lib/utils";

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
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [boot, setBoot] = useState<CustodyBootstrapStatus | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [passphrase2, setPassphrase2] = useState("");
  const [keyPass, setKeyPass] = useState("");
  const [keyPass2, setKeyPass2] = useState("");

  const shareStatus = useTeam((s) => s.refresh);

  const refresh = () => {
    teamStatus().then((s) => {
      setSt(s);
      setUrl(s.server_url);
      setTenant(s.tenant_id);
    }).catch(() => {});
    teamCustodyBootstrapStatus().then(setBoot).catch(() => {});
  };
  useEffect(() => { refresh(); }, []);

  const run = async (what: string, fn: () => Promise<void>) => {
    setBusy(what);
    try { await fn(); }
    catch (e) { toast.err(safeUiError(e)); }
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
    toast.ok(t("team.serverIdentity", { id }));
  });

  const enroll = () => run("enroll", async () => {
    // Cleared before the call, so a failed attempt does not keep it either.
    const typed = password;
    setPassword("");
    const next = await teamEnrollDevice(label.trim() || suggestLabel(), username, typed);
    setSt(next);
    void shareStatus();
    toast.ok(t("team.deviceEnrolled"));
  });

  const createKeyFile = () => run("keyFile", async () => {
    if (keyPass.length < MIN_RECOVERY_PASSPHRASE) {
      toast.err(t("team.recoveryPassphraseTooShort", { n: MIN_RECOVERY_PASSPHRASE }));
      return;
    }
    if (keyPass !== keyPass2) {
      toast.err(t("team.recoveryPassphrasesDiffer"));
      return;
    }
    const next = await teamKeysCreateFile(keyPass);
    setKeyPass("");
    setKeyPass2("");
    setSt(next);
    void shareStatus();
    toast.ok(t("team.keyFileCreated"));
  });

  const unlockKeys = () => run("unlock", async () => {
    const typed = keyPass;
    setKeyPass("");
    const next = await teamKeysUnlock(typed);
    setSt(next);
    void shareStatus();
    toast.ok(t("team.keysUnlocked"));
  });

  const bootstrap = () => run("bootstrap", async () => {
    if (passphrase.length < MIN_RECOVERY_PASSPHRASE) {
      toast.err(t("team.recoveryPassphraseTooShort", { n: MIN_RECOVERY_PASSPHRASE }));
      return;
    }
    if (passphrase !== passphrase2) {
      toast.err(t("team.recoveryPassphrasesDiffer"));
      return;
    }
    // A resumed setup keeps the bundle it already wrote; the backend ignores
    // a new path then, so do not ask for one.
    let path = boot?.recovery_path ?? "";
    if (!path) {
      const picked = await saveDialog({
        defaultPath: "shardx-recovery.shxrecovery",
        filters: [{ name: t("team.recoveryBundle"), extensions: ["shxrecovery"] }],
      });
      if (typeof picked !== "string") return; // cancelled
      path = picked;
    }
    const typed = password;
    setPassword("");
    try {
      const next = await teamBootstrapCustody(username, typed, path, passphrase);
      setBoot(next);
      setPassphrase("");
      setPassphrase2("");
      toast.ok(t("team.rootCustodyReady", { path: next.recovery_path }));
    } catch (e) {
      // Whatever step it reached is saved; show where the next try resumes.
      teamCustodyBootstrapStatus().then(setBoot).catch(() => {});
      throw e;
    }
  });

  const collect = () => run("collect", async () => {
    const r = await teamCollectCustody();
    if (r.grants === 0) {
      toast.info(t("team.noGrantsWaitingACustodianDeviceHasToIs"));
    } else if (r.failed > 0) {
      toast.err(t("team.grantsOpened", { opened: r.opened, grants: r.grants, failed: r.failed }));
    } else {
      // The fleet key is the one sync needs, so lead with that.
      if (r.can_sync_without_passphrase) {
        const gen =
          r.newest_fleet_generation == null
            ? ""
            : t("team.generationSuffix", { n: r.newest_fleet_generation });
        toast.ok(
          t("team.fleetKeyCollected", { gen }),
        );
      } else if (r.opened > 0) {
        const gen =
          r.newest_generation == null
            ? ""
            : t("team.generationSuffix", { n: r.newest_generation });
        toast.ok(t("team.rootCustody", { opened: r.opened, gen }));
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
        placeholder={st?.has_token ? t("team.tokenSavedPlaceholder") : t("team.pasteTheToken")}
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
          {busy === "save" ? t("common.saving") : t("team.saveConnection")}
        </Button>
        <Button size="small" mode="stroke" disabled={!!busy || !connected} onClick={test}>
          {busy === "test" ? t("busy.testing") : t("team.testConnection")}
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
              <div>
                <Button
                  size="small"
                  disabled={!!busy || !connected || !username.trim() || !password}
                  onClick={enroll}
                >
                  {busy === "enroll" ? t("busy.enrolling") : t("team.enrolThisDevice")}
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

              {st.keys_locked ? (
                <div className="flex flex-col gap-2" data-testid="keys-locked">
                  <p className="m-0 text-paragraph-xs text-state-error-base">{t("team.keysLocked")}</p>
                  <Input
                    label={t("team.keyFilePassphrase")}
                    inputSize="small"
                    type="password"
                    autoComplete="current-password"
                    value={keyPass}
                    onChange={(e) => setKeyPass(e.target.value)}
                  />
                  <div>
                    <Button size="small" disabled={!!busy || !keyPass} onClick={unlockKeys}>
                      {busy === "unlock" ? t("busy.unlocking") : t("team.unlockKeys")}
                    </Button>
                  </div>
                </div>
              ) : !st.keys_protected && (
                <div className="flex flex-col gap-2" data-testid="keys-unprotected">
                  <p className="m-0 text-paragraph-xs text-state-error-base">{t("team.keysNotProtected")}</p>
                  {!st.has_key_file && (
                    <>
                      <p className="m-0 text-paragraph-xs text-text-soft-400">{t("team.keyFileHint")}</p>
                      <Input
                        label={t("team.keyFilePassphrase")}
                        inputSize="small"
                        type="password"
                        autoComplete="new-password"
                        value={keyPass}
                        onChange={(e) => setKeyPass(e.target.value)}
                      />
                      <Input
                        label={t("team.keyFilePassphraseAgain")}
                        inputSize="small"
                        type="password"
                        autoComplete="new-password"
                        value={keyPass2}
                        onChange={(e) => setKeyPass2(e.target.value)}
                      />
                      <div>
                        <Button size="small" disabled={!!busy || !keyPass || !keyPass2} onClick={createKeyFile}>
                          {busy === "keyFile" ? t("busy.protectingKeys") : t("team.protectWithPassphrase")}
                        </Button>
                      </div>
                    </>
                  )}
                </div>
              )}

              {boot?.activated && boot.anchor && (
                <div>
                  <span className="text-paragraph-xs text-text-soft-400">{t("team.bootstrapAnchor")}</span>
                  <CopyField value={boot.anchor} />
                </div>
              )}

              {st.can_receive_custody && st.can_sync && boot && !boot.activated && (
                <div className="flex flex-col gap-2" data-testid="custody-bootstrap">
                  <p className="m-0 text-paragraph-xs text-text-soft-400">
                    {boot.started
                      ? boot.recovery_path
                        ? t("team.custodySetupResumeAt", { path: boot.recovery_path })
                        : t("team.custodySetupResume")
                      : t("team.firstDeviceCustodyHelp")}
                  </p>
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
                  <Input
                    label={t("team.recoveryPassphrase")}
                    inputSize="small"
                    type="password"
                    autoComplete="new-password"
                    value={passphrase}
                    onChange={(e) => setPassphrase(e.target.value)}
                  />
                  <Input
                    label={t("team.recoveryPassphraseAgain")}
                    inputSize="small"
                    type="password"
                    autoComplete="new-password"
                    value={passphrase2}
                    onChange={(e) => setPassphrase2(e.target.value)}
                  />
                  <div>
                    <Button
                      size="small"
                      disabled={!!busy || !username.trim() || !password || !passphrase || !passphrase2}
                      onClick={bootstrap}
                    >
                      {busy === "bootstrap"
                        ? t("busy.settingUpCustody")
                        : boot.started ? t("team.resumeCustodySetup") : t("team.setUpRootCustody")}
                    </Button>
                  </div>
                </div>
              )}

              {st.can_receive_custody ? (
                <>
                  <div>
                    <Button size="small" disabled={!!busy} onClick={collect}>
                      {busy === "collect" ? t("busy.collecting") : t("team.collectKeyCustody")}
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
