import { useEffect, useState } from "react";
import { Button, Checkbox, Input } from "@proxyshard/shardx-ui-kit";
import { CopyField } from "../../../shared/ui/CopyField";
import { toast } from "../../../shared/model/toast";
import {
  teamStatus, teamSetConnection, teamTestConnection,
  teamEnrollDevice, teamCollectCustody, useTeam,
  teamCustodyBootstrapStatus, teamBootstrapCustody,
  teamKeysCreateFile, teamKeysUnlock,
  teamEnrollAgain, teamExportRecoveryBundle, teamImportRecoveryBundle, teamFleetCustodyStatus,
  teamRenewCustody,
  type TeamStatus, type CustodyBootstrapStatus, type CustodyResult,
} from "../../../entities/team";
import { open as openDialog, save as saveDialog } from "@tauri-apps/plugin-dialog";
import { TeamDevices, type TeamAccount } from "./TeamDevices";
import { TeamJoin } from "./TeamJoin";

/** The recovery bundle's passphrase floor, as the backend seals it. */
const MIN_RECOVERY_PASSPHRASE = 8;
/** How long a root custodian's signing key counts as one (`MAX_CUSTODIAN_KEY_AGE_MS`). */
const KEY_AGE_MS = 1095 * 86_400_000;
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
  // The root state did not read: this device may be the root custodian, so no Reset until it does.
  const [bootUnreadable, setBootUnreadable] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [passphrase2, setPassphrase2] = useState("");
  const [keyPass, setKeyPass] = useState("");
  const [keyPass2, setKeyPass2] = useState("");
  const [oldDeviceLost, setOldDeviceLost] = useState(false);
  const [rootKeyIdRecorded, setRootKeyIdRecorded] = useState(false);
  const [exportDue, setExportDue] = useState(false);

  const shareStatus = useTeam((s) => s.refresh);

  const loadBoot = () =>
    teamCustodyBootstrapStatus()
      .then((b) => { setBoot(b); setBootUnreadable(false); })
      .catch(() => { setBoot(null); setBootUnreadable(true); });
  // A finished fleet key rotation asks for the recovery bundle again.
  const loadExportDue = () =>
    teamFleetCustodyStatus().then((f) => setExportDue(f.export_due)).catch(() => {});

  const refresh = () => {
    teamStatus().then((s) => {
      setSt(s);
      setUrl(s.server_url);
      setTenant(s.tenant_id);
    }).catch(() => {});
    void loadBoot();
    void loadExportDue();
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
    const typed = password;
    setPassword("");
    const id = await teamTestConnection(username, typed);
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

  /** The floor and the match check every new passphrase has to pass. */
  const passphrasesAgree = (a: string, b: string) => {
    if (a.length < MIN_RECOVERY_PASSPHRASE) {
      toast.err(t("team.recoveryPassphraseTooShort", { n: MIN_RECOVERY_PASSPHRASE }));
      return false;
    }
    if (a !== b) {
      toast.err(t("team.recoveryPassphrasesDiffer"));
      return false;
    }
    return true;
  };

  const createKeyFile = () => run("keyFile", async () => {
    if (!passphrasesAgree(keyPass, keyPass2)) return;
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
    if (!passphrasesAgree(passphrase, passphrase2)) return;
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
      void loadBoot();
      throw e;
    }
  });

  const exportBundle = () => run("export", async () => {
    if (!passphrasesAgree(passphrase, passphrase2)) return;
    const path = await saveDialog({
      defaultPath: "shardx-recovery.shxrecovery",
      filters: [{ name: t("team.recoveryBundle"), extensions: ["shxrecovery"] }],
    });
    if (typeof path !== "string") return; // cancelled
    const typed = password;
    setPassword("");
    await teamExportRecoveryBundle(username.trim(), typed, path, passphrase);
    setPassphrase("");
    setPassphrase2("");
    setRootKeyIdRecorded(false);
    void loadExportDue();
    toast.ok(t("team.recovery.exported", { path }));
  });

  const importBundle = () => run("import", async () => {
    const path = await openDialog({
      multiple: false,
      directory: false,
      filters: [{ name: t("team.recoveryBundle"), extensions: ["shxrecovery"] }],
    });
    if (typeof path !== "string") return; // cancelled
    const typed = password;
    setPassword("");
    try {
      const r = await teamImportRecoveryBundle(path, passphrase, username.trim(), typed, oldDeviceLost);
      setPassphrase("");
      setOldDeviceLost(false);
      toast.ok(t("team.recovery.imported"));
      report(r);
    } finally {
      // A failed collect after the import still leaves this device the root custodian.
      refresh();
      void shareStatus();
    }
  });

  const reset = () => run("reset", async () => {
    const typed = password;
    setPassword("");
    setSt(await teamEnrollAgain(username.trim(), typed));
    void shareStatus();
    toast.ok(t("team.joinCode.enrollAgainDone"));
  });

  /** Toasts what a collect report says: grants opened, the fleet key kept, waiting or refused. */
  const report = (r: CustodyResult) => {
    if (r.fleet_opened > 0) {
      toast.ok(t("team.fleetKeyCollected", { n: r.newest_fleet_generation ?? 0 }));
    }
    if (r.grants === 0) {
      if (r.fleet_grants_waiting === 0 && r.fleet_opened === 0) {
        toast.info(t("team.noGrantsWaitingACustodianDeviceHasToIs"));
      }
    } else if (r.failed > 0) {
      toast.err(t("team.grantsOpened", { opened: r.opened, grants: r.grants, failed: r.failed }));
    } else {
      if (r.opened > 0) {
        const gen =
          r.newest_generation == null
            ? ""
            : t("team.generationSuffix", { n: r.newest_generation });
        toast.ok(t("team.rootCustody", { opened: r.opened, gen }));
      } else {
        toast.err(t("team.noGrantsAreWaitingForThisDeviceYet"));
      }
    }
    if (r.fleet_refusal) {
      toast.err(t("team.fleetKeySubstituted"));
    } else if (r.fleet_enroll_again) {
      toast.err(t("fleet.enrollAgainMissedRotations"));
    } else if (r.fleet_failed > 0) {
      toast.err(t("team.fleetKeyFailed"));
    } else if (r.fleet_grants_waiting > 0) {
      toast.info(t("team.fleetKeyWaiting"));
    }
    // A kept fleet key turns has_fleet_key on, which ends the join steps.
    if (r.fleet_opened > 0) teamStatus().then(setSt).catch(() => {});
  };

  const renew = () => run("renew", async () => {
    const typed = password;
    setPassword("");
    const outcome = await teamRenewCustody(username.trim(), typed);
    void loadBoot();
    void loadExportDue();
    toast.ok(t(outcome === "renewed" ? "team.renewal.done" : "team.renewal.notDue"));
  });

  const collect = () => run("collect", async () => {
    const typed = password;
    setPassword("");
    report(await teamCollectCustody(username, typed));
  });

  // A device session needs no token: the token only serves legacy passphrase sync.
  const connected = !!st && !!st.server_url && !!st.tenant_id;
  // Nothing past the device's own seeds works while they cannot be read.
  const lost = !!st && (st.keys_lost || st.key_store_unavailable);
  // Only this device's root state makes it the root custodian. Another device's, kept by a connection change,
  // offers no setup: the backend refuses to start or resume over it.
  const setupOpen = !!boot && (boot.this_device ? !boot.activated : !boot.started);
  // Root custody renewal (v2.10 4.R): renewing is due from half the records' life,
  // and the warning shows from 75%, halfway from the renewal point to the end.
  const now = Date.now();
  const day = (ms: number) => new Date(ms).toLocaleDateString();
  const renewalDue = boot?.renewal_due_ms ?? null;
  const custodyEnds = boot?.custody_ends_ms ?? null;
  const keyAgeEnds = boot?.key_age_ends_ms ?? null;
  const renewalWarning = renewalDue !== null && custodyEnds !== null
    && now >= renewalDue + (custodyEnds - renewalDue) / 2;
  const keyAgeWarning = keyAgeEnds !== null && now >= keyAgeEnds - KEY_AGE_MS / 4;

  const account: TeamAccount = {
    username,
    signedIn: !!username.trim() && !!password,
    take: () => { setPassword(""); return password; },
  };

  // Restoring the root custodian: on a fresh device, or on its own machine once its keys are lost.
  const importForm = (
    <div data-testid="team-import" className="flex flex-col gap-2 border-t border-stroke-soft-200 pt-2">
      <p className="m-0 text-paragraph-xs text-text-soft-400">{t("team.recovery.importHelp")}</p>
      <Input
        label={t("team.recoveryPassphrase")}
        inputSize="small"
        type="password"
        autoComplete="off"
        value={passphrase}
        onChange={(e) => setPassphrase(e.target.value)}
      />
      <Checkbox
        label={t("team.recovery.oldDeviceLost")}
        checked={oldDeviceLost}
        onChange={() => setOldDeviceLost((v) => !v)}
      />
      <div>
        <Button
          size="small"
          mode="stroke"
          disabled={!!busy || !connected || !username.trim() || !password || !passphrase || !oldDeviceLost}
          onClick={importBundle}
        >
          {busy === "import" ? t("busy.importing") : t("team.recovery.import")}
        </Button>
      </div>
    </div>
  );

  return (
    <div data-testid="team-card" className="flex flex-col gap-2">
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
              {st.keys_unreadable && (
                <p className="m-0 text-paragraph-xs text-state-error-base">
                  {t("keyStore.otherWindowsAccount")}
                </p>
              )}
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
                  {t("team.saveServerAndTenantFirst")}
                </p>
              )}
              {importForm}
            </>
          ) : (
            <>
              <div>
                <span className="text-paragraph-xs text-text-soft-400">Device ID</span>
                <CopyField value={st.device_id} />
              </div>
              {st.signing_key_id && (
                <div data-testid="team-own-key-ids" className="flex flex-col gap-2">
                  <div>
                    <span className="text-paragraph-xs text-text-soft-400">{t("team.devices.signingKeyId")}</span>
                    <CopyField value={st.signing_key_id} />
                  </div>
                  <div>
                    <span className="text-paragraph-xs text-text-soft-400">{t("team.devices.hpkeKeyId")}</span>
                    <CopyField value={st.hpke_key_id} />
                  </div>
                </div>
              )}

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

              {boot?.this_device && boot.activated && boot.anchor && (
                <div>
                  <span className="text-paragraph-xs text-text-soft-400">{t("team.bootstrapAnchor")}</span>
                  <CopyField value={boot.anchor} />
                </div>
              )}

              {!lost && st.can_receive_custody && st.can_sync && boot && setupOpen && (
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

              {bootUnreadable && !lost && (
                <p data-testid="team-root-state-unreadable" className="m-0 text-paragraph-xs text-state-error-base">
                  {t("team.recovery.rootStateUnreadable")}
                </p>
              )}

              {lost ? (
                <div className="flex flex-col gap-2" data-testid="team-keys-lost">
                  {/* Until the root state reads, this device may be the root custodian: nothing to act on yet. */}
                  {(boot || bootUnreadable) && (
                    <p
                      data-testid={bootUnreadable ? "team-root-state-unreadable" : undefined}
                      className="m-0 text-paragraph-xs text-state-error-base"
                    >
                      {t(bootUnreadable
                        ? "team.recovery.rootStateUnreadable"
                        : boot?.this_device
                          ? !boot.activated
                            ? st.key_store_unavailable
                              ? "team.recovery.rootSetupKeyStoreUnavailable" : "team.recovery.rootSetupInterrupted"
                            : st.key_store_unavailable ? "team.recovery.rootKeyStoreUnavailable" : "team.recovery.rootKeysLost"
                          : st.key_store_unavailable ? "team.recovery.keyStoreUnavailable" : "team.recovery.keysLost")}
                    </p>
                  )}
                  {/* A root custodian whose store only did not answer, or whose setup never finished, has nothing to sign in for. */}
                  {boot && (!boot.this_device || (boot.activated && st.keys_lost)) && (
                    <>
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
                    </>
                  )}
                  {/* This device's saved root setup, finished or not, is never reset (the backend refuses it). A
                      finished one comes back from its recovery bundle; an unfinished one saved no anchor, so
                      import refuses it too. */}
                  {!boot ? null : boot.this_device ? boot.activated && st.keys_lost && importForm : (
                    <div>
                      <Button
                        size="small"
                        variant="error"
                        mode="stroke"
                        disabled={!!busy || !username.trim() || !password}
                        onClick={reset}
                      >
                        {busy === "reset" ? t("busy.resetting") : t("team.recovery.reset")}
                      </Button>
                    </div>
                  )}
                </div>
              ) : st.can_receive_custody ? (
                <>
                  {/* The bootstrap form above already holds the account login. */}
                  {!(st.can_sync && setupOpen) && (
                    <>
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
                    </>
                  )}
                  {st.can_sync && boot && (boot.this_device && boot.activated ? (
                    <TeamDevices
                      account={account} busy={busy} run={run} anchor={boot.anchor} selfId={st.device_id}
                      hasFleetKey={st.has_fleet_key} fleetKeyBlocked={st.fleet_key_blocked}
                      onFleetKey={() => { teamStatus().then(setSt).catch(() => {}); void loadExportDue(); }}
                    />
                  ) : st.has_fleet_key ? (
                    <p data-testid="team-joined" className="m-0 text-paragraph-xs text-text-sub-600">
                      {t("team.joinCode.joined")}
                    </p>
                  ) : st.fleet_key_blocked ? (
                    <p data-testid="team-key-blocked" className="m-0 text-paragraph-xs text-state-error-base">
                      {t("team.joinCode.blocked")}
                    </p>
                  ) : (
                    <TeamJoin
                      account={account}
                      busy={busy}
                      run={run}
                      onEnrolledAgain={(next) => { setSt(next); void shareStatus(); }}
                    />
                  ))}
                  {st.can_sync && boot?.this_device && boot.activated && renewalDue !== null && custodyEnds !== null && (
                    <div data-testid="team-renewal" className="flex flex-col gap-1.5 border-t border-stroke-soft-200 pt-2">
                      <span className="text-label-xs text-text-strong-950">{t("team.renewal.title")}</span>
                      {renewalWarning ? (
                        <p data-testid="team-renewal-warning" className="m-0 text-paragraph-xs text-state-error-base">
                          {t("team.renewal.warning", { date: day(custodyEnds) })}
                        </p>
                      ) : (
                        <p className="m-0 text-paragraph-xs text-text-soft-400">
                          {t("team.renewal.dates", { due: day(renewalDue), ends: day(custodyEnds) })}
                        </p>
                      )}
                      {keyAgeEnds !== null && (
                        <p
                          data-testid="team-renewal-key-age"
                          className={`m-0 text-paragraph-xs ${keyAgeWarning ? "text-state-error-base" : "text-text-soft-400"}`}
                        >
                          {t(keyAgeWarning ? "team.renewal.keyAgeWarning" : "team.renewal.keyAge", { date: day(keyAgeEnds) })}
                        </p>
                      )}
                      {now >= renewalDue && (
                        <div>
                          <Button
                            size="small" mode="stroke"
                            disabled={!!busy || !username.trim() || !password}
                            onClick={renew}
                          >
                            {busy === "renew" ? t("team.renewal.busy") : t("team.renewal.renew")}
                          </Button>
                        </div>
                      )}
                    </div>
                  )}
                  {st.can_sync && boot?.this_device && boot.activated && (
                    <div data-testid="team-export" className="flex flex-col gap-2 border-t border-stroke-soft-200 pt-2">
                      {exportDue && (
                        <p data-testid="team-export-due" className="m-0 text-paragraph-xs text-state-error-base">
                          {t("team.rotation.exportDue")}
                        </p>
                      )}
                      <p className="m-0 text-paragraph-xs text-text-soft-400">{t("team.devices.recoveryNotice")}</p>
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
                      {/* The owner's fingerprint ceremony (ADR 0002 D-5): the root key ID, recorded before export. */}
                      {boot.root_key_id && (
                        <>
                          <div>
                            <span className="text-paragraph-xs text-text-soft-400">{t("team.recovery.rootKeyId")}</span>
                            <CopyField value={boot.root_key_id} />
                          </div>
                          <Checkbox
                            label={t("team.recovery.rootKeyIdRecorded")}
                            checked={rootKeyIdRecorded}
                            onChange={() => setRootKeyIdRecorded((v) => !v)}
                          />
                        </>
                      )}
                      <div>
                        <Button
                          size="small"
                          mode="stroke"
                          disabled={!!busy || !(st.has_fleet_key || st.fleet_key_blocked) || !boot.root_key_id
                            || !rootKeyIdRecorded || !username.trim() || !password || !passphrase || !passphrase2}
                          onClick={exportBundle}
                        >
                          {busy === "export" ? t("busy.exporting") : t("team.recovery.export")}
                        </Button>
                      </div>
                      {!(st.has_fleet_key || st.fleet_key_blocked) && (
                        <p className="m-0 text-paragraph-xs text-text-soft-400">{t("team.recovery.exportNeedsFleetKey")}</p>
                      )}
                      {!boot.root_key_id && (
                        <p data-testid="team-export-no-root-key-id" className="m-0 text-paragraph-xs text-state-error-base">
                          {t("team.recovery.exportNeedsRootKeyId")}
                        </p>
                      )}
                    </div>
                  )}
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
