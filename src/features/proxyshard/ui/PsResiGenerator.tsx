import { useEffect, useState } from "react";
import { DialogModal, SegmentControl, SelectOption, Tooltip } from "@proxyshard/shardx-ui-kit";
import { Field } from "../../../shared/ui/Field";
import { NumField } from "../../../shared/ui/NumField";
import { CSSelect } from "../../../shared/ui/CSSelect";
import { ChevronDownIcon, InfoIcon } from "../../../shared/icons";
import { toast } from "../../../shared/model/toast";
import { randSid, safeUiError } from "../../../shared/lib/utils";
import type { ResiType, PsLoc } from "../../../entities/proxyshard";
import { PS_PLAN, PS_PROXY_TYPE, PS_RELAYS, PS_PORT, psProfileTraffic, psCountries, psRegions, psCities } from "../../../entities/proxyshard";
import { proxyBulkSave } from "../../../entities/proxy";
import { useT } from "../../../shared/i18n";


// A label is built when it is drawn, not when the module loads: a list built
// once at import time keeps whichever language was active then, and a reader
// who switches to Vietnamese goes on reading English until the app restarts.
type Tr = ReturnType<typeof useT>;

const sessionModeOptions = (t: Tr): SelectOption[] => [
  { label: t("ps.defaultAfter5sec"), value: "default" },
  { label: t("ps.static"), value: "static" },
];

const pofOptions = (t: Tr): SelectOption[] => [
  { label: t("ps.unset"), value: "unset" },
  { label: t("ps.macos"), value: "macos" },
  { label: t("ps.windows"), value: "windows" },
  { label: t("ps.android"), value: "android" },
  { label: t("ps.linux"), value: "linux" },
  { label: t("ps.ios"), value: "ios" },
];

const protoOptions = (t: Tr): SelectOption[] => [
  { value: "http", label: t("ps.http") },
  { value: "socks5", label: t("ps.socks5") },
];

const sessionOptions = (t: Tr): SelectOption[] => [
  { value: "rotating", label: t("ps.rotating") },
  { value: "sticky", label: t("ps.sticky") },
];

export function PsResiGenerator({ type, onClose }: { type: ResiType; onClose: () => void }) {
  const t = useT();
  const plan = PS_PLAN[type];
  const pt = PS_PROXY_TYPE[type];
  const [password, setPassword] = useState("");
  const [pwErr, setPwErr] = useState("");
  const [relay, setRelay] = useState(PS_RELAYS[0]);
  const [proto, setProto] = useState<"http" | "socks5">("socks5");
  const [session, setSession] = useState<"rotating" | "sticky">("sticky");
  const [count, setCount] = useState(1);
  const [prefix, setPrefix] = useState(`${type} resi`);
  const [sessionMode, setSessionMode] = useState<"default" | "static">("default");
  // setPof is unused today — the generator reads `pof` when building the
  // session string but nothing changes it yet.  Kept as state (not a const)
  // so wiring the OS selector back up is a one-line change.
  const [pof] = useState<"unset" | "macos" | "windows" | "android" | "linux" | "ios">("unset");
  const [showAdvanced, setShowAdvanced] = useState(false);


  const [countries, setCountries] = useState<PsLoc[]>([]);
  const [country, setCountry] = useState("");
  const [regions, setRegions] = useState<PsLoc[]>([]);
  const [region, setRegion] = useState("");
  const [cities, setCities] = useState<PsLoc[]>([]);
  const [city, setCity] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    psProfileTraffic(pt)
      .then((r) => {
        const p = r.proxy_password ?? r.password ?? "";
        setPassword(p);
        if (!p) setPwErr(t("ps.theAPIDidnTReturnAResidentialPasswordF"));
      })
      .catch((e) => setPwErr(safeUiError(e)));
    psCountries(pt)
      .then((r) => setCountries(r.results ?? []))
      .catch((e) => toast.err(safeUiError(e)));
  }, [pt]);

  // Region depends on country; city depends on region.
  useEffect(() => {
    setRegion(""); setRegions([]); setCity(""); setCities([]);
    if (!country) return;
    psRegions(pt, country)
      .then((r) => setRegions(r.results ?? [])).catch(() => { });
  }, [country]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    setCity(""); setCities([]);
    if (!country || !region) return;
    psCities(pt, country, region)
      .then((r) => setCities(r.results ?? [])).catch(() => { });
  }, [region]); // eslint-disable-line react-hooks/exhaustive-deps

  const buildUser = (sid: string | null) => {
    const parts = [`plan-${plan}`];
    if (country) parts.push(`country-${country.toLowerCase()}`);
    if (region) parts.push(`region-${region}`);
    if (city) parts.push(`city-${city}`);
    if (sid) parts.push(`sid-${sid}`);
    if (pof && pof !== "unset") parts.push(`os-${pof}`);
    if (sessionMode === "default") parts.push("session_mode-2");
    return parts.join("-");
  };
  const sampleUser = buildUser(session === "sticky" ? "‹sid›" : null);

  const generate = async () => {
    if (!password) { toast.err(t("ps.noResidentialPasswordAvailableFromTheA")); return; }
    const port = PS_PORT[proto];
    const n = Math.max(1, Math.round(count));
    const entries = Array.from({ length: n }, (_, i) => ({
      id: "",
      name: `${prefix.trim() || "resi"}${country ? " " + country.toUpperCase() : ""}${n > 1 ? ` #${i + 1}` : ""}`,
      kind: proto,
      host: relay,
      port,
      username: buildUser(session === "sticky" ? randSid() : null),
      password,
      country: country ? country.toUpperCase() : "",
      notes: t("ps.residentialPlan", { plan }),
    }));
    setSaving(true);
    try {
      const added = await proxyBulkSave(entries);
      toast.ok(added > 0 ? t(added === 1 ? "ps.addedProxyOne" : "ps.addedProxyMany", { n: added }) : t("ps.noNewProxiesDuplicates"));
     // onClose();
    } catch (e) { toast.err(safeUiError(e)); }
    finally { setSaving(false); }
  };

  return (
    <DialogModal
      open
      onClose={onClose}
      title={t("ps.generateResidential", { plan })}
      maxWidthClassName="max-w-[880px]"
      confirmLabel={saving ? t("ps.generating") : t("ps.generateCount", { n: Math.max(1, Math.round(count)) })}
      onConfirm={generate}
      isLoading={saving}
      isDisabled={saving || !password}
      cancelLabel={t("common.cancel")}
      onCancel={onClose}
    >
      <div className="flex flex-col gap-3 py-4 w-[450px]">
        <div className="grid grid-cols-2 gap-3">
          <CSSelect
            value={relay}
            title={t("ps.relay")}
            onChange={setRelay}
            options={PS_RELAYS.map((r) => ({ value: r, label: r }))}
          />

          <label className="flex flex-col gap-1">
            <span className="text-label-base font-medium text-text-strong-900">{t("ps.protocol")}</span>
            <SegmentControl
              size="small"
              value={proto}
              items={protoOptions(t)}
              onChange={(v) => setProto(v as "http" | "socks5")}
            />
          </label>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <CSSelect
            value={country}
            title={t("ps.country")}
            onChange={setCountry}
            placeholder={t("common.any")}
            isSearchable
            searchPlaceholder="Search countries…"
            options={[{ value: "", label: t("common.any") }, ...countries.map((c) => ({ value: c.code, label: `${c.name} (${c.code})` }))]}
          />
          <label className="flex flex-col gap-1">
            <span className="text-label-base font-medium text-text-strong-900">{t("ps.session")}</span>
            <SegmentControl
              size="small"
              value={session}
              items={sessionOptions(t)}
              onChange={(v) => setSession(v as "rotating" | "sticky")}
            />
          </label>
        </div>
        <div className="grid grid-cols-2 gap-3">
          <CSSelect
            value={region}
            title={t("ps.region")}
            onChange={setRegion}
            placeholder={country ? t("ps.any") : t("ps.pickCountryFirst")}
            isSearchable
            searchPlaceholder="Search regions…"
            options={[{ value: "", label: t("common.any") }, ...regions.map((r) => ({ value: r.code, label: r.name }))]}
          />

          <CSSelect
            value={city}
            title={t("ps.city")}
            onChange={setCity}
            placeholder={region ? t("ps.any") : t("ps.pickRegionFirst")}
            isSearchable
            searchPlaceholder="Search cities…"
            options={[{ value: "", label: t("common.any") }, ...cities.map((c) => ({ value: c.code, label: c.name }))]}
          />
          {
            type === "premium" && (
              <CSSelect
                value={city}
                title={t("ps.deviceOS")}
                onChange={setCity}
                placeholder={t("ps.selectDeviceOS")}
                options={pofOptions(t)}
              />
            )
          }
        </div>
        <div className="grid grid-cols-2 gap-3">
          <Field label={t("ps.namePrefix")} value={prefix} onChange={setPrefix} />
          <NumField label={session === "sticky" ? t("ps.countRandomSidEach") : t("ps.count")} value={count} onChange={(v) => setCount(Math.max(1, Math.round(v)))} />
        </div>
        <div className="flex flex-col gap-3">
          {
            type === "premium" && (
              <button
                type="button"
                aria-expanded={showAdvanced}
                onClick={() => setShowAdvanced((v) => !v)}
                className="flex w-fit items-center gap-2 rounded-lg text-label-sm font-medium text-text-soft-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary-base"
              >
                {t("ps.advancedSettings")}
                <ChevronDownIcon
                  aria-hidden="true"
                  className={`size-4 transition-transform duration-200 ${showAdvanced ? "rotate-180" : ""}`}
                />
              </button>
            )
          }
          {showAdvanced && (
            <div className="flex flex-col gap-1">
              <div className="flex items-center gap-1">
                <span className="text-label-base font-medium text-text-strong-900">{t("ps.sessionMode")}</span>
                <Tooltip
                  content={t("ps.sessionModeHelp")}
                  side="top"
                  className="left-20"
                >
                  <InfoIcon className="size-4 cursor-help text-text-soft-400" />
                </Tooltip>
              </div>
              <CSSelect
                value={sessionMode}
                onChange={(v) => setSessionMode(v as "default" | "static")}
                options={sessionModeOptions(t)}
              />
            </div>
          )}
        </div>
        <div className="mono mt-1.5 break-all rounded-8 bg-bg-weak-50 px-[11px] py-[9px] text-paragraph-xs text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200">
          {relay}:{PS_PORT[proto]}:{sampleUser}:{password ? "••••" : "?"}
        </div>
        <span className="text-label-sm font-medium text-text-soft-400">{t("ps.resiNote")}</span>
        {pwErr && <p className="m-0 text-paragraph-xs text-text-soft-400">{pwErr}</p>}
      </div>
    </DialogModal>
  );
}
