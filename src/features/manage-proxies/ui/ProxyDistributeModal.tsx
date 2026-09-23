import { useEffect, useMemo, useState } from "react";
import { Checkbox, DialogModal, SegmentControl, cn } from "@proxyshard/shardx-ui-kit";
import { CSSelect } from "../../../shared/ui/CSSelect";
import { useProxy } from "../../../entities/proxy";
import { useT } from "../../../shared/i18n";

/** Spreads the selected proxies over the chosen profiles, paired by position —
 *  which is why both lists are shown rather than just their counts. */
export function ProxyDistributeModal({ onClose }: { onClose: () => void }) {
  const t = useT();
  const proxies = useProxy((s) => s.proxies);
  const proxySel = useProxy((s) => s.proxySel);
  const profiles = useProxy((s) => s.profiles);
  const distribute = useProxy((s) => s.distribute);

  const picked = useMemo(
    () => proxies.filter((p) => proxySel.has(p.id)),
    [proxies, proxySel],
  );

  const folders = useMemo(() => {
    const set = new Set<string>();
    for (const p of profiles) if (p.folder) set.add(p.folder);
    return [...set].sort();
  }, [profiles]);

  const [folder, setFolder] = useState("all");
  // Unbound profiles by default: distributing proxies over profiles that
  // already have one is how two of them end up behind the same IP without
  // anyone meaning it. "All profiles" is there for a deliberate re-shuffle.
  const [scope, setScope] = useState<"unbound" | "all">("unbound");
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);

  const candidates = useMemo(
    () =>
      profiles.filter(
        (p) =>
          (folder === "all" || p.folder === folder) &&
          (scope === "all" || !p.proxy_id),
      ),
    [profiles, folder, scope],
  );

  // The list is what the filters say; re-pick everything whenever they change
  // rather than leaving a selection the operator can no longer see.
  useEffect(() => {
    setChosen(new Set(candidates.map((p) => p.id)));
  }, [candidates]);

  const targets = candidates.filter((p) => chosen.has(p.id));
  const boundCount = targets.filter((p) => p.proxy_id).length;
  const willBind = Math.min(targets.length, picked.length);

  const run = async () => {
    setBusy(true);
    try { await distribute(targets.map((p) => p.id)); onClose(); }
    finally { setBusy(false); }
  };

  return (
    <DialogModal
      open
      onClose={onClose}
      title={`Distribute ${picked.length} prox${picked.length === 1 ? "y" : "ies"}`}
      maxWidthClassName="max-w-[760px]"
      confirmLabel={willBind === 0 ? t("proxy.nothingToBind") : `Bind ${willBind}`}
      onConfirm={run}
      isLoading={busy}
      isDisabled={busy || willBind === 0}
      cancelLabel={t("common.cancel")}
      onCancel={onClose}
    >
      <div className="flex flex-col gap-3.5 py-4">
        <div className="grid grid-cols-2 gap-3">
          <CSSelect
            title={t("proxy.profilesFrom")}
            value={folder}
            onChange={setFolder}
            isSearchable={folders.length > 8}
            options={[
              { value: "all", label: t("proxy.everyFolder") },
              ...folders.map((f) => ({ value: f, label: f })),
            ]}
          />
          <label className="flex flex-col gap-1">
            <span className="text-label-base font-medium text-text-strong-900">{t("proxy.applyTo")}</span>
            <SegmentControl
              size="small"
              className="w-full *:flex-1"
              value={scope}
              items={[
                { value: "unbound", label: t("proxy.withoutAProxy") },
                { value: "all", label: t("proxy.allProfiles") },
              ]}
              onChange={(v) => setScope(v as "unbound" | "all")}
            />
          </label>
        </div>

        {scope === "all" && boundCount > 0 && (
          <p className="m-0 rounded-8 bg-warning-alpha-16 px-2.5 py-1.5 text-paragraph-xs text-text-sub-600 ring-1 ring-inset ring-warning-base/30">
            {boundCount} of the profiles below already {boundCount === 1 ? "has a proxy" : "have proxies"} — binding replaces {boundCount === 1 ? "it" : "them"}.
          </p>
        )}

        <div className="grid grid-cols-2 gap-3">
          <div className="flex flex-col gap-1.5">
            <span className="text-subheading-2xs text-text-soft-400">
              Proxies · {picked.length}
            </span>
            <div className="max-h-[240px] overflow-auto rounded-8 ring-1 ring-inset ring-stroke-soft-200">
              {picked.map((p, i) => (
                <div
                  key={p.id}
                  className={cn(
                    "flex items-center gap-2 border-t border-stroke-soft-200 px-2.5 py-1.5 first:border-t-0",
                    i >= targets.length && "opacity-40",
                  )}
                >
                  <span className="mono w-5 shrink-0 text-[10.5px] text-text-disabled-300">{i + 1}</span>
                  <span className="min-w-0 flex-1 truncate text-paragraph-xs text-text-sub-600">
                    {p.name || `${p.host}:${p.port}`}
                  </span>
                  {p.country && (
                    <span className="shrink-0 text-[10.5px] font-bold tracking-[0.5px] text-text-soft-400">
                      {p.country}
                    </span>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <span className="text-subheading-2xs text-text-soft-400">
              Profiles · {targets.length} of {candidates.length}
            </span>
            <div className="max-h-[240px] overflow-auto rounded-8 ring-1 ring-inset ring-stroke-soft-200">
              {candidates.map((p, i) => {
                const on = chosen.has(p.id);
                const beyond = on && i >= picked.length;
                return (
                  <label
                    key={p.id}
                    className={cn(
                      "flex cursor-pointer items-center gap-2 border-t border-stroke-soft-200 px-2.5 py-1.5 first:border-t-0 hover:bg-bg-weak-50",
                      beyond && "opacity-40",
                    )}
                  >
                    <Checkbox
                      checked={on}
                      onChange={() => {
                        const next = new Set(chosen);
                        if (on) next.delete(p.id); else next.add(p.id);
                        setChosen(next);
                      }}
                    />
                    <span className="mono w-5 shrink-0 text-[10.5px] text-text-disabled-300">{i + 1}</span>
                    <span className="min-w-0 flex-1 truncate text-paragraph-xs text-text-sub-600">
                      {p.name}
                    </span>
                  </label>
                );
              })}
              {candidates.length === 0 && (
                <div className="px-2.5 py-4 text-center text-paragraph-xs text-text-soft-400">
                  {t("proxy.noProfilesMatchTryAnotherFolderOrUnt")}
                </div>
              )}
            </div>
          </div>
        </div>

        <p className="m-0 text-paragraph-xs text-text-soft-400">
          {t("proxy.pairsAreMadeInTheOrderShownOneProxyE")}
        </p>
      </div>
    </DialogModal>
  );
}
