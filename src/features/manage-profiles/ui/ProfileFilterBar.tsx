import { useState } from "react";
import { Button, cn } from "@proxyshard/shardx-ui-kit";
import { FilterIcon } from "../../../shared/icons";
import { CSSelect } from "../../../shared/ui/CSSelect";
import { CountryFlag } from "../../../shared/ui/CountryFlag";
import { useProfile, useProfileCountries } from "../../../entities/profile";
import { useT } from "../../../shared/i18n";

/** Status / proxy country / bound-or-direct, behind one button with a count. */
export function ProfileFilterBar() {
  const t = useT();
  const filters = useProfile((s) => s.filters);
  const setFilters = useProfile((s) => s.setFilters);
  const clearFilters = useProfile((s) => s.clearFilters);
  const countries = useProfileCountries();
  const [open, setOpen] = useState(false);

  const active =
    (filters.status !== "all" ? 1 : 0) +
    (filters.country ? 1 : 0) +
    (filters.proxy !== "all" ? 1 : 0);

  return (
    <div className="relative">
      <Button
        variant={active > 0 ? "primary" : "neutral"}
        mode="stroke"
        size="small"
        leftIcon={<FilterIcon className="size-4" />}
        onClick={() => setOpen((v) => !v)}
      >
        {active > 0 ? `Filters · ${active}` : t("profile.filters")}
      </Button>

      {open && (
        <>
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 z-20 mt-1.5 flex w-[260px] flex-col gap-3 rounded-xl bg-bg-white-0 p-3 shadow-[var(--shadow-md)] ring-1 ring-stroke-soft-200">
            <CSSelect
              title={t("profile.status")}
              value={filters.status}
              onChange={(v) => setFilters({ status: v as typeof filters.status })}
              options={[
                { value: "all", label: t("profile.anyStatus") },
                { value: "running", label: t("common.running") },
                { value: "idle", label: t("profile.idle") },
              ]}
            />
            <CSSelect
              title={t("profile.connection")}
              value={filters.proxy}
              onChange={(v) => setFilters({ proxy: v as typeof filters.proxy })}
              options={[
                { value: "all", label: t("profile.anyConnection") },
                { value: "bound", label: t("profile.throughAProxy") },
                { value: "direct", label: t("profile.direct") },
              ]}
            />
            <label className="flex flex-col gap-1">
              <CSSelect
                title={t("profile.proxyCountry")}
                value={filters.country}
                onChange={(v) => setFilters({ country: v })}
                isSearchable={countries.length > 8}
                searchPlaceholder="Search countries…"
                options={[
                  { value: "", label: t("profile.anyCountry") },
                  ...countries.map((c) => ({ value: c, label: c })),
                ]}
              />
              {countries.length > 0 && (
                <span className="flex flex-wrap items-center gap-1 pt-0.5">
                  {countries.slice(0, 12).map((c) => (
                    <button
                      key={c}
                      type="button"
                      title={c}
                      onClick={() => setFilters({ country: filters.country === c ? "" : c })}
                      className={cn(
                        "rounded-4 px-1 py-0.5 ring-1 ring-inset transition-colors",
                        filters.country === c
                          ? "ring-primary-base"
                          : "ring-transparent hover:ring-stroke-soft-200",
                      )}
                    >
                      <CountryFlag cc={c} />
                    </button>
                  ))}
                </span>
              )}
            </label>
            {active > 0 && (
              <Button variant="neutral" mode="ghost" size="2xsmall" onClick={clearFilters}>
                {t("profile.clearFilters")}
              </Button>
            )}
          </div>
        </>
      )}
    </div>
  );
}
