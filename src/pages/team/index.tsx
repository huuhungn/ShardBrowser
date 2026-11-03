import { Topbar } from "../../shared/ui/Topbar";
import { TeamCard } from "../../features/manage-team/ui/TeamCard";
import { TeamProfiles } from "../../features/manage-team/ui/TeamProfiles";
import { useT } from "../../shared/i18n";

export function TeamPage() {
  const t = useT();
  return (
    <section className="flex flex-col">
      <Topbar crumbs={[t("nav.system"), t("settings.team.title")]} />
      <h1 className="m-0 mb-3.5 text-title-h5 text-text-strong-950">{t("settings.team.title")}</h1>
      <TeamProfiles />
      <div className="rounded-lg bg-bg-white-0 p-[18px] shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
        <TeamCard />
      </div>
    </section>
  );
}
