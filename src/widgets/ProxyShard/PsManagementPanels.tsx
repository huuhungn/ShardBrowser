import { usePsConnected } from "../../entities/proxyshard";
import { PsResidentialCard, PsOrdersCard, PsBuyCard } from "../../features/proxyshard";
import { useT } from "../../shared/i18n";

export function PsManagementPanels() {
  const t = useT();
  const connected = usePsConnected();

  if (!connected) {
    return (
      <div className="rounded-lg bg-bg-white-0 p-[18px] ring-1 ring-inset ring-stroke-soft-200">
        <p className="m-0 text-paragraph-xs text-text-soft-400">
          {t("ps.addAValidApiKeyAboveToViewTrafficMan")}
        </p>
      </div>
    );
  }

  return (
    <>
      <PsResidentialCard />
      <PsOrdersCard />
      <PsBuyCard />
    </>
  );
}
