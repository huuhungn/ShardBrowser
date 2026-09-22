import { useEffect } from "react";
import { Topbar } from "../../shared/ui/Topbar";
import { useFingerprint } from "../../entities/fingerprint";
import { FingerprintImporter } from "../../features/manage-fingerprints";
import { FingerprintLibrary } from "../../widgets/FingerprintLibrary/FingerprintLibrary";
import { FingerprintToolbar } from "../../widgets/FingerprintLibrary/FingerprintToolbar";
import { useT } from "../../shared/i18n";
import { Rich } from "../../shared/i18n/Rich";

export function FingerprintsPage() {
  const t = useT();
  const init = useFingerprint((s) => s.init);
  const reload = useFingerprint((s) => s.reload);
  const importerOpen = useFingerprint((s) => s.importerOpen);
  const setImporterOpen = useFingerprint((s) => s.setImporterOpen);

  useEffect(() => { init(); }, [init]);

  return (
    <section className="flex flex-col">
      <Topbar crumbs={[t("nav.library"), t("fingerprints.crumb")]} />
      <div className="mb-3.5 flex items-end justify-between gap-4">
        <h1 className="m-0 text-title-h5 text-text-strong-950">{t("fingerprints.title")}</h1>
        <FingerprintToolbar />
      </div>
      <p className="m-0 mb-3.5 text-paragraph-xs text-text-soft-400">
        <Rich text={t("fingerprints.intro")} />
      </p>
      <FingerprintLibrary />
      {importerOpen && (
        <FingerprintImporter onClose={() => { setImporterOpen(false); reload(); }} />
      )}
    </section>
  );
}
