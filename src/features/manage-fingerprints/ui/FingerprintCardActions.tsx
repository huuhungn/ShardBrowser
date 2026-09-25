import { Button } from "@proxyshard/shardx-ui-kit";
import Badge from "../../../shared/ui/Badge";
import { useFingerprint, type FingerprintEntry } from "../../../entities/fingerprint";
import { useT } from "../../../shared/i18n";

export function FingerprintCardActions({ entry }: { entry: FingerprintEntry }) {
  const t = useT();
  const useTemplate = useFingerprint((s) => s.useTemplate);
  const remove = useFingerprint((s) => s.remove);

  return (
    <>
      <Button variant="neutral" mode="stroke" size="2xsmall" onClick={() => useTemplate(entry.id)}>
        {t("fp.useTemplate")}
      </Button>
      {entry.builtin ? (
        <Badge color="gray" variant="lighter" size="small" className="ml-auto">{t("fp.builtIn")}</Badge>
      ) : (
        <Button variant="error" mode="stroke" size="2xsmall" onClick={() => remove(entry.id)} title={t("fp.remove")}>
          ✕
        </Button>
      )}
    </>
  );
}
