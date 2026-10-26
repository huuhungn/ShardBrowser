import { Button } from "@proxyshard/shardx-ui-kit";
import Badge from "../../../shared/ui/Badge";
import { DeleteIcon } from "../../../shared/icons";
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
        // Quiet on purpose: on a library of hundreds of cards a red button on each drowns the cards.
        <Button
          variant="neutral" mode="ghost" size="2xsmall" onlyIcon className="ml-auto"
          onClick={() => remove(entry.id)}
          title={t("fp.remove")}
          aria-label={t("fp.removeFingerprintNamed", { label: entry.label })}
        >
          <DeleteIcon className="size-3.5" />
        </Button>
      )}
    </>
  );
}
