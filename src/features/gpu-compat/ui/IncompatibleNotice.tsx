import { useState } from "react";
import { Modal, Button } from "@proxyshard/shardx-ui-kit";
import Badge from "../../../shared/ui/Badge";
import { useGpuCompat } from "../../../shared/model/gpuCompat";
import { useT } from "../../../shared/i18n";
import type { GpuCompat } from "../../../entities/fingerprint/model/types";

/// The one text that explains an incompatible fingerprint, used by both the
/// badge and the warning dialog — so the operator reads the same reason
/// wherever they meet it.
export function IncompatibleExplainer({ compat }: { compat: GpuCompat }) {
  const t = useT();
  const caps = useGpuCompat((s) => s.caps);
  const missing = [...compat.missing_webgl1, ...compat.missing_webgl2];
  const unique = Array.from(new Set(missing));
  const gpuMissing = Array.from(new Set(compat.missing_webgpu ?? []));
  return (
    <div className="flex flex-col gap-3 text-paragraph-sm text-text-sub-600">
      <p className="m-0">
        {t("incompatibleNotice.claimsIntro")}
        {missing.length > 0 ? t("incompatibleNotice.webglExtensionsPart") : ""}
        {missing.length > 0 && gpuMissing.length > 0 ? t("incompatibleNotice.andPart") : ""}
        {gpuMissing.length > 0 ? t("incompatibleNotice.webgpuFeaturesPart") : ""}
        {" "}{t("incompatibleNotice.claimsOutro")}
      </p>
      <div className="rounded-lg bg-bg-weak-50 p-3 text-paragraph-xs">
        <div>
          <span className="text-text-soft-400">{t("incompatibleNotice.profileClaims")}</span>{" "}
          <span className="text-text-strong-950">{compat.profile_renderer || "—"}</span>
        </div>
        <div>
          <span className="text-text-soft-400">{t("incompatibleNotice.thisMachineHas")}</span>{" "}
          <span className="text-text-strong-950">{caps?.renderer || t("incompatibleNotice.unknownRenderer")}</span>
        </div>
      </div>
      <p className="m-0">
        {t("incompatibleNotice.reportsListNote")}
      </p>
      <pre className="m-0 overflow-x-auto rounded-lg bg-bg-weak-50 p-3 text-paragraph-xs">
{`gl.getSupportedExtensions()
  -> [ ..., "${unique[0] ?? "WEBGL_compressed_texture_astc"}", ... ]

gl.getExtension("${unique[0] ?? "WEBGL_compressed_texture_astc"}")
  -> null`}
      </pre>
      <p className="m-0">
        {t("incompatibleNotice.contradictionNote")}
      </p>
      <div>
        <div className="mb-1 text-paragraph-xs text-text-soft-400">
          {unique.length === 1
            ? t("incompatibleNotice.extensionsUnbackedOne", { n: unique.length })
            : t("incompatibleNotice.extensionsUnbackedMany", { n: unique.length })}
        </div>
        <div className="max-h-32 overflow-y-auto rounded-lg bg-bg-weak-50 p-3 font-mono text-paragraph-xs text-text-strong-950">
          {unique.map((e) => (
            <div key={e}>{e}</div>
          ))}
        </div>
      </div>
      {gpuMissing.length > 0 && (
        <div>
          <div className="mb-1 text-paragraph-xs text-text-soft-400">
            {gpuMissing.length === 1
              ? t("incompatibleNotice.webgpuUnbackedOne", { n: gpuMissing.length })
              : t("incompatibleNotice.webgpuUnbackedMany", { n: gpuMissing.length })}
          </div>
          <div className="max-h-32 overflow-y-auto rounded-lg bg-bg-weak-50 p-3 font-mono text-paragraph-xs text-text-strong-950">
            {gpuMissing.map((f) => (
              <div key={f}>{f}</div>
            ))}
          </div>
          <p className="m-0 mt-1.5 text-paragraph-xs text-text-soft-400">
            {t("incompatibleNotice.webgpuNote")}
          </p>
        </div>
      )}
      <p className="m-0 text-text-soft-400">
        {t("incompatibleNotice.advice")}
      </p>
    </div>
  );
}

/// The badge shown next to an incompatible fingerprint. Clicking it opens the
/// explanation above; it is not a tooltip, because the reason is longer than a
/// tooltip should be and the operator needs to be able to read it slowly.
export function IncompatibleBadge({ compat }: { compat: GpuCompat }) {
  const t = useT();
  const [open, setOpen] = useState(false);
  if (compat.compatible) return null;
  return (
    <>
      <Badge
        color="warning"
        variant="lighter"
        size="small"
        role="button"
        tabIndex={0}
        className="flex-none cursor-pointer select-none"
        title={t("incompatibleNotice.badgeTitle")}
        onClick={(e) => {
          e.stopPropagation();
          setOpen(true);
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.stopPropagation();
            e.preventDefault();
            setOpen(true);
          }
        }}
      >
        {t("incompatibleNotice.badgeLabel")}
      </Badge>
      {open && (
        <Modal
          open
          onClose={() => setOpen(false)}
          title={t("incompatibleNotice.badgeModalTitle")}
          maxWidthClassName="max-w-lg"
          footer={
            <div className="flex justify-end">
              <Button size="small" variant="neutral" mode="stroke" onClick={() => setOpen(false)}>
                {t("incompatibleNotice.closeButton")}
              </Button>
            </div>
          }
        >
          <IncompatibleExplainer compat={compat} />
        </Modal>
      )}
    </>
  );
}

/// Shown when the operator picks an incompatible fingerprint by hand. It does
/// not refuse — the choice is theirs and there are legitimate reasons for it
/// (testing, a profile meant for another machine) — it makes sure the cost is
/// known before it is paid.
export function IncompatibleWarningModal({
  compat,
  onKeep,
  onCancel,
}: {
  compat: GpuCompat;
  onKeep: () => void;
  onCancel: () => void;
}) {
  const t = useT();
  const [dontWarn, setDontWarn] = useState(false);
  const setSuppressed = useGpuCompat((s) => s.setSuppressed);
  const keep = () => {
    if (dontWarn) setSuppressed(true);
    onKeep();
  };
  return (
    <Modal
      open
      onClose={onCancel}
      title={t("incompatibleNotice.warningModalTitle")}
      maxWidthClassName="max-w-lg"
      footer={
        <div className="flex w-full min-w-0 flex-wrap items-center justify-between gap-x-3 gap-y-2">
          <label className="flex min-w-0 flex-1 cursor-pointer items-center gap-2 text-paragraph-xs text-text-soft-400">
            <input
              type="checkbox"
              className="flex-none"
              checked={dontWarn}
              onChange={(e) => setDontWarn(e.target.checked)}
            />
            <span className="min-w-0">{t("incompatibleNotice.dontWarnAgain")}</span>
          </label>
          <div className="flex flex-none gap-2">
            <Button size="small" variant="neutral" mode="stroke" onClick={onCancel}>
              {t("incompatibleNotice.pickAnother")}
            </Button>
            <Button size="small" variant="error" mode="filled" onClick={keep}>
              {t("incompatibleNotice.useAnyway")}
            </Button>
          </div>
        </div>
      }
    >
      <IncompatibleExplainer compat={compat} />
    </Modal>
  );
}
