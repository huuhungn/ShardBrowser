import Badge from "../../shared/ui/Badge";
import { AppleOsIcon, WindowsOsIcon, LinuxOsIcon, NavFingerprintsIcon, WarningIcon } from "../../shared/icons";
import { useGpuCompat } from "../../shared/model/gpuCompat";
import { EmptyState } from "../../shared/ui/EmptyState";
import { useFingerprint, useFingerprintGroups, FingerprintCard } from "../../entities/fingerprint";
import { FingerprintCardActions } from "../../features/manage-fingerprints";
import { useT } from "../../shared/i18n";

function PlatformIcon({ platform }: { platform: string }) {
  switch (platform.toLowerCase()) {
    case "macos":
      return <AppleOsIcon className="size-4 text-primary-base" />;
    case "windows":
      return <WindowsOsIcon className="size-4 text-information-base" />;
    case "linux":
      return <LinuxOsIcon className="size-4 text-success-base" />;
    default:
      return <AppleOsIcon className="size-4 text-primary-base" />;
  }
}

export function FingerprintLibrary() {
  const t = useT();
  const items = useFingerprint((s) => s.items);
  const isEmpty = items.length === 0;
  const groups = useFingerprintGroups();
  const byId = useGpuCompat((s) => s.byId);
  const mismatched = items.filter((e) => byId[e.id]?.compatible === false).length;

  if (isEmpty) {
    return (
      <EmptyState card icon={<NavFingerprintsIcon className="size-6" />} title={t("fp.none.title")} body={t("fp.libraryIsEmpty")} />
    );
  }

  return (
    <div className="flex flex-col gap-[22px]">
      {mismatched > 0 && (
        <p role="status" className="m-0 flex items-start gap-2 rounded-10 bg-warning-alpha-16 px-3 py-2 text-paragraph-xs text-text-sub-600">
          <WarningIcon className="mt-px size-4 flex-none text-warning-base" />
          {t("fp.gpuMismatchSummary", { n: String(mismatched), total: String(items.length) })}
        </p>
      )}
      {groups.map(([platform, list]) => (
        <div key={platform} className="flex flex-col gap-2.5">
          <div className="flex items-center gap-2.5 border-b border-stroke-soft-200 pb-2">
            <PlatformIcon platform={platform} />
            <h3 className="m-0 text-label-sm text-text-strong-950">
              {platform === "Other" ? t("fingerprints.platformOther") : platform}
            </h3>
            <Badge color="gray" variant="filled" size="small">{list.length}</Badge>
          </div>
          <div className="grid gap-2.5 [grid-template-columns:repeat(auto-fill,minmax(240px,1fr))]">
            {list.map((t) => (
              <FingerprintCard key={t.id} entry={t} actions={<FingerprintCardActions entry={t} />} />
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}
