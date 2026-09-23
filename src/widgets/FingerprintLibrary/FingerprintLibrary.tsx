import Badge from "../../shared/ui/Badge";
import { AppleOsIcon, WindowsOsIcon, LinuxOsIcon } from "../../shared/icons";
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
  const isEmpty = useFingerprint((s) => s.items.length === 0);
  const groups = useFingerprintGroups();

  if (isEmpty) {
    return (
      <div className="rounded-12 bg-bg-white-0 px-6 py-14 text-center text-paragraph-sm text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200">
        {t("fp.libraryIsEmpty")}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-[22px]">
      {groups.map(([platform, list]) => (
        <div key={platform} className="flex flex-col gap-2.5">
          <div className="flex items-center gap-2.5 border-b border-stroke-soft-200 pb-2">
            <PlatformIcon platform={platform} />
            <h3 className="m-0 text-label-sm text-text-strong-950">{platform}</h3>
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
