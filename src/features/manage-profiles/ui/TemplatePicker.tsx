import { useEffect, useState } from "react";
import { Modal } from "@proxyshard/shardx-ui-kit";
import type { FingerprintEntry } from "../../../entities/fingerprint";
import { fingerprintList } from "../../../entities/fingerprint";
import { hostPlatform } from "../../../entities/profile";
import { useT } from "../../../shared/i18n";

export function TemplatePicker({
  fingerprints,
  onPick,
  onClose,
}: {
  /** When passed in, skip the fingerprint_list IO and the visible mount
   *  flash that used to happen while the 170-entry list streamed back. */
  fingerprints?: FingerprintEntry[];
  onPick: (id: string) => void;
  onClose: () => void;
}) {
  const t = useT();
  const [lib, setLib] = useState<FingerprintEntry[]>(fingerprints ?? []);
  const [host, setHost] = useState<string>("");
  useEffect(() => {
    if (!fingerprints) {
      fingerprintList().then(setLib).catch(() => {});
    }
    hostPlatform().then(setHost).catch(() => {});
  }, [fingerprints]);
  // Only host-matching fingerprints (UA/fonts/WebGL renderer are host-coupled).
  const tpls = host ? lib.filter((e) => e.platform === host) : [];
  return (
    <Modal
      open
      onClose={onClose}
      title={t("fp.pickAFingerprint", { host: host || "" })}
      maxWidthClassName="max-w-[880px]"
    >
      {tpls.length === 0 ? (
        <div className="rounded-10 bg-bg-weak-50 px-4 py-8 text-center text-paragraph-sm text-text-sub-600">
          No {host} fingerprints in the library yet. Add some on the
          Fingerprints page (or drop JSONs into the library folder).
        </div>
      ) : (
        <div className="grid max-h-[60vh] grid-cols-[repeat(auto-fill,minmax(220px,1fr))] gap-3 overflow-y-auto">
          {tpls.map((t) => (
            <button
              key={t.id}
              className="relative flex cursor-pointer flex-col gap-1.5 overflow-hidden rounded-10 bg-bg-white-0 px-4 py-3.5 pb-3 text-left ring-1 ring-inset ring-stroke-soft-200 transition-all hover:bg-bg-weak-50 hover:ring-primary-base active:translate-y-px"
              onClick={() => onPick(t.id)}
            >
              <div
                className="absolute left-0 right-0 top-0 h-[3px] opacity-85"
                style={{ background: t.tag_color }}
              />
              <div className="mt-1 flex items-center justify-between text-subheading-2xs">
                <span className="text-primary-base">{t.platform}</span>
                <span className="text-text-soft-400">Chrome {t.chrome}</span>
              </div>
              <div className="mt-0.5 text-label-sm text-text-strong-950">{t.label}</div>
              <div className="mono text-[11.5px] text-text-soft-400">{t.gpu}</div>
            </button>
          ))}
        </div>
      )}
    </Modal>
  );
}
