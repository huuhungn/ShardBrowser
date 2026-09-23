import { useEffect, useState } from "react";
import {
  helperFields, helperFill, helperClose, helperDismiss, type HelperField,
} from "../../entities/profile/model/api";
import { SyncIcon } from "../../shared/icons";
import { dragWindowOnMouseDown } from "../../shared/lib/dragWindow";
import { t, useT } from "../../shared/i18n";

/** What a kind is called to a person. */
const LABELS: Record<string, string> = {
  first_name: t("helper.firstName"), last_name: t("helper.lastName"), full_name: t("helper.fullName"),
  email: t("helper.email"), username: t("helper.username"), phone: t("helper.phone"), country: t("helper.country"), city: t("helper.city"),
  postal_code: t("helper.postcode"), street: t("helper.address"),
  birth_day: t("helper.birthDay"), birth_month: t("helper.birthMonth"), birth_year: t("helper.birthYear"),
  birth_date: t("helper.dateOfBirth"), gender: t("helper.gender"),
};

/**
 * Shard Helper: offers to fill a form the browser noticed. It only ever offers —
 * nothing is typed until the button is pressed — and closes itself once the page
 * has nothing left to fill.
 */
export function HelperPanel({ profile }: { profile: string }) {
  const t = useT();
  const [fields, setFields] = useState<HelperField[]>([]);
  const [busy, setBusy] = useState(false);
  const [filled, setFilled] = useState(0);

  useEffect(() => {
    let alive = true;
    const tick = async () => {
      try {
        const r = await helperFields(profile);
        if (!alive) return;
        const next = r?.fields ?? [];
        setFields(next);
        // Nothing left to fill — the page moved on, or the browser closed.
        if (next.length === 0) void helperClose();
      } catch { void helperClose(); }
    };
    void tick();
    const id = setInterval(tick, 1200);
    return () => { alive = false; clearInterval(id); };
  }, [profile]);

  const kinds = [...new Set(fields.map((f) => f.kind))];

  return (
    <div
      onMouseDown={dragWindowOnMouseDown}
      className="flex h-screen w-screen flex-col rounded-12 bg-bg-white-0 ring-1 ring-inset ring-stroke-soft-200"
    >
      <div className="flex shrink-0 select-none items-center gap-2 px-3 pt-2.5 pb-1">
        <SyncIcon className="size-4 shrink-0 text-primary-base" />
        <div className="flex-1 truncate text-label-xs text-text-strong-950">
          {t("helper.fillableForm")}
        </div>
        <button type="button" onMouseDown={(e) => e.stopPropagation()} onClick={() => void helperDismiss(profile)}
                title={t("common.dismiss")}
                className="rounded-4 px-1.5 text-paragraph-xs text-text-soft-400 hover:bg-bg-weak-50">
          ✕
        </button>
      </div>

      <div className="min-h-0 flex-1 overflow-auto px-3 pb-1">
        {/* In a group each window fills with its own person. */}
        <div className="flex flex-wrap gap-1">
          {kinds.map((k) => (
            <span key={k}
                  className="rounded-6 px-1.5 py-0.5 text-paragraph-xs text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200">
              {LABELS[k] ?? k}
            </span>
          ))}
        </div>
      </div>

      <div className="shrink-0 px-3 pb-3 pt-1">
        <button
          type="button"
          onMouseDown={(e) => e.stopPropagation()}
          disabled={busy || fields.length === 0}
          onClick={async () => {
            setBusy(true);
            try { setFilled(await helperFill(profile)); } catch { /* shown by the next poll */ }
            setBusy(false);
          }}
          className="w-full rounded-8 bg-primary-base py-1.5 text-label-xs text-static-white hover:bg-primary-darker disabled:opacity-50"
        >
          {filled > 1
            ? `Filled ${filled} windows — fill again`
            : filled === 1
              ? t("helper.fillAgain")
              : `Fill ${fields.length} field${fields.length === 1 ? "" : "s"}`}
        </button>
      </div>
    </div>
  );
}
