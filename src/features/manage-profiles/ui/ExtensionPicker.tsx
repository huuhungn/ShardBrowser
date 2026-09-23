import { useEffect, useMemo, useState } from "react";
import { Checkbox, Input, cn } from "@proxyshard/shardx-ui-kit";
import { ChevronDownIcon, CloseIcon } from "../../../shared/icons";
import { useExtensions, type ExtensionEntry } from "../../../entities/extension";
import { useNav } from "../../../shared/model/navigation";
import { useT } from "../../../shared/i18n";

function Icon({ e, className }: { e: ExtensionEntry; className?: string }) {
  return e.icon ? (
    <img src={e.icon} alt="" className={cn("shrink-0 rounded-[3px]", className)} />
  ) : (
    <span
      className={cn(
        "grid shrink-0 place-items-center rounded-[3px] bg-bg-weak-50 text-[9px] uppercase",
        className,
      )}
    >
      {e.name.slice(0, 1)}
    </span>
  );
}

/** Which extensions this profile loads. Expanded in place, not in a popover:
 *  the editor sits in a table row that clips an overlay. */
export function ExtensionPicker({
  value, onChange,
}: {
  value: string[];
  onChange: (v: string[]) => void;
}) {
  const t = useT();
  const items = useExtensions((s) => s.items);
  const init = useExtensions((s) => s.init);
  const go = useNav((s) => s.setSection);
  const [open, setOpen] = useState(false);
  const [q, setQ] = useState("");

  useEffect(() => { init(); }, [init]);

  const toggle = (id: string) =>
    onChange(value.includes(id) ? value.filter((x) => x !== id) : [...value, id]);

  const picked = useMemo(
    () => value.map((id) => items.find((e) => e.id === id)).filter(Boolean) as ExtensionEntry[],
    [value, items],
  );
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    if (!needle) return items;
    return items.filter(
      (e) => e.name.toLowerCase().includes(needle) || e.description.toLowerCase().includes(needle),
    );
  }, [items, q]);

  if (items.length === 0) {
    return (
      <p className="m-0 text-paragraph-xs text-text-soft-400">
        No extensions in the library yet.{" "}
        <button
          type="button"
          className="text-primary-base hover:underline"
          onClick={() => go("extensions")}
        >
          Add one →
        </button>
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-1.5">
      {picked.length > 0 && (
        <div className="flex max-h-[88px] flex-wrap gap-1.5 overflow-y-auto scrollbar">
          {picked.map((e) => (
            <span
              key={e.id}
              title={e.description || e.name}
              className="flex max-w-[13rem] items-center gap-1.5 rounded-6 bg-primary-alpha-10 py-1 pl-1 pr-1 text-paragraph-xs text-primary-base ring-1 ring-inset ring-primary-alpha-24"
            >
              <Icon e={e} className="size-4" />
              <span className="truncate">{e.name}</span>
              <button
                type="button"
                title={t("profile.remove")}
                onClick={() => toggle(e.id)}
                className="grid size-4 shrink-0 place-items-center rounded-4 text-primary-base/70 hover:bg-primary-alpha-16 hover:text-primary-base"
              >
                <CloseIcon className="size-3" />
              </button>
            </span>
          ))}
        </div>
      )}

      <button
        type="button"
        aria-expanded={open}
        onClick={() => setOpen((v) => !v)}
        className="flex w-fit items-center gap-1.5 rounded-6 px-2 py-1 text-paragraph-xs text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200 transition-colors hover:bg-bg-weak-50"
      >
        {picked.length > 0 ? `Change · ${picked.length} of ${items.length}` : "Choose extensions"}
        <ChevronDownIcon className={cn("size-3.5 transition-transform", open && "rotate-180")} />
      </button>

      {open && (
        <div className="flex flex-col gap-1.5 rounded-8 bg-bg-white-0 p-1.5 ring-1 ring-inset ring-stroke-soft-200">
          {items.length > 6 && (
            <Input
              inputSize="small"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder={t("profile.searchExtensions")}
            />
          )}
          <div className="flex max-h-[176px] flex-col overflow-y-auto scrollbar">
            {shown.map((e) => (
              <label
                key={e.id}
                title={e.description || e.name}
                className="flex cursor-pointer items-center gap-2 rounded-6 px-1.5 py-1 hover:bg-bg-weak-50"
              >
                <Checkbox checked={value.includes(e.id)} onChange={() => toggle(e.id)} />
                <Icon e={e} className="size-4" />
                <span className="min-w-0 flex-1 truncate text-paragraph-xs text-text-sub-600">
                  {e.name}
                </span>
                {e.version && (
                  <span className="mono shrink-0 text-[10.5px] text-text-disabled-300">
                    {e.version}
                  </span>
                )}
              </label>
            ))}
            {shown.length === 0 && (
              <div className="px-1.5 py-3 text-center text-paragraph-xs text-text-soft-400">
                {t("profile.nothingMatchesThat")}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
