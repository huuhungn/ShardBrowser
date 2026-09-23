import { useEffect, useRef } from "react";
import { Breadcrumb, Input } from "@proxyshard/shardx-ui-kit";
import { HOST_OS } from "../lib/utils";
import { SearchIcon } from "../icons";
import { useT } from "../../shared/i18n";

/// Page header — UI-kit Breadcrumb + search Input.
///
/// The search box is named after the section it filters ("Search Browsers"),
/// so it is reachable by name rather than by position, and it owns the
/// Ctrl/Cmd+K shortcut plus Escape-to-clear that the shortcut implies.
export function Topbar({ crumbs, search = "", onSearch }: {
  crumbs: string[];
  /** Omit both on pages that cannot filter: a dead search box is worse than none. */
  search?: string;
  onSearch?: (v: string) => void;
}) {
  const t = useT();
  const ref = useRef<HTMLInputElement>(null);
  const section = crumbs[crumbs.length - 1] ?? "";
  const label = section ? `Search ${section}` : "Search";
  const searchable = typeof onSearch === "function";
  const isMac = HOST_OS === "macOS";

  useEffect(() => {
    // Do not claim the shortcut on pages with no search box to focus.
    if (!searchable) return;
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        ref.current?.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [searchable]);

  return (
    <div className="mb-4 flex items-center justify-between gap-4">
      <Breadcrumb items={crumbs.map((c) => ({ label: c }))} />
      {searchable && (
      <div className="w-[320px]">
        <Input
          ref={ref}
          type="search"
          inputSize="small"
          aria-label={label}
          placeholder={t("ui.search")}
          leftIcon={<SearchIcon className="size-4" />}
          value={search}
          onChange={(e) => onSearch?.(e.target.value)}
          onKeyDown={(e) => {
            // Escape clears first; a second Escape on an empty box gives focus
            // back to the page so the shortcut is not a one-way trip.
            if (e.key !== "Escape") return;
            if (search) {
              e.preventDefault();
              onSearch?.("");
            } else {
              ref.current?.blur();
            }
          }}
          rightIcon={
            // The hint sits in a narrow slot, so an ordinary space lets "Ctrl K"
            // wrap onto two lines and read as a squashed column.
            <span aria-hidden="true" className="whitespace-nowrap text-paragraph-xs text-text-soft-400">
              {isMac ? "⌘K" : "Ctrl\u00a0K"}
            </span>
          }
        />
      </div>
      )}
    </div>
  );
}
