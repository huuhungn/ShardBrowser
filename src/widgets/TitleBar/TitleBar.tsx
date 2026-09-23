import { getCurrentWindow } from "@tauri-apps/api/window";
import { HOST_OS } from "../../shared/lib/utils";
import { useT } from "../../shared/i18n";

export function TitleBar() {
  const t = useT();
  return (
    <div
      className={`fixed left-0 right-0 top-0 z-10000 flex select-none items-center justify-center border-b border-stroke-soft-200 bg-bg-white-0 [-webkit-user-select:none]${HOST_OS === "macOS" ? " titlebar-mac" : " titlebar-custom"}`}
      style={{ height: "var(--titlebar-h)" }}
      data-tauri-drag-region
    >
      <span className="pointer-events-none text-label-xs tracking-[0.4px] text-text-soft-400">
        ShardX Launcher
      </span>
      {/* Custom min/max/close on Win/Linux (macOS uses native traffic lights). */}
      {HOST_OS !== "macOS" && (
        <div className="absolute right-0 top-0 flex h-full">
          <button
            className="flex h-full w-[46px] cursor-default items-center justify-center border-none bg-transparent p-0 text-icon-soft-400 hover:bg-bg-weak-50 hover:text-icon-strong-950"
            aria-label={t("titleBar.minimize")}
            onClick={() => getCurrentWindow().minimize()}
          >
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
              <line x1="1" y1="5" x2="9" y2="5" stroke="currentColor" strokeWidth="1" />
            </svg>
          </button>
          <button
            className="flex h-full w-[46px] cursor-default items-center justify-center border-none bg-transparent p-0 text-icon-soft-400 hover:bg-bg-weak-50 hover:text-icon-strong-950"
            aria-label={t("titleBar.maximize")}
            onClick={() => getCurrentWindow().toggleMaximize()}
          >
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
              <rect x="1.5" y="1.5" width="7" height="7" fill="none" stroke="currentColor" strokeWidth="1" />
            </svg>
          </button>
          <button
            className="flex h-full w-[46px] cursor-default items-center justify-center border-none bg-transparent p-0 text-icon-soft-400 hover:bg-error-base! hover:text-white!"
            aria-label={t("common.close")}
            onClick={() => getCurrentWindow().close()}
          >
            <svg width="10" height="10" viewBox="0 0 10 10" aria-hidden="true">
              <line x1="1" y1="1" x2="9" y2="9" stroke="currentColor" strokeWidth="1" />
              <line x1="9" y1="1" x2="1" y2="9" stroke="currentColor" strokeWidth="1" />
            </svg>
          </button>
        </div>
      )}
    </div>
  );
}
