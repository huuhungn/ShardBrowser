import { useEffect, useState } from "react";
import Badge from "../../../shared/ui/Badge";
import {
  GlobeIcon,
  ClockIcon,
  BuildingIcon,
} from "../../../shared/icons";
import { CountryFlag } from "../../../shared/ui/CountryFlag";
import { toast } from "../../../shared/model/toast";
import { fmtTs, safeUiError } from "../../../shared/lib/utils";
import type { ProxyEntry, ProxyTestSnapshot } from "../../../entities/proxy";
import { proxyHistory } from "../../../entities/proxy";
import { t } from "../../../shared/i18n";

/// Proxy detail popover: latest IP/geo + UDP + IP-change history.
export function ProxyInfoPopover({
  proxy, anchor, latest, onClose,
}: {
  proxy: ProxyEntry;
  anchor: { x: number; y: number };
  latest?: ProxyTestSnapshot;
  onClose: () => void;
}) {
  const [history, setHistory] = useState<ProxyTestSnapshot[]>([]);
  useEffect(() => {
    proxyHistory(proxy.id)
      .then((h) => setHistory([...h].reverse()))
      .catch((e) => toast.err(String(e)));
  }, [proxy.id]);
  useEffect(() => {
    const onDoc = (e: MouseEvent) => {
      const t = e.target as HTMLElement;
      if (!t.closest(".proxy-popover")) onClose();
    };
    window.addEventListener("mousedown", onDoc);
    return () => window.removeEventListener("mousedown", onDoc);
  }, [onClose]);

  // Clamp inside viewport to avoid clipping at the right edge.
  const left = Math.min(anchor.x, window.innerWidth - 360);
  const top = Math.min(anchor.y + 8, window.innerHeight - 320);

  return (
    <div
      className="proxy-popover fixed z-250 flex max-h-[480px] w-[340px] animate-[fadeUp_0.12s_ease-out] flex-col overflow-hidden rounded-12 bg-bg-white-0 shadow-[var(--shadow-md)] ring-1 ring-inset ring-stroke-soft-200"
      style={{ left, top }}
      onClick={(e) => e.stopPropagation()}
    >
      <div className="flex flex-col gap-1.5 px-4 py-3.5">
        {latest?.ip ? (
          <>
            <div className="flex items-center gap-2.5 text-paragraph-sm text-text-strong-950">
              <span className="inline-grid w-5 place-items-center text-icon-soft-400"><GlobeIcon className="size-4" /></span>
              <span className="mono">{latest.ip}</span>
            </div>
            <div className="flex items-center gap-2.5 text-paragraph-sm text-text-strong-950">
              <span className="inline-grid w-5 place-items-center text-icon-soft-400">
                {latest.country_code ? <CountryFlag cc={latest.country_code} height={14} /> : <GlobeIcon className="size-4" />}
              </span>
              <span>{[latest.region, latest.city].filter(Boolean).join(", ") || latest.country || "—"}</span>
            </div>
            {latest.timezone && (
              <div className="flex items-center gap-2.5 text-paragraph-sm text-text-strong-950">
                <span className="inline-grid w-5 place-items-center text-icon-soft-400"><ClockIcon className="size-4" /></span>
                <span>{latest.timezone}</span>
              </div>
            )}
            {latest.isp && (
              <div className="flex items-center gap-2.5 text-paragraph-sm text-text-strong-950">
                <span className="inline-grid w-5 place-items-center text-icon-soft-400"><BuildingIcon className="size-4" /></span>
                <span className="text-paragraph-xs text-text-soft-400">{latest.isp}</span>
              </div>
            )}
            <div className="mt-1 flex flex-wrap items-center gap-2">
              <Badge color={latest.tcp_ms != null ? "success" : "error"} variant="lighter" size="small">
                TCP {latest.tcp_ms != null ? `${latest.tcp_ms} ms` : "✗"}
              </Badge>
              {proxy.kind === "socks5" && (
                <Badge
                  color={latest.udp_ms != null ? "success" : "error"}
                  variant="lighter"
                  size="small"
                  title={
                    latest.udp_error ? safeUiError(latest.udp_error) : undefined
                  }
                >
                  UDP {latest.udp_ms != null ? `${latest.udp_ms} ms` : "✗"}
                </Badge>
              )}
            </div>
          </>
        ) : (
          <div className="text-paragraph-xs text-text-soft-400">Not tested yet — click ↻ on the row.</div>
        )}
      </div>
      <div className="border-b border-t border-stroke-soft-200 bg-bg-weak-50 px-4 py-2 text-center text-subheading-2xs text-text-soft-400">IP HISTORY</div>
      <div className="flex-1 overflow-y-auto py-1">
        {history.length === 0 && <div className="px-4 py-2.5 text-paragraph-xs text-text-soft-400">{t("proxy.noHistoryYet")}</div>}
        {history.map((s, i) => (
          <div key={`${s.ip}-${s.first_seen}-${i}`} className="border-b border-stroke-soft-200 px-4 py-2 last:border-b-0">
            <div className="flex items-center gap-2 text-paragraph-sm text-text-strong-950">
              <span className="mono">{s.ip || "—"}</span>
              {s.country_code && (
                <>
                  <CountryFlag cc={s.country_code} />
                  <span className="text-paragraph-xs text-text-sub-600">{s.country_code}</span>
                </>
              )}
              {s.city && <span className="text-paragraph-xs text-text-soft-400">{s.city}</span>}
            </div>
            <div className="mt-0.5 text-[11px] text-text-disabled-300">
              {fmtTs(s.first_seen)}
              {s.first_seen !== s.last_seen && <> → {fmtTs(s.last_seen)}</>}
              {s.udp_ms != null && <> · UDP ✓</>}
              {s.udp_error && <> · UDP ✗</>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
