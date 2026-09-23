import { useRef } from "react";
import { Checkbox } from "@proxyshard/shardx-ui-kit";
import Badge from "../../shared/ui/Badge";
import type { ContextItem } from "../../shared/types";
import {
  useProxy,
  type ProxyEntry,
} from "../../entities/proxy";
import { ProxyRowActions, RenameProxyCell } from "../../features/manage-proxies";

import { ProxyTypeBadge, ProxyCountryCell, ProxyTestResult } from "../../entities/proxy";
import { useT } from "../../shared/i18n";

export function ProxyRow({ proxy, profileCount, onMenu }: {
  proxy: ProxyEntry;
  profileCount: number;
  onMenu: (e: React.MouseEvent, items: ContextItem[]) => void;
}) {
  const t = useT();
  const snap = useProxy((s) => s.snapshots[proxy.id]);
  const busy = useProxy((s) => !!s.proxyTesting[proxy.id]);
  const isSel = useProxy((s) => s.proxySel.has(proxy.id));
  const selectProxy = useProxy((s) => s.selectProxy);
  const selectRangeTo = useProxy((s) => s.selectRangeTo);
  const testProxy = useProxy((s) => s.testProxy);
  const removeProxy = useProxy((s) => s.removeProxy);
  const setEditing = useProxy((s) => s.setEditing);
  const setInfoFor = useProxy((s) => s.setInfoFor);

  // Handled in mousedown only: a click on the checkbox's <label> reaches the
  // row twice, and applying the range twice would undo it.
  const shiftPress = useRef(false);

  return (
    <div
      className="relative border-t border-stroke-soft-200 first:border-t-0"
      onMouseDown={(e) => {
        const t = e.target as HTMLElement;
        shiftPress.current = e.button === 0 && e.shiftKey && !t.closest("button, a");
        if (!shiftPress.current) return;
        // Stops the text selection a shift-drag begins, and the label
        // activation that would reach the checkbox.
        e.preventDefault();
        selectRangeTo(proxy.id);
      }}
      onClick={(e) => { if (shiftPress.current) e.preventDefault(); }}
      onContextMenu={(e) =>
        onMenu(e, [
          { label: t("proxyTable.testTcpUdpGeo"), onClick: () => testProxy(proxy) },
          { label: t("proxyTable.viewDetails"), onClick: () => setInfoFor({ proxy, anchor: { x: e.clientX, y: e.clientY } }) },
          { label: t("common.edit"), onClick: () => setEditing(proxy) },
          { sep: true, label: "", onClick: () => { } },
          { label: t("common.delete"), onClick: () => removeProxy(proxy.id), danger: true },
        ])
      }
    >
      <div className="p-cols transition-colors hover:bg-bg-weak-50">
        <div>
          <Checkbox
            checked={isSel}
            onChange={() => { if (!shiftPress.current) selectProxy(!isSel, [proxy]); }}
          />
        </div>
        <RenameProxyCell proxy={proxy} />
        <div><ProxyTypeBadge kind={proxy.kind} /></div>
        <div className="min-w-0 overflow-hidden">
          <span
            className="mono small inline-block max-w-full cursor-pointer overflow-hidden text-ellipsis whitespace-nowrap align-middle text-text-sub-600 transition-colors hover:text-primary-base"
            onClick={() => { if (!shiftPress.current) setEditing(proxy); }}
            title={t("proxyTable.editProxy")}
          >
            {proxy.host}:{proxy.port}
          </span>
        </div>
        <div className="cell-country"><ProxyCountryCell snap={snap} fallback={proxy.country} /></div>
        <div className="cell-profiles">
          <Badge color="gray" variant='filled' size="small" title={t(
            profileCount === 1 ? "proxyTable.boundProfilesOne" : "proxyTable.boundProfilesMany",
            { n: profileCount },
          )}>
            {profileCount}
          </Badge>
        </div>
        <div className="min-w-0">
          <ProxyTestResult snap={snap} kind={proxy.kind} busy={busy} />
        </div>
        <ProxyRowActions proxy={proxy} />
      </div>
    </div>
  );
}
