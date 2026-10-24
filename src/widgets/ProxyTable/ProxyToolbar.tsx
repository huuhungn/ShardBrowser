import { BulkActionsBar, BuyProxiesButton, ImportProxyButton, NewProxyButton } from "../../features/manage-proxies";

export function ProxyToolbar() {
  return (
    <div className="ml-auto flex max-w-full flex-none flex-wrap items-center justify-end gap-2">
      <BulkActionsBar />
      {/* Sits next to Import / New proxy so it's discoverable without a dialog. */}
      <BuyProxiesButton />
      <ImportProxyButton />
      <NewProxyButton />
    </div>
  );
}
