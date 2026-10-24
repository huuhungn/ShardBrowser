import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";

import { TitleBar } from "../widgets/TitleBar/TitleBar";
import { Sidebar } from "../widgets/Sidebar/Sidebar";
import { FirstRunGate } from "../widgets/FirstRunGate/FirstRunGate";
import { ToastHost } from "../widgets/ToastHost/ToastHost";
import { ConfirmHost } from "../widgets/ConfirmHost/ConfirmHost";

import { PassphraseHost } from "../widgets/PassphraseHost/PassphraseHost";
import { StarModal } from "../widgets/StarModal/StarModal";
import { HelperWatcher } from "../widgets/HelperWatcher";
import { WhatsNewGate } from "../widgets/WhatsNewGate";
import { BrowsersPage } from "../pages/browsers";
import { ProxiesPage } from "../pages/proxies";
import { ProxyShardPage } from "../pages/proxyshard";
import { FingerprintsPage } from "../pages/fingerprints";
import { ExtensionsPage } from "../pages/extensions";
import { AutomationPage } from "../pages/automation";
import { BookmarksPage } from "../pages/bookmarks";
import { TrashPage } from "../pages/trash";
import { SettingsPage } from "../pages/settings";
import { PatchLogPage } from "../pages/patchlog";
import { useNav } from "../shared/model/navigation";

import { useTeam } from "../entities/team";
import { toast } from "../shared/model/toast";
import { t } from "../shared/i18n";

export function App() {
  const section = useNav((s) => s.section);
  // Profile rows ask whether team actions apply; load it once here.
  const loadTeam = useTeam((s) => s.refresh);
  useEffect(() => { void loadTeam(); }, [loadTeam]);
  // The backend refuses to quit while a browser it started is open.
  useEffect(() => {
    let disposed = false;
    let un: (() => void) | undefined;
    listen<{ running_count: number }>("launcher:exit-blocked", ({ payload }) => {
      toast.err(t("app.exitBlocked", { n: payload.running_count }));
    }).then((fn) => {
      if (disposed) fn();
      else un = fn;
    });
    return () => {
      disposed = true;
      un?.();
    };
  }, []);

  return (
    <>
      <TitleBar />
      <HelperWatcher />
      <WhatsNewGate />
      <FirstRunGate>
        <div
          className="grid overflow-hidden bg-bg-weak-50 [grid-template-columns:240px_1fr] [@media(min-width:1700px)]:[grid-template-columns:280px_1fr]"
          style={{ height: "100vh", paddingTop: "var(--titlebar-h)" }}
        >
          <Sidebar />
          <main className="overflow-y-auto px-7 py-6">
            {section === "browsers" && <BrowsersPage />}
            {section === "proxies" && <ProxiesPage />}
            {section === "proxyshard" && <ProxyShardPage />}
            {section === "fingerprints" && <FingerprintsPage />}
            {section === "extensions" && <ExtensionsPage />}
            {section === "automation" && <AutomationPage />}
            {section === "bookmarks" && <BookmarksPage />}
            {section === "trash" && <TrashPage />}
            {section === "patchlog" && <PatchLogPage />}
            {section === "settings" && <SettingsPage />}
          </main>
          <ToastHost />
          <ConfirmHost />

      <PassphraseHost />
          <StarModal />
        </div>
      </FirstRunGate>
    </>
  );
}
