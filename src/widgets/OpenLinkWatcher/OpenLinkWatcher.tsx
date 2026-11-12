import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { openLinkTake, processList, profileList, useProfile } from "../../entities/profile";
import { confirmModal } from "../../shared/lib/confirm";
import { toast } from "../../shared/model/toast";
import { t } from "../../shared/i18n";

/// A shardbrowser://open/<profile> link names a profile and nothing else, and any
/// web page can fire one. So it never starts anything by itself: the operator
/// sees the profile's name and confirms first.
async function isRunning(id: string) {
  const s = useProfile.getState();
  return !!s.running[id] || s.startBusy.has(id) || (await processList()).some((p) => p.profile_id === id);
}

async function openNamed(ref: string) {
  const profiles = await profileList();
  const byId = profiles.find((p) => p.id === ref);
  const named = profiles.filter((p) => p.name === ref);
  if (!byId && named.length > 1) return toast.err(t("openLink.ambiguous", { name: ref }));
  const profile = byId ?? named[0];
  if (!profile) return toast.err(t("openLink.notFound"));
  const already = () => toast.info(t("openLink.alreadyRunning", { name: profile.name }));
  if (await isRunning(profile.id)) return already();
  const ok = await confirmModal({
    title: t("openLink.confirmTitle"),
    message: t("openLink.confirm", { name: profile.name }),
    buttons: [
      { label: t("common.cancel"), value: false },
      { label: t("openLink.start"), value: true, primary: true },
    ],
  });
  if (ok !== true) return;
  // startStop toggles: a profile started while the dialog was open must not be stopped.
  if (await isRunning(profile.id)) return already();
  await useProfile.getState().startStop(profile);
}

/// Takes the links the backend queued (a cold start brings one before this
/// mounts) and handles them one at a time. Renders nothing.
export function OpenLinkWatcher() {
  const busy = useRef(false);

  useEffect(() => {
    let disposed = false;
    let un: (() => void) | undefined;
    const drain = async () => {
      try {
        const links = await openLinkTake();
        // A link that lands while one is being confirmed is dropped, so a page
        // cannot stack dialogs.
        if (busy.current) return;
        busy.current = true;
        try {
          for (const ref of links) {
            if (ref === null) toast.err(t("openLink.invalid"));
            else await openNamed(ref);
          }
        } finally {
          busy.current = false;
        }
      } catch (e) { toast.err(e); }
    };
    listen("open-link", () => { void drain(); }).then((fn) => {
      if (disposed) fn();
      else un = fn;
    });
    void drain();
    return () => {
      disposed = true;
      un?.();
    };
  }, []);

  return null;
}
