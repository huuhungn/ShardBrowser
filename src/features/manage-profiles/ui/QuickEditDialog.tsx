import { useState } from "react";
import { DialogModal, Select, Textarea } from "@proxyshard/shardx-ui-kit";
import { toast } from "../../../shared/model/toast";
import type { ProfileMeta } from "../../../entities/profile";
import type { ProxyEntry } from "../../../entities/proxy";
import { profileBindProxy, profileGet, profileSave } from "../../../entities/profile";
import { useT } from "../../../shared/i18n";

export function QuickEditDialog({
  kind, profile, proxies, onClose, onSaved,
}: {
  kind: "proxy" | "notes";
  profile: ProfileMeta;
  proxies: ProxyEntry[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const t = useT();
  const [proxyId, setProxyId] = useState<string | null>(profile.proxy_id);
  const [notes, setNotes] = useState(profile.notes);

  const saveProxy = async () => {
    try {
      await profileBindProxy(profile.id, proxyId);
      toast.ok(t("profile.proxyUpdated"));
      onSaved();
    } catch (e) { toast.err(String(e)); }
  };

  const saveNotes = async () => {
    try {
      // Round-trip the whole profile JSON so the user's other fields stay intact.
      const stored = await profileGet(profile.id);
      stored.notes = notes;
      await profileSave(stored);
      toast.ok(t("profile.notesSaved"));
      onSaved();
    } catch (e) { toast.err(String(e)); }
  };

  return (
    <DialogModal
      open
      onClose={onClose}
      title={`${kind === "proxy" ? t("profile.bindProxy") : t("profile.editNotes")} — ${profile.name}`}
      confirmLabel={t("common.save")}
      onConfirm={kind === "proxy" ? saveProxy : saveNotes}
      cancelLabel={t("common.cancel")}
      onCancel={onClose}
    >
      <div className="py-4">
        {kind === "proxy" ? (
          <Select
            label={t("profile.proxy")}
            size="small"
            isSearchable
            value={proxyId ?? ""}
            onChange={(v) => setProxyId(v || null)}
            options={[
              { value: "", label: "— direct connection —" },
              ...proxies.map((px) => ({
                value: px.id,
                label: `${px.name || `${px.host}:${px.port}`} · ${px.country || px.kind}`,
              })),
            ]}
          />
        ) : (
          <Textarea
            label={t("common.notes")}
            rows={6}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            autoFocus
          />
        )}
      </div>
    </DialogModal>
  );
}
