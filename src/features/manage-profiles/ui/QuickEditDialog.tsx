import { useState } from "react";
import { DialogModal, Select, Textarea } from "@proxyshard/shardx-ui-kit";
import { toast } from "../../../shared/model/toast";
import type { ProfileMeta } from "../../../entities/profile";
import type { ProxyEntry } from "../../../entities/proxy";
import { profileBindProxy, profileGet, profileSave, profileSetTags } from "../../../entities/profile";
import { TagsField } from "./TagsField";
import { useT } from "../../../shared/i18n";
import { safeUiError } from "../../../shared/lib/utils";

export function QuickEditDialog({
  kind, profile, proxies, onClose, onSaved,
}: {
  kind: "proxy" | "notes" | "tags";
  profile: ProfileMeta;
  proxies: ProxyEntry[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const t = useT();
  const [proxyId, setProxyId] = useState<string | null>(profile.proxy_id);
  const [notes, setNotes] = useState(profile.notes);
  const [tags, setTags] = useState(profile.tags);

  const saveProxy = async () => {
    try {
      await profileBindProxy(profile.id, proxyId);
      toast.ok(t("profile.proxyUpdated"));
      onSaved();
    } catch (e) { toast.err(safeUiError(e)); }
  };

  const saveNotes = async () => {
    try {
      // Round-trip the whole profile JSON so the user's other fields stay intact.
      const stored = await profileGet(profile.id);
      stored.notes = notes;
      await profileSave(stored);
      toast.ok(t("profile.notesSaved"));
      onSaved();
    } catch (e) { toast.err(safeUiError(e)); }
  };

  const saveTags = async () => {
    try {
      await profileSetTags(profile.id, tags);
      toast.ok(t("tag.saved"));
      onSaved();
    } catch (e) { toast.err(safeUiError(e)); }
  };

  const title = kind === "proxy" ? t("profile.bindProxy") : kind === "notes" ? t("profile.editNotes") : t("tag.editTags");
  const save = kind === "proxy" ? saveProxy : kind === "notes" ? saveNotes : saveTags;

  return (
    <DialogModal
      open
      onClose={onClose}
      title={`${title} — ${profile.name}`}
      confirmLabel={t("common.save")}
      onConfirm={save}
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
              { value: "", label: t("proxy.directConnection") },
              ...proxies.map((px) => ({
                value: px.id,
                label: `${px.name || `${px.host}:${px.port}`} · ${px.country || px.kind}`,
              })),
            ]}
          />
        ) : kind === "tags" ? (
          <TagsField value={tags} onChange={setTags} />
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
