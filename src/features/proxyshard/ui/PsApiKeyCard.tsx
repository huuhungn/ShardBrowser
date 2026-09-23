import { useEffect, useState } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Button, Input } from "@proxyshard/shardx-ui-kit";
import { EyeIcon, EyeOffIcon, KeyIcon } from "../../../shared/icons";
import { DASHBOARD_URL } from "../../../shared/lib/utils";
import { PsConnectionBadge, usePsAccount } from "../../../entities/proxyshard";
import { useT } from "../../../shared/i18n";

export function PsApiKeyCard() {
  const t = useT();
  const key = usePsAccount((s) => s.key);
  const status = usePsAccount((s) => s.status);
  const me = usePsAccount((s) => s.me);
  const err = usePsAccount((s) => s.err);
  const saveKey = usePsAccount((s) => s.saveKey);
  const refreshMe = usePsAccount((s) => s.refreshMe);

  const [draft, setDraft] = useState("");
  const [showKey, setShowKey] = useState(false);

  // Sync the editable draft once the saved key loads from disk.
  useEffect(() => { setDraft(key ?? ""); }, [key]);

  return (
    <div className="mb-3.5 rounded-lg bg-bg-white-0 p-[18px] shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
      <h3 className="m-0 mb-1 text-label-sm text-text-strong-950">{t("ps.apiKey")}</h3>
      <p className="m-0 mb-2 text-paragraph-xs text-text-soft-400">
        Paste your ProxyShard <strong>{t("ps.apiKey")}</strong> (from the{" "}
        <a
          href="#"
          className="text-primary-base hover:underline"
          onClick={(e) => { e.preventDefault(); openUrl(DASHBOARD_URL).catch(() => {}); }}
        >dashboard</a>).
        It's stored locally and sent as <code>Authorization: Bearer …</code> to user-api.proxyshard.com.
      </p>
      <div className="mt-1 flex items-center gap-2">
        <div className="min-w-0 flex-1">
          <Input
            inputSize="small"
            type={showKey ? "text" : "password"}
            placeholder={t("ps.pasteApiKey")}
            leftIcon={<KeyIcon className="size-4" />}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === "Enter") saveKey(draft); }}
            rightIcon={
              <button
                type="button"
                className="pointer-events-auto flex size-6 cursor-pointer items-center justify-center rounded-6 border-0 bg-transparent text-icon-soft-400 transition-colors hover:bg-bg-weak-50 hover:text-icon-strong-950"
                title={showKey ? t("ps.hide") : t("ps.show")}
                onClick={() => setShowKey((v) => !v)}
              >
                {showKey ? <EyeOffIcon className="size-4" /> : <EyeIcon className="size-4" />}
              </button>
            }
          />
        </div>
        <Button
          variant="primary"
          mode="filled"
          size="small"
          onClick={() => saveKey(draft)}
          disabled={draft.trim() === (key ?? "")}
        >
          {t("common.save")}
        </Button>
        <Button
          variant="neutral"
          mode="stroke"
          size="small"
          onClick={refreshMe}
          disabled={!key || status === "checking"}
          isLoading={status === "checking"}
        >
          {status === "checking" ? "Checking…" : t("ps.test")}
        </Button>
      </div>
      <PsConnectionBadge status={status} me={me} err={err} hasKey={!!key} />
    </div>
  );
}
