import { useEffect, useMemo, useState } from "react";
import { Button, DialogModal } from "@proxyshard/shardx-ui-kit";
import { Topbar } from "../../shared/ui/Topbar";
import { useStoreChanged } from "../../shared/hooks/useStoreChanged";
import { AddIcon, DeleteIcon, FolderIcon, GlobeIcon, NavExtensionsIcon } from "../../shared/icons";
import { Field } from "../../shared/ui/Field";
import { useExtensions, type ExtensionEntry } from "../../entities/extension";
import { fmtBytes } from "../../shared/lib/utils";
import { useT } from "../../shared/i18n";

function Card({ e }: { e: ExtensionEntry }) {
  const t = useT();
  const remove = useExtensions((s) => s.remove);
  return (
    <article className="flex flex-col gap-2.5 rounded-xl bg-bg-white-0 p-3.5 ring-1 ring-inset ring-stroke-soft-200">
      <div className="flex items-start gap-2.5">
        {e.icon ? (
          <img src={e.icon} alt="" className="size-10 shrink-0 rounded-lg object-contain" />
        ) : (
          <div className="grid size-10 shrink-0 place-items-center rounded-lg bg-primary-alpha-10 text-primary-base">
            <NavExtensionsIcon className="size-5" />
          </div>
        )}
        <div className="min-w-0 flex-1">
          <h3 className="m-0 truncate text-label-xs text-text-strong-950" title={e.name}>{e.name}</h3>
          <div className="mt-0.5 flex items-center gap-1.5 text-paragraph-xs text-text-soft-400">
            {e.version && <span>v{e.version}</span>}
            <span>·</span>
            <span>{fmtBytes(e.size_bytes)}</span>
          </div>
        </div>
      </div>
      <p className="m-0 line-clamp-3 min-h-[2.4em] text-paragraph-xs text-text-sub-600">
        {e.description || <span className="text-text-soft-400">{t("extensions.noDescription")}</span>}
      </p>
      <div className="flex justify-end">
        <Button
          variant="error"
          mode="ghost"
          size="2xsmall"
          leftIcon={<DeleteIcon className="size-3.5" />}
          onClick={() => remove(e)}
        >
          {t("extensions.remove")}
        </Button>
      </div>
    </article>
  );
}

/** Add by address: a Web Store page, a bare id, or a .crx / .zip link. */
function LinkDialog({ onClose }: { onClose: () => void }) {
  const [url, setUrl] = useState("");
  const t = useT();
  const busy = useExtensions((s) => s.busy);
  const importUrl = useExtensions((s) => s.importUrl);
  return (
    <DialogModal
      open
      onClose={onClose}
      title={t("extensions.link.title")}
      confirmLabel={busy ? t("extensions.link.downloading") : t("extensions.link.download")}
      onConfirm={() => importUrl(url)}
      isLoading={busy}
      isDisabled={busy || !url.trim()}
      cancelLabel={t("common.cancel")}
      onCancel={onClose}
    >
      <div className="flex w-[460px] flex-col gap-3 py-4">
        <Field
          label={t("extensions.link.field")}
          value={url}
          onChange={setUrl}
          placeholder="https://chromewebstore.google.com/detail/…"
          mono
        />
        <p className="m-0 text-paragraph-xs text-text-soft-400">
          {t("extensions.link.help")}
        </p>
      </div>
    </DialogModal>
  );
}

export function ExtensionsPage() {
  const init = useExtensions((s) => s.init);
  const items = useExtensions((s) => s.items);
  const busy = useExtensions((s) => s.busy);
  const search = useExtensions((s) => s.search);
  const setSearch = useExtensions((s) => s.setSearch);
  const importFiles = useExtensions((s) => s.importFiles);
  const importFolder = useExtensions((s) => s.importFolder);
  const linkOpen = useExtensions((s) => s.linkOpen);
  const setLinkOpen = useExtensions((s) => s.setLinkOpen);

  const t = useT();
  const reload = useExtensions((s) => s.reload);
  useEffect(() => { init(); }, [init]);
  // Pick up extensions added through the automation API.
  useStoreChanged(reload);

  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (e) => e.name.toLowerCase().includes(q) || e.description.toLowerCase().includes(q),
    );
  }, [items, search]);

  return (
    <section className="flex flex-col">
      <Topbar crumbs={[t("nav.library"), t("extensions.title")]} search={search} onSearch={setSearch} />

      <div className="mb-3.5 flex items-end justify-between gap-4">
        <div>
          <h1 className="m-0 text-title-h5 text-text-strong-950">{t("extensions.title")}</h1>
          <p className="m-0 mt-1 max-w-[70ch] text-paragraph-xs text-text-soft-400">
            {t("extensions.intro")}
          </p>
        </div>
        <div className="flex flex-none items-center gap-2">
          <Button
            variant="neutral" mode="stroke" size="small" disabled={busy}
            leftIcon={<FolderIcon className="size-4" />}
            onClick={importFolder}
          >
            {t("extensions.unpacked")}
          </Button>
          <Button
            variant="neutral" mode="stroke" size="small" disabled={busy}
            leftIcon={<GlobeIcon className="size-4" />}
            onClick={() => setLinkOpen(true)}
          >
            {t("extensions.fromLink")}
          </Button>
          <Button
            variant="primary" mode="filled" size="small" disabled={busy} isLoading={busy}
            leftIcon={<AddIcon className="size-4" />}
            onClick={importFiles}
          >
            {t("extensions.addFile")}
          </Button>
        </div>
      </div>

      {shown.length === 0 ? (
        <div className="flex flex-col items-center gap-2.5 rounded-lg bg-bg-white-0 px-6 py-14 text-center ring-1 ring-inset ring-stroke-soft-200">
          <div className="grid size-14 place-items-center rounded-[14px] bg-primary-alpha-10 text-primary-base ring-1 ring-inset ring-primary-alpha-24">
            <NavExtensionsIcon className="size-6" />
          </div>
          <h3 className="m-0 text-label-sm text-text-strong-950">
            {items.length === 0 ? t("extensions.none.title") : t("extensions.none.noMatch")}
          </h3>
          <p className="m-0 max-w-[420px] text-paragraph-sm text-text-sub-600">
            {t("extensions.none.body")}
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-[repeat(auto-fill,minmax(260px,1fr))] gap-2.5 pb-6">
          {shown.map((e) => <Card key={e.id} e={e} />)}
        </div>
      )}

      {linkOpen && <LinkDialog onClose={() => setLinkOpen(false)} />}
    </section>
  );
}
