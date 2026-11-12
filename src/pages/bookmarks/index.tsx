import { useEffect, useMemo, useState } from "react";
import { Button, Checkbox, DialogModal, cn } from "@proxyshard/shardx-ui-kit";
import { Topbar } from "../../shared/ui/Topbar";
import { EmptyState } from "../../shared/ui/EmptyState";
import { useStoreChanged } from "../../shared/hooks/useStoreChanged";
import { Field } from "../../shared/ui/Field";
import { CSSelect } from "../../shared/ui/CSSelect";
import { AddIcon, DeleteIcon, NavBookmarksIcon } from "../../shared/icons";
import { useBookmarks, emptyBookmark, type Bookmark } from "../../entities/bookmark";
import { useFolders, useProfile } from "../../entities/profile";
import { useT } from "../../shared/i18n";
import { Rich } from "../../shared/i18n/Rich";

function Editor({ initial, folders, onClose }: {
  initial: Bookmark;
  folders: string[];
  onClose: () => void;
}) {
  const [b, setB] = useState(initial);
  const t = useT();
  const save = useBookmarks((s) => s.save);
  return (
    <DialogModal
      open
      onClose={onClose}
      title={initial.id ? t("bookmarks.editTitle") : t("bookmarks.newTitle")}
      confirmLabel={t("common.save")}
      onConfirm={() => save(b)}
      cancelLabel={t("common.cancel")}
      onCancel={onClose}
    >
      <div className="flex w-[420px] flex-col gap-3 py-4">
        <Field
          label={t("bookmarks.url")}
          value={b.url}
          onChange={(v) => setB({ ...b, url: v })}
          placeholder="facebook.com/ads/manager"
          mono
        />
        <Field
          label={t("bookmarks.titleField")}
          value={b.title}
          onChange={(v) => setB({ ...b, title: v })}
          placeholder={t("bookmarks.titlePlaceholder")}
        />
        <CSSelect
          title={t("bookmarks.folder")}
          value={b.folder}
          onChange={(v) => setB({ ...b, folder: v })}
          isSearchable={folders.length > 8}
          options={[
            { value: "", label: t("bookmarks.everyProfile") },
            ...folders.map((f) => ({ value: f, label: f })),
          ]}
        />
        <p className="m-0 text-paragraph-xs text-text-soft-400">
          <Rich text={t("bookmarks.editorNote")} />
        </p>
      </div>
    </DialogModal>
  );
}

export function BookmarksPage() {
  const init = useBookmarks((s) => s.init);
  const items = useBookmarks((s) => s.items);
  const editing = useBookmarks((s) => s.editing);
  const setEditing = useBookmarks((s) => s.setEditing);
  const remove = useBookmarks((s) => s.remove);
  const removeMany = useBookmarks((s) => s.removeMany);
  const search = useBookmarks((s) => s.search);
  const setSearch = useBookmarks((s) => s.setSearch);
  const folder = useBookmarks((s) => s.folder);
  const setFolder = useBookmarks((s) => s.setFolder);

  const initProfiles = useProfile((s) => s.init);
  const folders = useFolders();
  const profiles = useProfile((s) => s.profiles);

  const t = useT();
  const reload = useBookmarks((s) => s.reload);
  useEffect(() => { init(); initProfiles(); }, [init, initProfiles]);
  useStoreChanged(reload);

  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter(
      (b) =>
        (folder === "all" || b.folder === (folder === "__any__" ? "" : folder)) &&
        (!q || b.title.toLowerCase().includes(q) || b.url.toLowerCase().includes(q)),
    );
  }, [items, search, folder]);

  // Picks follow the filter: the header box and the bar act on the rows shown.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const picked = useMemo(() => shown.filter((b) => selected.has(b.id)), [shown, selected]);
  const allShownPicked = shown.length > 0 && picked.length === shown.length;
  const toggle = (ids: string[], on: boolean) =>
    setSelected((s) => { const next = new Set(s); for (const id of ids) on ? next.add(id) : next.delete(id); return next; });

  const countIn = (f: string) =>
    f === "" ? profiles.length : profiles.filter((p) => p.folder === f).length;

  const tabs = [
    { id: "all", label: t("bookmarks.tab.all") },
    { id: "__any__", label: t("bookmarks.everyProfile") },
    ...folders.map((f) => ({ id: f, label: f })),
  ];

  return (
    <section className="flex flex-col">
      <Topbar crumbs={[t("nav.library"), t("bookmarks.title")]} search={search} onSearch={setSearch} />

      <div className="mb-3.5 flex items-end justify-between gap-4">
        <div className="flex min-w-0 flex-1 flex-col gap-3.5">
          <div>
            <h1 className="m-0 text-title-h5 text-text-strong-950">{t("bookmarks.title")}</h1>
            <p className="m-0 mt-1 max-w-[70ch] text-paragraph-xs text-text-soft-400">
              {t("bookmarks.intro")}
            </p>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setFolder(tab.id)}
                className={cn(
                  "rounded-6 px-2.5 py-1 text-label-xs ring-1 ring-inset transition-colors",
                  folder === tab.id
                    ? "bg-primary-alpha-10 text-primary-base ring-primary-alpha-24"
                    : "text-text-sub-600 ring-stroke-soft-200 hover:bg-bg-weak-50",
                )}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
        <Button
          variant="primary" mode="filled" size="small"
          leftIcon={<AddIcon className="size-4" />}
          onClick={() => setEditing(emptyBookmark(folder === "all" || folder === "__any__" ? "" : folder))}
        >
          {t("bookmarks.new")}
        </Button>
      </div>

      {picked.length > 0 && (
        <div className="mb-3 flex flex-wrap items-center gap-2 rounded-8 bg-primary-alpha-10 py-1 pl-3 pr-1 text-label-xs text-primary-base ring-1 ring-inset ring-primary-alpha-24">
          <span>{t("bookmarks.selectedCount", { n: picked.length })}</span>
          <Button
            variant="error" mode="stroke" size="2xsmall"
            leftIcon={<DeleteIcon className="size-3.5" />}
            onClick={() => void removeMany(picked).then((n) => { if (n > 0) setSelected(new Set()); })}
          >
            {t("common.delete")}
          </Button>
          <Button variant="neutral" mode="ghost" size="2xsmall" onClick={() => setSelected(new Set())}>
            {t("bookmarks.clear")}
          </Button>
        </div>
      )}

      <div className="overflow-hidden rounded-12 bg-bg-white-0 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
        {shown.length > 0 && (
          <div className="grid grid-cols-[28px_1fr_1fr_200px_100px] items-center gap-3 bg-bg-weak-50 px-4 py-2 text-subheading-2xs text-text-soft-400">
            <Checkbox
              aria-label={t("bookmarks.selectAll")}
              checked={allShownPicked}
              indeterminate={picked.length > 0 && !allShownPicked}
              onChange={(e) => toggle(shown.map((b) => b.id), e.target.checked)}
            />
            <div>{t("bookmarks.titleField")}</div>
            <div>{t("bookmarks.url")}</div>
            <div>{t("bookmarks.folder")}</div>
            <div />
          </div>
        )}
        {shown.map((b) => (
          <div
            key={b.id}
            className="grid grid-cols-[28px_1fr_1fr_200px_100px] items-center gap-3 border-t border-stroke-soft-200 px-4 py-2.5 first:border-t-0 transition-colors hover:bg-bg-weak-50"
          >
            <Checkbox
              aria-label={t("bookmarks.select", { name: b.title || b.url })}
              checked={selected.has(b.id)}
              onChange={(e) => toggle([b.id], e.target.checked)}
            />
            <div
              className="min-w-0 cursor-pointer truncate text-label-xs text-text-strong-950 transition-colors hover:text-primary-base"
              onClick={() => setEditing(b)}
              title={t("common.edit")}
            >
              {b.title || b.url}
            </div>
            <div className="mono min-w-0 truncate text-paragraph-xs text-text-sub-600" title={b.url}>
              {b.url}
            </div>
            <div className="truncate text-paragraph-xs text-text-sub-600">
              {b.folder
                ? `${b.folder} · ${t(
                    countIn(b.folder) === 1 ? "bookmarks.profileCountOne" : "bookmarks.profileCountMany",
                    { n: String(countIn(b.folder)) },
                  )}`
                : `${t("bookmarks.everyProfile")} · ${profiles.length}`}
            </div>
            <div className="flex justify-end">
              <Button
                variant="error" mode="ghost" size="2xsmall"
                leftIcon={<DeleteIcon className="size-3.5" />}
                onClick={() => remove(b)}
              >
                {t("common.delete")}
              </Button>
            </div>
          </div>
        ))}
        {shown.length === 0 && (
          <EmptyState
            icon={<NavBookmarksIcon className="size-6" />}
            title={items.length === 0 ? t("bookmarks.none.title") : t("bookmarks.none.inFolder")}
            body={t("bookmarks.none.body")}
          />
        )}
      </div>

      {editing && (
        <Editor initial={editing} folders={folders} onClose={() => setEditing(null)} />
      )}
    </section>
  );
}
