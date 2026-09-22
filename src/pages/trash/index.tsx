import { useEffect } from "react";
import { Button } from "@proxyshard/shardx-ui-kit";
import { Topbar } from "../../shared/ui/Topbar";
import { useStoreChanged } from "../../shared/hooks/useStoreChanged";
import Badge from "../../shared/ui/Badge";
import { DeleteIcon, NavTrashIcon, RestoreIcon } from "../../shared/icons";
import { daysUntil, fmtBytes, fmtTs } from "../../shared/lib/utils";
import { useTrash } from "../../entities/trash";
import { useT } from "../../shared/i18n";

export function TrashPage() {
  const init = useTrash((s) => s.init);
  const items = useTrash((s) => s.items);
  const busy = useTrash((s) => s.busy);
  const restore = useTrash((s) => s.restore);
  const purge = useTrash((s) => s.purge);
  const empty = useTrash((s) => s.empty);

  const t = useT();
  const reload = useTrash((s) => s.reload);
  useEffect(() => { init(); }, [init]);
  // A profile deleted or restored through the API belongs in this list.
  useStoreChanged(reload);

  return (
    <section className="flex flex-col">
      <Topbar crumbs={[t("nav.system"), t("trash.title")]} />

      <div className="mb-3.5 flex items-end justify-between gap-4">
        <div>
          <h1 className="m-0 text-title-h5 text-text-strong-950">{t("trash.title")}</h1>
          <p className="m-0 mt-1 max-w-[70ch] text-paragraph-xs text-text-soft-400">
            {t("trash.intro")}
          </p>
        </div>
        {items.length > 0 && (
          <Button
            variant="error" mode="stroke" size="small"
            leftIcon={<DeleteIcon className="size-4" />}
            onClick={empty}
          >
            {t("trash.empty")}
          </Button>
        )}
      </div>

      <div className="overflow-hidden rounded-12 bg-bg-white-0 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
        {items.length > 0 && (
          <div className="grid grid-cols-[1fr_120px_150px_120px_180px] items-center gap-3 border-b border-stroke-soft-200 bg-bg-weak-50 px-4 py-2 text-subheading-2xs text-text-soft-400">
            <div>{t("trash.col.name")}</div>
            <div>{t("trash.col.folder")}</div>
            <div>{t("trash.col.deleted")}</div>
            <div>{t("trash.col.size")}</div>
            <div />
          </div>
        )}
        {items.map((e) => {
          const left = daysUntil(e.expires_at);
          return (
            <div
              key={e.id}
              className="grid grid-cols-[1fr_120px_150px_120px_180px] items-center gap-3 border-t border-stroke-soft-200 px-4 py-2.5 first:border-t-0 transition-colors hover:bg-bg-weak-50"
            >
              <div className="min-w-0">
                <div className="truncate text-label-xs text-text-strong-950">{e.name}</div>
                <div className="mono truncate text-[10.5px] text-text-disabled-300">{e.id.slice(0, 8)}</div>
              </div>
              <div className="truncate text-paragraph-xs text-text-sub-600">
                {e.folder || <span className="text-text-soft-400">—</span>}
              </div>
              <div className="flex items-center gap-1.5">
                <span className="text-paragraph-xs text-text-soft-400">{fmtTs(`@${e.deleted_at}`)}</span>
                <Badge color={left <= 1 ? "error" : "gray"} variant="filled" size="small">
                  {left === 0 ? t("trash.today") : t("trash.daysLeft", { n: String(left) })}
                </Badge>
              </div>
              <div className="text-paragraph-xs text-text-sub-600">{fmtBytes(e.size_bytes)}</div>
              <div className="flex justify-end gap-2">
                <Button
                  variant="neutral" mode="stroke" size="2xsmall"
                  disabled={busy === e.id} isLoading={busy === e.id}
                  leftIcon={<RestoreIcon className="size-3.5" />}
                  onClick={() => restore(e)}
                >
                  {t("trash.restore")}
                </Button>
                <Button
                  variant="error" mode="ghost" size="2xsmall"
                  leftIcon={<DeleteIcon className="size-3.5" />}
                  onClick={() => purge(e)}
                >
                  {t("trash.delete")}
                </Button>
              </div>
            </div>
          );
        })}
        {items.length === 0 && (
          <div className="flex flex-col items-center gap-2.5 px-6 py-14 text-center">
            <div className="grid size-14 place-items-center rounded-[14px] bg-primary-alpha-10 text-primary-base ring-1 ring-inset ring-primary-alpha-24">
              <NavTrashIcon className="size-6" />
            </div>
            <h3 className="m-0 text-label-sm text-text-strong-950">{t("trash.none.title")}</h3>
            <p className="m-0 max-w-[420px] text-paragraph-sm text-text-sub-600">
              {t("trash.none.body")}
            </p>
          </div>
        )}
      </div>
    </section>
  );
}
