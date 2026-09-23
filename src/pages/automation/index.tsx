import { useEffect, useMemo } from "react";
import { Button, cn } from "@proxyshard/shardx-ui-kit";
import { Topbar } from "../../shared/ui/Topbar";
import { useStoreChanged } from "../../shared/hooks/useStoreChanged";
import { Field } from "../../shared/ui/Field";
import { CSSelect } from "../../shared/ui/CSSelect";
import {
  AddIcon,
  DeleteIcon,
  NavAutomationIcon,
  PlayIcon,
} from "../../shared/icons";
import {
  BLOCK_KINDS,
  emptyBlock,
  emptyProject,
  useAutomation,
  type Block,
  type Project,
  type RunReport,
} from "../../entities/automation";
import { useProfile } from "../../entities/profile";
import { useT } from "../../shared/i18n";

type ParamSpec = {
  key: string;
  /** A key in locales/, not the English text: the box label is translated. */
  labelKey: string;
  placeholder: string;
  /** When the hint is words rather than syntax, it is translated where it is
   *  drawn: a t() call here would freeze the first language the module saw. */
  placeholderKey?: string;
  /** Numbers are stored as JSON numbers; the runner rejects a string here. */
  numeric?: boolean;
  /** Read with `as_bool()`, so the string "true" would be ignored in silence. */
  boolean?: boolean;
};

/**
 * The params each kind actually reads, keyed exactly as `runner::exec_block`
 * looks them up. A key that does not appear there is a param the runner will
 * silently ignore, so this list is deliberately narrow.
 */
const PARAMS: Record<string, ParamSpec[]> = {
  navigate: [{ key: "url", labelKey: "automation.param.url", placeholder: "https://example.com" }],
  wait: [{ key: "ms", labelKey: "automation.param.milliseconds", placeholder: "1000", numeric: true }],
  waitForSelector: [{ key: "selector", labelKey: "automation.param.selector", placeholder: "#login" }],
  click: [{ key: "selector", labelKey: "automation.param.selector", placeholder: "button[type=submit]" }],
  type: [
    { key: "selector", labelKey: "automation.param.selector", placeholder: "input[name=email]" },
    { key: "text", labelKey: "automation.param.text", placeholder: "hello or {{var}}" },
  ],
  setVariable: [
    { key: "name", labelKey: "automation.param.variable", placeholder: "token" },
    { key: "value", labelKey: "automation.param.value", placeholder: "abc or {{other}}" },
  ],
  readText: [
    { key: "selector", labelKey: "automation.param.selector", placeholder: ".price" },
    { key: "into", labelKey: "automation.param.storeInVariable", placeholder: "price" },
  ],
  assert: [
    { key: "selector", labelKey: "automation.param.selector", placeholder: ".welcome" },
    { key: "expected", labelKey: "automation.param.mustContain", placeholder: "", placeholderKey: "automation.signedIn" },
  ],
  evaluate: [
    { key: "script", labelKey: "automation.param.script", placeholder: "document.title" },
    // A script may not interpolate a value that came from outside the project;
    // this is where such a value goes instead, arriving as an argument.
    { key: "with", labelKey: "automation.param.passVariablesIn", placeholder: '["price"]' },
    { key: "into", labelKey: "automation.param.storeInVariable", placeholder: "title" },
  ],
  recordTraffic: [],
  stopTraffic: [{ key: "into", labelKey: "automation.param.storeCountIn", placeholder: "requests" }],
  assertRequest: [
    { key: "urlContains", labelKey: "automation.param.urlContains", placeholder: "/api/login" },
    { key: "mustSucceed", labelKey: "automation.param.requireOneToHaveSucceeded", placeholder: "", boolean: true },
    { key: "into", labelKey: "automation.param.storeCountIn", placeholder: "hits" },
  ],
  httpOpen: [],
  httpRequest: [
    { key: "url", labelKey: "automation.param.url", placeholder: "https://api.example.com/v1/me" },
    { key: "method", labelKey: "automation.param.method", placeholder: "", placeholderKey: "automation.get" },
    { key: "body", labelKey: "automation.param.body", placeholder: '{"name":"{{who}}"}' },
    {
      key: "headers",
      labelKey: "automation.param.headers",
      placeholder: '{"Authorization":"Bearer {{token}}"}',
    },
    { key: "mustSucceed", labelKey: "automation.param.requireA2xxReply", placeholder: "", boolean: true },
    { key: "into", labelKey: "automation.param.storeBodyIn", placeholder: "response" },
    { key: "statusInto", labelKey: "automation.param.storeStatusIn", placeholder: "code" },
  ],
  httpClose: [],
  readFile: [
    { key: "path", labelKey: "automation.param.file", placeholder: "accounts.txt" },
    { key: "into", labelKey: "automation.param.storeInVariable", placeholder: "accounts" },
  ],
  writeFile: [
    { key: "path", labelKey: "automation.param.file", placeholder: "out/result.txt" },
    { key: "contents", labelKey: "automation.param.contents", placeholder: "{{response}}" },
  ],
  appendFile: [
    { key: "path", labelKey: "automation.param.file", placeholder: "out/run.log" },
    { key: "contents", labelKey: "automation.param.contents", placeholder: "{{who}} done\n" },
  ],
  fileExists: [
    { key: "path", labelKey: "automation.param.file", placeholder: "out/result.txt" },
    { key: "mustExist", labelKey: "automation.param.failTheRunWhenMissing", placeholder: "", boolean: true },
    { key: "into", labelKey: "automation.param.storeInVariable", placeholder: "found" },
  ],
  deleteFile: [{ key: "path", labelKey: "automation.param.file", placeholder: "out/result.txt" }],
  dbExecute: [
    { key: "database", labelKey: "automation.param.database", placeholder: "work.db" },
    {
      key: "sql",
      labelKey: "automation.param.statement",
      placeholder: "insert into seen (name) values (?)",
    },
    { key: "params", labelKey: "automation.param.parameters", placeholder: '["{{who}}"]' },
    { key: "into", labelKey: "automation.param.storeRowCountIn", placeholder: "changed" },
  ],
  dbQuery: [
    { key: "database", labelKey: "automation.param.database", placeholder: "work.db" },
    {
      key: "sql",
      labelKey: "automation.param.query",
      placeholder: "select name from seen where done = ?",
    },
    { key: "params", labelKey: "automation.param.parameters", placeholder: "[0]" },
    { key: "into", labelKey: "automation.param.storeRowsIn", placeholder: "rows" },
    { key: "countInto", labelKey: "automation.param.storeCountIn", placeholder: "found" },
    { key: "firstColumn", labelKey: "automation.param.firstRowColumn", placeholder: "name" },
    { key: "firstInto", labelKey: "automation.param.storeFirstValueIn", placeholder: "next" },
    { key: "minRows", labelKey: "automation.param.requireAtLeast", placeholder: "1", numeric: true },
  ],
};

const str = (v: unknown) => (v == null ? "" : String(v));

/** Keep an empty box out of the params rather than storing "" or NaN. */
function paramValue(spec: ParamSpec, typed: string): unknown {
  if (typed === "") return undefined;
  if (spec.boolean) return typed === "true";
  if (!spec.numeric) return typed;
  const n = Number(typed);
  return Number.isFinite(n) ? n : typed;
}

function BlockRow({
  block,
  index,
  total,
  onChange,
  onMove,
  onRemove,
}: {
  block: Block;
  index: number;
  total: number;
  onChange: (b: Block) => void;
  onMove: (dir: -1 | 1) => void;
  onRemove: () => void;
}) {
  const t = useT();
  const fields = PARAMS[block.kind] ?? [];
  return (
    <div className="border-t border-stroke-soft-200 px-4 py-3 first:border-t-0">
      <div className="flex items-center gap-2">
        <span className="w-6 shrink-0 text-paragraph-xs text-text-soft-400">
          {index + 1}
        </span>
        <div className="w-[190px] shrink-0">
          <CSSelect
            value={block.kind}
            // Params belong to the old kind; keeping them would send junk to the runner.
            onChange={(v) => onChange({ ...block, kind: v, params: {} })}
            options={BLOCK_KINDS.map((k) => ({ value: k, label: k }))}
          />
        </div>
        <div className="flex min-w-0 flex-1 flex-wrap gap-2">
          {fields.map((f) => (
            <div key={f.key} className="min-w-[160px] flex-1">
              {f.boolean ? (
                // A text box here would store "true", which `as_bool()` reads
                // as absent -- the setting would look set and do nothing.
                <label className="flex items-center gap-2 py-[7px] text-paragraph-xs text-text-sub-600">
                  <input
                    type="checkbox"
                    checked={block.params[f.key] === true}
                    onChange={(e) => {
                      const next = { ...block.params };
                      if (e.target.checked) next[f.key] = true;
                      else delete next[f.key];
                      onChange({ ...block, params: next });
                    }}
                  />
                  {t(f.labelKey)}
                </label>
              ) : (
                <Field
                  label={t(f.labelKey)}
                  value={str(block.params[f.key])}
                  placeholder={f.placeholderKey ? t(f.placeholderKey) : f.placeholder}
                  onChange={(v) => {
                    const next = { ...block.params };
                    const parsed = paramValue(f, v);
                    if (parsed === undefined) delete next[f.key];
                    else next[f.key] = parsed;
                    onChange({ ...block, params: next });
                  }}
                />
              )}
            </div>
          ))}
          {fields.length === 0 && (
            <span className="self-center text-paragraph-xs text-text-soft-400">
              {t("automation.noParams")}
            </span>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-1">
          <Button
            variant="neutral" mode="ghost" size="2xsmall"
            disabled={index === 0}
            onClick={() => onMove(-1)}
          >
            ↑
          </Button>
          <Button
            variant="neutral" mode="ghost" size="2xsmall"
            disabled={index === total - 1}
            onClick={() => onMove(1)}
          >
            ↓
          </Button>
          <Button
            variant={block.enabled ? "neutral" : "primary"}
            mode="ghost" size="2xsmall"
            onClick={() => onChange({ ...block, enabled: !block.enabled })}
            title={block.enabled ? t("automation.skipThisBlock") : t("automation.enableThisBlock")}
          >
            {block.enabled ? "On" : t("automation.off")}
          </Button>
          <Button
            variant="error" mode="ghost" size="2xsmall"
            leftIcon={<DeleteIcon className="size-3.5" />}
            onClick={onRemove}
          />
        </div>
      </div>
      <div className="mt-2 flex items-center gap-2 pl-8">
        <span className="text-paragraph-xs text-text-soft-400">{t("automation.onFailure")}</span>
        <div className="w-[150px]">
          <CSSelect
            value={block.on_fail === "next" ? "next" : "stop"}
            onChange={(v) => onChange({ ...block, on_fail: v === "next" ? "next" : "stop" })}
            options={[
              { value: "stop", label: t("automation.param.stopTheRun") },
              { value: "next", label: t("automation.param.carryOn") },
            ]}
          />
        </div>
      </div>
    </div>
  );
}

function RunPanel({ report }: { report: RunReport }) {
  const t = useT();
  return (
    <div className="mt-4 overflow-hidden rounded-12 bg-bg-white-0 ring-1 ring-inset ring-stroke-soft-200">
      <div className="flex items-center justify-between border-b border-stroke-soft-200 px-4 py-2.5">
        <span className="text-label-xs text-text-strong-950">
          {t("automation.run.last")} · {t(report.ok ? "automation.run.passed" : "automation.run.failed")} · {report.ms} ms
        </span>
        {report.stopped_because && (
          <span className="text-paragraph-xs text-error-base">
            {report.stopped_because}
          </span>
        )}
      </div>
      {report.steps.map((s, i) => (
        <div
          key={`${s.block_id}-${i}`}
          className="grid grid-cols-[28px_140px_1fr_90px_70px] items-center gap-2 border-t border-stroke-soft-200 px-4 py-2 first:border-t-0"
        >
          <span className="text-paragraph-xs text-text-soft-400">{i + 1}</span>
          <span className="truncate text-paragraph-xs text-text-sub-600">{s.kind}</span>
          <span className="truncate text-paragraph-xs text-text-sub-600" title={s.error ?? ""}>
            {s.error ?? s.label ?? ""}
          </span>
          <span
            className={cn(
              "text-paragraph-xs",
              s.outcome === "ok" && "text-success-base",
              s.outcome === "failed" && "text-error-base",
              (s.outcome === "skipped" || s.outcome === "stopped") && "text-text-soft-400",
            )}
          >
            {t(`automation.outcome.${s.outcome}`)}
          </span>
          <span className="text-right text-paragraph-xs text-text-soft-400">{s.ms} ms</span>
        </div>
      ))}
      {Object.keys(report.variables).length > 0 && (
        <div className="border-t border-stroke-soft-200 px-4 py-2 text-paragraph-xs text-text-sub-600">
          {Object.entries(report.variables)
            .map(([k, v]) => `${k} = ${v}`)
            .join("  ·  ")}
        </div>
      )}
    </div>
  );
}

function Editor({ project }: { project: Project }) {
  const patch = useAutomation((s) => s.patchEditing);
  const save = useAutomation((s) => s.save);
  const run = useAutomation((s) => s.run);
  const running = useAutomation((s) => s.running);
  const lastRun = useAutomation((s) => s.lastRun);
  const setEditing = useAutomation((s) => s.setEditing);
  const runProfile = useAutomation((s) => s.runProfile);
  const setRunProfile = useAutomation((s) => s.setRunProfile);
  const profiles = useProfile((s) => s.profiles);

  const t = useT();
  const setBlocks = (blocks: Block[]) => patch({ blocks });

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-end gap-3">
        <div className="w-[280px]">
          <Field
            label={t("automation.name")}
            value={project.name}
            placeholder={t("automation.namePlaceholder")}
            onChange={(v) => patch({ name: v })}
          />
        </div>
        <div className="min-w-0 flex-1">
          <Field
            label={t("automation.notes")}
            value={project.notes}
            placeholder={t("automation.notesPlaceholder")}
            onChange={(v) => patch({ notes: v })}
          />
        </div>
        <Button variant="neutral" mode="stroke" size="small" onClick={() => setEditing(null)}>
          {t("automation.close")}
        </Button>
        <Button variant="primary" mode="filled" size="small" onClick={() => save(project)}>
          {t("common.save")}
        </Button>
      </div>

      <div className="flex items-end gap-3 rounded-12 bg-bg-weak-50 px-4 py-3">
        <div className="w-[280px]">
          <CSSelect
            title={t("automation.runAgainst")}
            value={runProfile}
            onChange={setRunProfile}
            isSearchable={profiles.length > 8}
            options={[
              { value: "", label: t("automation.param.pickARunningProfile") },
              ...profiles.map((p) => ({ value: p.id, label: p.name })),
            ]}
          />
        </div>
        <Button
          variant="primary" mode="filled" size="small"
          disabled={running || !project.id}
          leftIcon={<PlayIcon className="size-4" />}
          onClick={() => run(project)}
        >
          {running ? t("automation.running") : t("automation.run")}
        </Button>
        <p className="m-0 flex-1 text-paragraph-xs text-text-soft-400">
          {t("automation.runHelp")}
        </p>
      </div>

      <div className="overflow-hidden rounded-12 bg-bg-white-0 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
        {project.blocks.map((b, i) => (
          <BlockRow
            key={b.id}
            block={b}
            index={i}
            total={project.blocks.length}
            onChange={(next) =>
              setBlocks(project.blocks.map((x) => (x.id === b.id ? next : x)))
            }
            onMove={(dir) => {
              const next = [...project.blocks];
              const to = i + dir;
              if (to < 0 || to >= next.length) return;
              [next[i], next[to]] = [next[to], next[i]];
              setBlocks(next);
            }}
            onRemove={() => setBlocks(project.blocks.filter((x) => x.id !== b.id))}
          />
        ))}
        {project.blocks.length === 0 && (
          <div className="px-4 py-8 text-center text-paragraph-sm text-text-sub-600">
            {t("automation.noBlocks")}
          </div>
        )}
      </div>

      <div>
        <Button
          variant="neutral" mode="stroke" size="small"
          leftIcon={<AddIcon className="size-4" />}
          onClick={() => setBlocks([...project.blocks, emptyBlock()])}
        >
          {t("automation.addBlock")}
        </Button>
      </div>

      {lastRun && <RunPanel report={lastRun} />}
    </div>
  );
}

export function AutomationPage() {
  const init = useAutomation((s) => s.init);
  const reload = useAutomation((s) => s.reload);
  const items = useAutomation((s) => s.items);
  const editing = useAutomation((s) => s.editing);
  const setEditing = useAutomation((s) => s.setEditing);
  const remove = useAutomation((s) => s.remove);
  const search = useAutomation((s) => s.search);
  const setSearch = useAutomation((s) => s.setSearch);
  const initProfiles = useProfile((s) => s.init);

  useEffect(() => { init(); initProfiles(); }, [init, initProfiles]);
  useStoreChanged(reload);

  const t = useT();
  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (p) => p.name.toLowerCase().includes(q) || p.notes.toLowerCase().includes(q),
    );
  }, [items, search]);

  return (
    <>
      <Topbar
        crumbs={[t("automation.title")]}
        search={editing ? undefined : search}
        onSearch={editing ? undefined : setSearch}
      />
      <div className="flex flex-col gap-4 px-6 py-5">
        {editing ? (
          <Editor project={editing} />
        ) : (
          <>
            <div className="flex items-center justify-between">
              <p className="m-0 text-paragraph-sm text-text-sub-600">
                {t("automation.intro")}
              </p>
              <Button
                variant="primary" mode="filled" size="small"
                leftIcon={<AddIcon className="size-4" />}
                onClick={() => setEditing(emptyProject())}
              >
                {t("automation.newProject")}
              </Button>
            </div>

            <div className="overflow-hidden rounded-12 bg-bg-white-0 shadow-[var(--shadow-xs)] ring-1 ring-inset ring-stroke-soft-200">
              {shown.map((p) => (
                <div
                  key={p.id}
                  className="grid grid-cols-[1fr_1fr_120px_100px] items-center gap-3 border-t border-stroke-soft-200 px-4 py-2.5 first:border-t-0 transition-colors hover:bg-bg-weak-50"
                >
                  <div
                    className="min-w-0 cursor-pointer truncate text-label-xs text-text-strong-950 transition-colors hover:text-primary-base"
                    onClick={() => setEditing(p)}
                    title={t("common.edit")}
                  >
                    {p.name || t("automation.untitled")}
                  </div>
                  <div className="min-w-0 truncate text-paragraph-xs text-text-sub-600">
                    {p.notes}
                  </div>
                  <div className="text-paragraph-xs text-text-sub-600">
                    {t(p.blocks.length === 1 ? "automation.blockOne" : "automation.blockMany", { n: String(p.blocks.length) })}
                  </div>
                  <div className="flex justify-end">
                    <Button
                      variant="error" mode="ghost" size="2xsmall"
                      leftIcon={<DeleteIcon className="size-3.5" />}
                      onClick={() => remove(p)}
                    />
                  </div>
                </div>
              ))}
              {shown.length === 0 && (
                <div className="flex flex-col items-center gap-2.5 px-6 py-14 text-center">
                  <div className="grid size-14 place-items-center rounded-[14px] bg-primary-alpha-10 text-primary-base ring-1 ring-inset ring-primary-alpha-24">
                    <NavAutomationIcon className="size-6" />
                  </div>
                  <h3 className="m-0 text-label-sm text-text-strong-950">
                    {items.length === 0 ? t("automation.none.title") : t("automation.none.noMatch")}
                  </h3>
                  <p className="m-0 max-w-[460px] text-paragraph-sm text-text-sub-600">
                    {t("automation.none.body")}
                  </p>
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </>
  );
}
