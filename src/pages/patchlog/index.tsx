import { Fragment, useState, type ReactNode } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import { Button, cn } from "@proxyshard/shardx-ui-kit";
import { Topbar } from "../../shared/ui/Topbar";
import { useT, useLang } from "../../shared/i18n";
import Badge from "../../shared/ui/Badge";
import { LockedIcon, StarOutlineIcon, ChevronDownIcon } from "../../shared/icons";
import { withUtm } from "../../shared/lib/utils";
import data from "./patchlog.json";
import dataVi from "./patchlog.vi.json";

/** The log is data, in patchlog.json; this module only draws it. */

type Block =
  | { type: "p" | "note"; text: string }
  | { type: "code"; text: string }
  | { type: "list"; items: string[] };

type Entry = {
  id: string;
  title: string;
  /** One line under the title: what it is, before any detail. */
  lead: string;
  tag?: string;
  /** Which half of the product changed: the engine, or the launcher. */
  scope?: "browser" | "launcher";
  locked?: boolean;
  blocks: Block[];
};

type Release = { version: string; date: string; entries: Entry[] };

const RELEASES = data.releases as Release[];
/** The same log, in Vietnamese: same ids, same shape, translated prose. */
const RELEASES_VI = dataVi.releases as Release[];

/**
 * The log the reader can actually read. Both files carry the same releases in
 * the same order, so the picker and the selected version keep their meaning
 * when the language changes under them.
 */
function useReleases(): Release[] {
  const lang = useLang((s) => s.lang);
  return lang === "vi" ? RELEASES_VI : RELEASES;
}

/** Newest release, and the one the picker starts on. */
const LATEST = RELEASES[0];

/** "new" is an addition, anything else reads as a correction. */
const tagColor = (tag: string) => (tag === "new" ? "success" : "primary");

const SCOPE_KEY: Record<string, string> = {
  browser: "patchlog.scope.browser",
  launcher: "patchlog.scope.launcher",
};

/**
 * The tag is data, and `tagColor` reads its raw value, so translating it in
 * patchlog.vi.json would decide the badge's colour by a Vietnamese word.
 * Translate at render instead, exactly as the scope label does.
 */
const TAG_KEY: Record<string, string> = {
  new: "patchlog.tag.new",
  fix: "patchlog.tag.fix",
};

/** Inline markup, deliberately tiny: `code`, **strong**, *emphasis*. */
function Rich({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*|\*[^*]+\*)/g);
  return (
    <>
      {parts.map((p, i) => {
        if (p.startsWith("`") && p.endsWith("`") && p.length > 2) {
          return (
            <code
              key={i}
              className="rounded bg-bg-weak-50 px-1 py-0.5 font-mono text-[11px] text-text-strong-950"
            >
              {p.slice(1, -1)}
            </code>
          );
        }
        if (p.startsWith("**") && p.endsWith("**") && p.length > 4) {
          return (
            <strong key={i} className="text-text-strong-950">
              {p.slice(2, -2)}
            </strong>
          );
        }
        if (p.startsWith("*") && p.endsWith("*") && p.length > 2) {
          return <em key={i}>{p.slice(1, -1)}</em>;
        }
        return <Fragment key={i}>{p}</Fragment>;
      })}
    </>
  );
}

function Blocks({ blocks }: { blocks: Block[] }) {
  return (
    <>
      {blocks.map((b, i) => {
        const spaced = i === 0 ? "" : "mt-2";
        if (b.type === "code") {
          return (
            <pre
              key={i}
              className={cn(
                "m-0 overflow-x-auto rounded-lg bg-bg-weak-50 p-3 font-mono text-[11px] leading-relaxed text-text-sub-600 ring-1 ring-inset ring-stroke-soft-200",
                i === 0 ? "" : "mt-2.5",
              )}
            >
              {b.text}
            </pre>
          );
        }
        if (b.type === "list") {
          return (
            <ul key={i} className={cn("m-0 flex list-none flex-col gap-1.5 p-0", spaced)}>
              {b.items.map((it, j) => (
                <li key={j} className="flex gap-2 text-paragraph-xs text-text-sub-600">
                  <span className="mt-[7px] size-1 shrink-0 rounded-full bg-text-soft-400" />
                  <span>
                    <Rich text={it} />
                  </span>
                </li>
              ))}
            </ul>
          );
        }
        return (
          <p
            key={i}
            className={cn(
              "m-0 text-paragraph-xs",
              b.type === "note" ? "text-text-soft-400" : "text-text-sub-600",
              spaced,
            )}
          >
            <Rich text={b.text} />
          </p>
        );
      })}
    </>
  );
}

function ReleasePicker({
  value,
  onChange,
  releases,
}: {
  value: Release;
  onChange: (version: string) => void;
  releases: Release[];
}) {
  const [open, setOpen] = useState(false);
  const t = useT();
  return (
    <div className="relative">
      <button
        type="button"
        className="flex cursor-pointer items-center gap-2 rounded-lg border-0 bg-bg-weak-50 px-2.5 py-[7px] text-label-xs text-text-strong-950 ring-1 ring-inset ring-stroke-soft-200 transition-colors hover:bg-bg-white-0"
        onClick={() => setOpen((v) => !v)}
      >
        <span>v{value.version}</span>
        {value.version === LATEST.version && (
          <Badge color="success" variant="filled" size="small">
            {t("patchlog.latest")}
          </Badge>
        )}
        <span
          className={cn(
            "grid place-items-center text-icon-soft-400 transition-transform",
            open && "rotate-180",
          )}
        >
          <ChevronDownIcon className="size-4" />
        </span>
      </button>

      {open && (
        <>
          {/* Click anywhere else and the list goes away. */}
          <div className="fixed inset-0 z-10" onClick={() => setOpen(false)} />
          <div className="absolute right-0 z-20 mt-1.5 min-w-[190px] overflow-hidden rounded-xl bg-bg-white-0 p-1 shadow-lg ring-1 ring-stroke-soft-200">
            {releases.map((r) => (
              <button
                key={r.version}
                type="button"
                className={cn(
                  "flex w-full cursor-pointer items-center justify-between gap-3 rounded-lg border-0 px-2.5 py-2 text-left text-label-xs transition-colors",
                  r.version === value.version
                    ? "bg-primary-alpha-10 text-primary-base"
                    : "bg-transparent text-text-sub-600 hover:bg-bg-weak-50",
                )}
                onClick={() => {
                  onChange(r.version);
                  setOpen(false);
                }}
              >
                <span>v{r.version}</span>
                <span className="text-paragraph-xs text-text-soft-400">{r.date}</span>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
}

function LockNotice() {
  const t = useT();
  return (
    <div className="mt-2.5 flex flex-col gap-2 rounded-lg bg-warning-alpha-16 p-3 ring-1 ring-inset ring-warning-base/30">
      <div className="flex items-center gap-2 text-label-xs text-text-strong-950">
        <span className="text-warning-base">
          <LockedIcon className="size-[15px]" />
        </span>
        <span>
          {t("patchlog.lock.ships", { n: data.starsRequired.toLocaleString("en-US") })}
        </span>
      </div>
      <p className="m-0 text-paragraph-xs text-text-sub-600">
        {t("patchlog.lock.body")}
      </p>
      <div>
        <Button
          size="xsmall"
          variant="neutral"
          mode="stroke"
          onClick={() => openUrl(withUtm(data.repoUrl)).catch(() => {})}
        >
          <span className="mr-1.5 inline-grid place-items-center align-middle">
            <StarOutlineIcon className="size-[14px]" />
          </span>
          {t("patchlog.lock.star")}
        </Button>
      </div>
    </div>
  );
}

function EntryCard({ entry }: { entry: Entry }): ReactNode {
  const t = useT();
  return (
    <article className="rounded-xl bg-bg-white-0 p-4 ring-1 ring-inset ring-stroke-soft-200">
      <div className="flex flex-wrap items-center gap-2">
        <h2 className="m-0 text-label-sm text-text-strong-950">{entry.title}</h2>
        <span className="rounded-4 bg-bg-weak-50 px-1.5 py-0.5 text-[10.5px] font-bold uppercase tracking-[0.5px] text-text-soft-400">
          {t(SCOPE_KEY[entry.scope ?? "browser"])}
        </span>
        {entry.tag && (
          <Badge color={tagColor(entry.tag)} variant="filled" size="small">
            {TAG_KEY[entry.tag] ? t(TAG_KEY[entry.tag]) : entry.tag}
          </Badge>
        )}
        {entry.locked && (
          <Badge color="warning" variant="filled" size="small">
            {t("patchlog.locked")}
          </Badge>
        )}
      </div>
      <p className="m-0 mb-2.5 mt-1 max-w-[80ch] text-paragraph-xs text-text-soft-400">
        {entry.lead}
      </p>
      <div className="max-w-[80ch]">
        <Blocks blocks={entry.blocks} />
      </div>
      {entry.locked && <LockNotice />}
    </article>
  );
}

export function PatchLogPage() {
  const releases = useReleases();
  // Hold the version, not the object: switching language replaces every
  // release object, and a reference kept across that swap would stop matching.
  const [version, setVersion] = useState<string>(LATEST.version);
  const release = releases.find((r) => r.version === version) ?? releases[0];
  const t = useT();

  return (
    <section className="flex flex-col">
      <Topbar crumbs={[t("nav.system"), t("patchlog.title")]} />

      <div className="mb-1.5 flex items-start justify-between gap-4">
        <h1 className="m-0 text-title-h5 text-text-strong-950">{t("patchlog.title")}</h1>
        <ReleasePicker value={release} onChange={setVersion} releases={releases} />
      </div>

      <p className="m-0 mb-3.5 max-w-[70ch] text-paragraph-xs text-text-soft-400">
        <Rich text={t("patchlog.intro")} />
      </p>

      <div className="mb-3 flex items-center gap-2.5">
        <span className="text-subheading-2xs text-text-soft-400">
          v{release.version} · {release.date}
        </span>
        <span className="h-px flex-1 bg-stroke-soft-200" />
        <span className="text-paragraph-xs text-text-soft-400">
          {t(release.entries.length === 1 ? "patchlog.changeOne" : "patchlog.changeMany", { n: String(release.entries.length) })}
        </span>
      </div>

      <div className="flex flex-col gap-2.5 pb-6">
        {release.entries.map((e) => (
          <EntryCard key={e.id} entry={e} />
        ))}
      </div>
    </section>
  );
}
