import { useState } from "react";
import { Button, Checkbox, Modal, Select, Textarea } from "@proxyshard/shardx-ui-kit";
import Badge from "../../../shared/ui/Badge";
import { RefreshIcon } from "../../../shared/icons";
import { CountryFlag } from "../../../shared/ui/CountryFlag";
import { toast } from "../../../shared/model/toast";
import type { ProxyEntry, BulkRowState } from "../../../entities/proxy";
import { proxyBulkParse, proxyBulkSave, proxyFullTest } from "../../../entities/proxy";
import { useT } from "../../../shared/i18n";

export function ProxyBulkImporter({ onClose }: { onClose: () => void }) {
  const t = useT();
  const [text, setText] = useState("");
  const [kind, setKind] = useState<ProxyEntry["kind"]>("socks5");
  const [rows, setRows] = useState<BulkRowState[]>([]);
  const [busy, setBusy] = useState(false);

  const parse = async () => {
    if (!text.trim()) { toast.err(t("proxy.nothingToParse")); return; }
    try {
      const parsed = await proxyBulkParse(text, kind);
      if (parsed.length === 0) { toast.err(t("proxy.noValidProxyLinesFound")); return; }
      setRows(parsed.map((e) => ({ entry: e, selected: true, status: "idle" })));
    } catch (e) { toast.err(String(e)); }
  };

  const testOne = async (idx: number) => {
    setRows((rs) => rs.map((r, i) => i === idx ? { ...r, status: "testing" } : r));
    const entry = rows[idx]?.entry;
    if (!entry) return;
    try {
      const snap = await proxyFullTest(entry);
      setRows((rs) => rs.map((r, i) =>
        i === idx
          ? {
            ...r,
            status: snap.tcp_ms != null ? "ok" : "fail",
            tcp_ms: snap.tcp_ms,
            udp_ms: snap.udp_ms,
            country: snap.country_code || r.country,
            entry: { ...r.entry, country: snap.country_code || r.entry.country },
          }
          : r,
      ));
    } catch (e) {
      setRows((rs) => rs.map((r, i) => i === idx ? { ...r, status: "fail", error: String(e) } : r));
    }
  };

  const testAll = async () => {
    setBusy(true);
    const CONCURRENCY = 5;
    const queue = rows.map((_, i) => i);
    let cursor = 0;
    await Promise.all(
      Array.from({ length: Math.min(CONCURRENCY, queue.length) }, async () => {
        while (cursor < queue.length) {
          const i = queue[cursor++];
          if (i == null) break;
          await testOne(i);
        }
      }),
    );
    setBusy(false);
  };

  const saveSelected = async () => {
    const entries = rows.filter((r) => r.selected).map((r) => r.entry);
    if (entries.length === 0) { toast.err(t("proxy.nothingSelected")); return; }
    try {
      const n = await proxyBulkSave(entries);
      toast.ok(`Imported ${n} prox${n === 1 ? "y" : "ies"}`);
      onClose();
    } catch (e) { toast.err(String(e)); }
  };

  const allSel = rows.length > 0 && rows.every((r) => r.selected);
  const selCount = rows.filter((r) => r.selected).length;

  return (
    <Modal
      open
      onClose={onClose}
      title={t("proxy.bulkImportProxies")}
      maxWidthClassName="max-w-[750px]"
      footer={
        <div className="flex items-center justify-end gap-2">
          <Button variant="neutral" mode="stroke" size="small" onClick={onClose}>{t("proxy.cancel")}</Button>
          {rows.length === 0 ? (
            <Button variant="primary" mode="filled" size="small" onClick={parse}>Parse →</Button>
          ) : (
            <Button variant="primary" mode="filled" size="small" onClick={saveSelected}>
              Import {selCount}
            </Button>
          )}
        </div>
      }
    >
      <div className="flex min-h-0 flex-col gap-3">
        {rows.length === 0 ? (
          <>
            <Select
              label={t("proxy.defaultTypeUsedWhenALineHasNoScheme")}
              size="small"
              value={kind}
              onChange={(v) => setKind(v as ProxyEntry["kind"])}
              options={[
                { value: "socks5", label: t("proxy.socks5") },
                { value: "http", label: t("proxy.http") },
                { value: "https", label: t("proxy.https") },
              ]}
            />
            <Textarea
              label={t("proxy.pasteOneProxyPerLine")}
              rows={12}
              className="mono"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={`socks5://user:pass@host:1080
user:pass@host:1080
host:1080:user:pass     # country=PL
host:8080               # no auth
# lines starting with # are ignored`}
            />
            <p className="m-0 text-paragraph-xs text-text-soft-400">
              Duplicates (same host:port:user) are skipped on save.
            </p>
          </>
        ) : (
          <>
            <div className="flex items-center gap-3 pb-1.5">
              <Checkbox
                checked={allSel}
                label={`${selCount} of ${rows.length} selected`}
                onChange={(e) =>
                  setRows((rs) => rs.map((r) => ({ ...r, selected: e.target.checked })))
                }
              />
              <div className="ml-auto flex gap-1.5">
                <Button variant="neutral" mode="stroke" size="2xsmall" onClick={() => setRows([])}>← Back</Button>
                <Button
                  variant="neutral"
                  mode="stroke"
                  size="2xsmall"
                  leftIcon={<RefreshIcon className="size-3.5" />}
                  onClick={testAll}
                  disabled={busy}
                  isLoading={busy}
                >
                  {busy ? "Testing…" : t("proxy.testAll")}
                </Button>
                <Button
                  variant="neutral"
                  mode="stroke"
                  size="2xsmall"
                  onClick={() =>
                    setRows((rs) =>
                      rs.map((r) => ({ ...r, selected: r.status === "ok" }))
                    )
                  }
                  title={t("proxy.tickOnlyProxiesWhoseLatestTestSuccee")}
                >
                  ✓ Keep working only
                </Button>
              </div>
            </div>
            <div className="max-h-[380px] overflow-y-auto py-2  overflow-x-hidden rounded-lg bg-bg-white-0 ring-1 ring-inset ring-stroke-soft-200">
              {rows.map((r, i) => (
                <div
                  key={`${r.entry.host}:${r.entry.port}:${i}`}
                  className={`import-cols border-b border-stroke-soft-200 px-2.5 py-1.5 text-paragraph-xs last:border-b-0${r.status === "ok" ? " bg-success-alpha-16/20" : r.status === "fail" ? " bg-error-alpha-16/20 opacity-85" : ""}`}
                >
                  <Checkbox
                    checked={r.selected}
                    onChange={() =>
                      setRows((rs) => rs.map((x, j) => j === i ? { ...x, selected: !x.selected } : x))
                    }
                  />
                  <Badge
                    size="small"
                    variant="filled"
                    color={r.entry.kind === "socks5" ? "primary" : r.entry.kind === "http" ? "gray" : "success"}
                  >
                    {r.entry.kind.toUpperCase()}
                  </Badge>
                  <span className="mono min-w-0 overflow-hidden text-ellipsis whitespace-nowrap text-paragraph-xs text-text-strong-950" title={`${r.entry.host}:${r.entry.port}${r.entry.username ? " @" + r.entry.username : ""}`}>
                    {r.entry.host}:{r.entry.port}
                    {r.entry.username && <span className="text-text-soft-400"> · {r.entry.username}</span>}
                  </span>
                  <div className="inline-flex items-center justify-end gap-1.5">
                    {r.status === "idle" && <span className="text-text-soft-400">not tested</span>}
                    {r.status === "testing" && <span className="text-text-soft-400">testing…</span>}
                    {r.status === "ok" && (
                      <>
                        <Badge color="success" variant="filled" size="small" title={`TCP ${r.tcp_ms} ms`}>{t("proxy.active")}</Badge>
                        {r.entry.kind === "socks5" && r.udp_ms != null && (
                          <Badge color="primary" variant="filled" size="small" title={t("proxy.udpRelayWorks", { ms: r.udp_ms })}>UDP</Badge>
                        )}
                        {r.country && (
                          <>
                            <CountryFlag cc={r.country} />
                            <span className="text-text-sub-600">{r.country}</span>
                          </>
                        )}
                      </>
                    )}
                    {r.status === "fail" && (
                      <Badge color="error" variant="filled" size="small" title={r.error}>{t("proxy.failed")}</Badge>
                    )}
                  </div>
                  <Button
                    variant="neutral"
                    mode="stroke"
                    size="2xsmall"
                    onlyIcon
                    onClick={() => testOne(i)}
                    disabled={r.status === "testing"}
                    title={t("proxy.testThisRow")}
                    leftIcon={<RefreshIcon className="size-3.5" />}
                  />
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </Modal>
  );
}
