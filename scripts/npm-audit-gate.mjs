#!/usr/bin/env node
// Release gate for npm dependencies: `npm audit --audit-level=moderate`, except
// for the owner-approved, time-boxed exceptions listed in EXCEPTIONS.
//
//   node scripts/npm-audit-gate.mjs [--prefix <dir>]   audit one package
//   node scripts/npm-audit-gate.mjs --check-expiry     fail once an exception expired
//
// An exception only excuses its own advisory id, only until its expiry date
// (inclusive, UTC), and does nothing once no audited package reports it. Every
// other moderate, high or critical advisory still fails the gate, and an
// expired exception fails it too, whether or not it is still used.

import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const EXCEPTIONS = [];

const BLOCKING = new Set(["moderate", "high", "critical"]);
const GHSA = /GHSA(?:-[0-9a-z]{4}){3}/i;

/** Moderate-or-worse advisories in an `npm audit --json` (v2) report. */
export function advisories(report) {
  const found = new Map();
  for (const vuln of Object.values(report.vulnerabilities ?? {})) {
    for (const via of vuln.via ?? []) {
      // A string names another vulnerable package; its own entry carries the advisory.
      if (typeof via !== "object" || !BLOCKING.has(via.severity)) continue;
      const id = (String(via.url ?? "").match(GHSA)?.[0] ?? `npm-${via.source}`).toUpperCase();
      found.set(`${id} ${via.name}`, { id, name: via.name, severity: via.severity, title: via.title, url: via.url });
    }
  }
  return [...found.values()];
}

/** Decide the gate for one report on `today` (YYYY-MM-DD, UTC). */
export function verdict(report, today, exceptions = EXCEPTIONS) {
  if (report.error) {
    return { ok: false, reason: `npm audit failed: ${report.error.summary ?? report.error.code ?? "unknown error"}` };
  }
  const expired = exceptions.filter((e) => today > e.expires);
  const live = exceptions.filter((e) => today <= e.expires);
  const found = advisories(report);
  const excused = found.filter((a) => live.some((e) => e.id.toUpperCase() === a.id));
  const blocking = found.filter((a) => !excused.includes(a));
  const unused = exceptions.filter((e) => !found.some((a) => a.id === e.id.toUpperCase()));

  // Fail closed if the summary counts blocking vulnerabilities this parser did not see.
  const counts = report.metadata?.vulnerabilities ?? {};
  const counted = [...BLOCKING].reduce((n, s) => n + (counts[s] ?? 0), 0);
  if (counted > 0 && found.length === 0) {
    return { ok: false, reason: `npm audit counts ${counted} moderate+ vulnerabilities but lists no advisory` };
  }
  if (expired.length) {
    return {
      ok: false,
      reason: `expired audit exception(s): ${expired.map((e) => `${e.id} (expired ${e.expires})`).join(", ")}; remove or re-approve them`,
      blocking,
    };
  }
  if (blocking.length) {
    return { ok: false, reason: `${blocking.length} advisory(ies) without an approved exception`, blocking, excused };
  }
  return { ok: true, excused, unused };
}

function runAudit(prefix) {
  const opts = { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 };
  // Windows runs npm through its .cmd shim, which needs a shell.
  const res =
    process.platform === "win32"
      ? spawnSync(`npm audit --json --prefix "${prefix}"`, { ...opts, shell: true })
      : spawnSync("npm", ["audit", "--json", "--prefix", prefix], opts);
  try {
    return JSON.parse(res.stdout);
  } catch {
    return { error: { summary: `unreadable npm audit output (exit ${res.status}): ${res.stderr.slice(0, 500)}` } };
  }
}

function main(argv) {
  const today = new Date().toISOString().slice(0, 10);
  if (argv.includes("--check-expiry")) {
    const expired = EXCEPTIONS.filter((e) => today > e.expires);
    for (const e of expired) console.error(`npm audit exception ${e.id} expired on ${e.expires}: remove or re-approve it.`);
    return expired.length ? 1 : 0;
  }
  const at = argv.indexOf("--prefix");
  const prefix = at >= 0 ? argv[at + 1] : ".";
  const v = verdict(runAudit(prefix), today);
  for (const a of v.excused ?? []) {
    console.log(`[${prefix}] excused until ${EXCEPTIONS.find((e) => e.id.toUpperCase() === a.id).expires}: ${a.id} ${a.name} (${a.severity}) ${a.url}`);
  }
  for (const e of v.unused ?? []) console.log(`[${prefix}] exception ${e.id} is unused here`);
  for (const a of v.blocking ?? []) console.error(`[${prefix}] ${a.severity}: ${a.id} ${a.name} - ${a.title} ${a.url ?? ""}`);
  if (!v.ok) {
    console.error(`[${prefix}] npm audit gate failed: ${v.reason}`);
    return 1;
  }
  console.log(`[${prefix}] npm audit gate passed`);
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  process.exitCode = main(process.argv.slice(2));
}
