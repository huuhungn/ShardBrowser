import { strict as assert } from "node:assert";
import test from "node:test";
import { EXCEPTIONS, advisories, verdict } from "./npm-audit-gate.mjs";

const PICOMATCH = {
  source: 1247710,
  name: "picomatch",
  dependency: "picomatch",
  title: "picomatch vulnerable to ReDoS through single-branch repeated extglobs",
  url: "https://github.com/advisories/GHSA-fc5q-39xc-vjpf",
  severity: "high",
  range: "<=4.0.7",
};

// Shape of `npm audit --json` (report v2): advisories sit in `via` objects; a
// package that is vulnerable only through a dependency lists that name instead.
function report(...extra) {
  const vulnerabilities = {
    picomatch: { name: "picomatch", severity: "high", via: [PICOMATCH], effects: ["tinyglobby"] },
    tinyglobby: { name: "tinyglobby", severity: "high", via: ["picomatch", "fdir"], effects: ["vite"] },
    vite: { name: "vite", severity: "high", via: ["tinyglobby"], effects: [] },
  };
  for (const v of extra) vulnerabilities[v.name] = { name: v.name, severity: v.severity, via: [v], effects: [] };
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  for (const v of Object.values(vulnerabilities)) counts[v.severity] += 1;
  return { auditReportVersion: 2, vulnerabilities, metadata: { vulnerabilities: counts } };
}

const BEFORE = "2026-11-18";
const LAST_DAY = EXCEPTIONS[0].expires;
const AFTER = "2026-12-03";

test("the picomatch advisory alone passes until its expiry date, inclusive", () => {
  assert.equal(EXCEPTIONS[0].id, "GHSA-fc5q-39xc-vjpf");
  assert.equal(LAST_DAY, "2026-12-02");
  for (const day of [BEFORE, LAST_DAY]) {
    const v = verdict(report(), day);
    assert.equal(v.ok, true, day);
    assert.deepEqual(v.excused.map((a) => a.id), ["GHSA-FC5Q-39XC-VJPF"]);
  }
});

test("any other moderate or worse advisory still fails", () => {
  for (const severity of ["moderate", "high", "critical"]) {
    const other = {
      source: 1,
      name: "left-pad",
      title: "synthetic advisory",
      url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
      severity,
    };
    const v = verdict(report(other), BEFORE);
    assert.equal(v.ok, false, severity);
    assert.deepEqual(v.blocking.map((a) => a.id), ["GHSA-AAAA-BBBB-CCCC"]);
  }
});

test("a low advisory does not fail, as with --audit-level=moderate", () => {
  const low = { source: 2, name: "x", title: "t", url: "https://github.com/advisories/GHSA-dddd-eeee-ffff", severity: "low" };
  assert.equal(verdict(report(low), BEFORE).ok, true);
});

test("an expired exception fails, used or not", () => {
  const used = verdict(report(), AFTER);
  assert.equal(used.ok, false);
  assert.match(used.reason, /expired/);
  const unused = verdict({ auditReportVersion: 2, vulnerabilities: {}, metadata: { vulnerabilities: {} } }, AFTER);
  assert.equal(unused.ok, false);
  assert.match(unused.reason, /GHSA-fc5q-39xc-vjpf \(expired 2026-12-02\)/);
});

test("a clean audit passes and reports the exception as unused", () => {
  const v = verdict({ auditReportVersion: 2, vulnerabilities: {}, metadata: { vulnerabilities: {} } }, BEFORE);
  assert.equal(v.ok, true);
  assert.deepEqual(v.excused, []);
  assert.deepEqual(v.unused.map((e) => e.id), ["GHSA-fc5q-39xc-vjpf"]);
});

test("an npm error or an unparsed vulnerability fails closed", () => {
  assert.equal(verdict({ error: { code: "ENOAUDIT", summary: "no audit" } }, BEFORE).ok, false);
  const opaque = { vulnerabilities: { x: { name: "x", severity: "high", via: ["y"] } }, metadata: { vulnerabilities: { high: 1 } } };
  assert.equal(verdict(opaque, BEFORE).ok, false);
});

test("advisories are read from via objects only, once each", () => {
  assert.deepEqual(advisories(report()).map((a) => `${a.id} ${a.name}`), ["GHSA-FC5Q-39XC-VJPF picomatch"]);
});
