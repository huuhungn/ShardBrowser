import { strict as assert } from "node:assert";
import test from "node:test";
import { EXCEPTIONS, advisories, verdict } from "./npm-audit-gate.mjs";

// The shipped list is empty when no exception is approved; the mechanism is
// exercised with a synthetic exception passed in explicitly.
const EXAMPLE = {
  source: 1000001,
  name: "example-lib",
  dependency: "example-lib",
  title: "example-lib synthetic advisory",
  url: "https://github.com/advisories/GHSA-1111-2222-3333",
  severity: "high",
  range: "<=1.0.0",
};
const EXCEPTION = { id: "GHSA-1111-2222-3333", url: EXAMPLE.url, expires: "2026-12-02" };
const EXCEPTION_LIST = [EXCEPTION];

// Shape of `npm audit --json` (report v2): advisories sit in `via` objects; a
// package that is vulnerable only through a dependency lists that name instead.
function report(...extra) {
  const vulnerabilities = {
    "example-lib": { name: "example-lib", severity: "high", via: [EXAMPLE], effects: ["example-tool"] },
    "example-tool": { name: "example-tool", severity: "high", via: ["example-lib", "other-lib"], effects: ["example-app"] },
    "example-app": { name: "example-app", severity: "high", via: ["example-tool"], effects: [] },
  };
  for (const v of extra) vulnerabilities[v.name] = { name: v.name, severity: v.severity, via: [v], effects: [] };
  const counts = { info: 0, low: 0, moderate: 0, high: 0, critical: 0 };
  for (const v of Object.values(vulnerabilities)) counts[v.severity] += 1;
  return { auditReportVersion: 2, vulnerabilities, metadata: { vulnerabilities: counts } };
}

const CLEAN = { auditReportVersion: 2, vulnerabilities: {}, metadata: { vulnerabilities: {} } };
const BEFORE = "2026-11-18";
const LAST_DAY = EXCEPTION.expires;
const AFTER = "2026-12-03";

test("no exception is approved by default, so any advisory fails", () => {
  assert.deepEqual(EXCEPTIONS, []);
  assert.equal(verdict(CLEAN, BEFORE).ok, true);
  const v = verdict(report(), BEFORE);
  assert.equal(v.ok, false);
  assert.deepEqual(v.blocking.map((a) => a.id), ["GHSA-1111-2222-3333"]);
});

test("an approved advisory alone passes until its expiry date, inclusive", () => {
  for (const day of [BEFORE, LAST_DAY]) {
    const v = verdict(report(), day, EXCEPTION_LIST);
    assert.equal(v.ok, true, day);
    assert.deepEqual(v.excused.map((a) => a.id), ["GHSA-1111-2222-3333"]);
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
    const v = verdict(report(other), BEFORE, EXCEPTION_LIST);
    assert.equal(v.ok, false, severity);
    assert.deepEqual(v.blocking.map((a) => a.id), ["GHSA-AAAA-BBBB-CCCC"]);
  }
});

test("a low advisory does not fail, as with --audit-level=moderate", () => {
  const low = { source: 2, name: "x", title: "t", url: "https://github.com/advisories/GHSA-dddd-eeee-ffff", severity: "low" };
  assert.equal(verdict(report(low), BEFORE, EXCEPTION_LIST).ok, true);
});

test("an expired exception fails, used or not", () => {
  const used = verdict(report(), AFTER, EXCEPTION_LIST);
  assert.equal(used.ok, false);
  assert.match(used.reason, /expired/);
  const unused = verdict(CLEAN, AFTER, EXCEPTION_LIST);
  assert.equal(unused.ok, false);
  assert.match(unused.reason, /GHSA-1111-2222-3333 \(expired 2026-12-02\)/);
});

test("a clean audit passes and reports the exception as unused", () => {
  const v = verdict(CLEAN, BEFORE, EXCEPTION_LIST);
  assert.equal(v.ok, true);
  assert.deepEqual(v.excused, []);
  assert.deepEqual(v.unused.map((e) => e.id), ["GHSA-1111-2222-3333"]);
});

test("an npm error or an unparsed vulnerability fails closed", () => {
  assert.equal(verdict({ error: { code: "ENOAUDIT", summary: "no audit" } }, BEFORE).ok, false);
  const opaque = { vulnerabilities: { x: { name: "x", severity: "high", via: ["y"] } }, metadata: { vulnerabilities: { high: 1 } } };
  assert.equal(verdict(opaque, BEFORE).ok, false);
});

test("advisories are read from via objects only, once each", () => {
  assert.deepEqual(advisories(report()).map((a) => `${a.id} ${a.name}`), ["GHSA-1111-2222-3333 example-lib"]);
});
