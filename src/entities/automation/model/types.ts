/** One recorded step. `params` is block-kind specific, so it stays loose. */
export type Block = {
  id: string;
  /** One of the kinds this build can run; see `runner::supported_kinds`. */
  kind: string;
  label: string;
  params: Record<string, unknown>;
  enabled: boolean;
  x: number;
  y: number;
  /** Where to go after the step succeeds. */
  on_done: Branch;
  /** Param names whose values must never be shown or exported. */
  secrets: string[];
  /** Where to go after it fails. Defaults to stopping the run. */
  on_fail: Branch;
};

/**
 * Where a run goes after a step.
 *
 * Serde writes the unit variants lowercase and the data-carrying ones as
 * `{ goto: "block-id" }` / `{ retry: 2 }`, so the union mirrors that shape
 * exactly -- a mismatch here is a save the launcher silently cannot read.
 */
export type Branch =
  | "next"
  | "stop"
  | "endpass"
  | { goto: string }
  | { retry: number };

export type RunSettings = {
  threads: number;
  /** Passes over the block list. 0 means "until `hours` is up". */
  loops: number;
  hours: number;
  profiles: string[];
  /** Block id the run starts at; empty means the first block. */
  start: string;
};

export type Project = {
  id: string;
  name: string;
  notes: string;
  blocks: Block[];
  run: RunSettings;
  created_at: number;
  updated_at: number;
};

export type StepOutcome = "ok" | "failed" | "skipped" | "stopped";

export type StepReport = {
  block_id: string;
  kind: string;
  label: string;
  outcome: StepOutcome;
  attempt: number;
  ms: number;
  error: string | null;
};

export type RunReport = {
  project_id: string;
  profile_id: string;
  ok: boolean;
  passes: number;
  steps: StepReport[];
  ms: number;
  variables: Record<string, string>;
  stopped_because: string | null;
};

/** Kinds this build can run. Kept in step with `runner::supported_kinds`. */
export const BLOCK_KINDS = [
  "navigate",
  "wait",
  "waitForSelector",
  "click",
  "type",
  "setVariable",
  "readText",
  "assert",
  "evaluate",
] as const;

export type BlockKind = (typeof BLOCK_KINDS)[number];
