// In-process Ship jobs for the MCP server (spec sections 8.1 and 11.2). A job's ID is its run ID, reserved with
// newRunId() when the job is accepted. Jobs run one at a time, in the order they were started; a queued job reports
// "running". Results are not kept in memory: a finished job is read back from .secor/runs/<runId>.json.

import { redact } from "../engine/redact.js";
import { newRunId, writeRun } from "../engine/report.js";
import { runShip, type ShipOptions, type ShipOutcome } from "../ship/run.js";
import type { RunResult } from "../types.js";

export type JobStatus = "running" | "done" | "failed";

export interface Job {
  id: string;
  root: string;
  status: JobStatus;
  /** Redacted error message, set when status is "failed". */
  error?: string;
}

export type ShipRunner = (opts: ShipOptions) => Promise<ShipOutcome>;

/** Options a job passes to runShip, beyond root and runId (which the store sets). */
export type JobRunOptions = Omit<ShipOptions, "root" | "runId">;

/**
 * What a job runs. With `finalize`, runShip does not write the run; finalize adjusts the result, which is then
 * written (and redacted) by writeRun.
 */
export interface JobPlan {
  opts?: JobRunOptions;
  finalize?: (result: RunResult) => RunResult;
}

export class JobStore {
  private readonly jobs = new Map<string, Job>();
  private tail: Promise<void> = Promise.resolve();

  constructor(
    private readonly runner: ShipRunner = runShip,
    private readonly defaults: JobRunOptions = {},
  ) {}

  /**
   * Accept a job: reserve its run ID now, run it after the jobs already queued. A plan given as a function is
   * evaluated when the job starts, so it can read the results of the jobs queued before it.
   */
  start(root: string, plan: JobPlan | (() => JobPlan) = {}): Job {
    const id = newRunId(root, new Date());
    const job: Job = { id, root, status: "running" };
    this.jobs.set(id, job);
    const run = async (): Promise<void> => {
      try {
        const { opts = {}, finalize } = typeof plan === "function" ? plan() : plan;
        const { result } = await this.runner({ ...this.defaults, ...opts, root, runId: id, ...(finalize ? { write: false } : {}) });
        if (finalize) writeRun(root, finalize(result));
        job.status = "done";
      } catch (e) {
        job.error = redact(e instanceof Error ? e.message : String(e));
        job.status = "failed";
      }
    };
    this.tail = this.tail.then(run, run);
    return job;
  }

  get(id: string): Job | undefined {
    return this.jobs.get(id);
  }

  /** The most recently started job for `root` that is still running, if any. */
  runningFor(root: string): Job | undefined {
    let found: Job | undefined;
    for (const j of this.jobs.values()) if (j.root === root && j.status === "running") found = j;
    return found;
  }

  /** Resolves when every job accepted so far has finished. */
  async idle(): Promise<void> {
    let seen: Promise<void> | undefined;
    while (seen !== this.tail) {
      seen = this.tail;
      await seen;
    }
  }
}
