// Shared test helpers for Probe: temp HOME / SECOR_HOME, fake DNS resolver, scripted terminal I/O,
// a recording local HTTP server, and a latest-run writer.

import * as http from "node:http";
import type { AddressInfo } from "node:net";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeRun } from "../../src/engine/report.js";
import { computeScore } from "../../src/engine/score.js";
import type { EntryPoint, Finding, RunResult, ServiceUnit } from "../../src/types.js";
import type { ConsentIO } from "../../src/probe/consent.js";
import type { Resolver } from "../../src/probe/scope-guard.js";

export interface TempHome {
  home: string;
  secorHome: string;
  restore(): void;
}

/** Point HOME and SECOR_HOME at fresh temp dirs so nothing touches the real ~/.secor. */
export function tempHome(): TempHome {
  const home = mkdtempSync(join(tmpdir(), "secor-probe-home-"));
  const secorHome = mkdtempSync(join(tmpdir(), "secor-probe-secor-"));
  const prevHome = process.env.HOME;
  const prevSecor = process.env.SECOR_HOME;
  process.env.HOME = home;
  process.env.SECOR_HOME = secorHome;
  return {
    home,
    secorHome,
    restore() {
      if (prevHome === undefined) delete process.env.HOME;
      else process.env.HOME = prevHome;
      if (prevSecor === undefined) delete process.env.SECOR_HOME;
      else process.env.SECOR_HOME = prevSecor;
      rmSync(home, { recursive: true, force: true });
      rmSync(secorHome, { recursive: true, force: true });
    },
  };
}

type LookupResult = { address: string; family: number }[];

/** A resolver whose lookup/txt answers are fixed arrays or functions (for sequenced rebinding tests). */
export function fakeResolver(opts: {
  lookup?: LookupResult | ((host: string) => LookupResult);
  txt?: string[][] | ((host: string) => string[][]);
}): Resolver {
  return {
    lookup(host) {
      const r = typeof opts.lookup === "function" ? opts.lookup(host) : (opts.lookup ?? []);
      return Promise.resolve(r);
    },
    resolveTxt(host) {
      const r = typeof opts.txt === "function" ? opts.txt(host) : (opts.txt ?? []);
      return Promise.resolve(r);
    },
  };
}

export const v4 = (address: string): LookupResult => [{ address, family: 4 }];

export interface ScriptedIO extends ConsentIO {
  output: string[];
}

/** A ConsentIO that returns scripted answers in order and captures printed output. */
export function scriptedIO(answers: string[], isTTY = true): ScriptedIO {
  const output: string[] = [];
  let i = 0;
  return {
    isTTY,
    output,
    print(msg) {
      output.push(msg);
    },
    question: isTTY
      ? (prompt) => {
          output.push(prompt);
          return Promise.resolve(answers[i++] ?? "");
        }
      : undefined,
  };
}

/** A non-TTY ConsentIO (no question function). */
export function nonTtyIO(): ScriptedIO {
  const io = scriptedIO([], false);
  return io;
}

/** A TTY ConsentIO that just confirms (for a local target with --i-own-this-target). */
export function autoConfirmIO(): ScriptedIO {
  return scriptedIO(["y", "y", "y"]);
}

export interface RecordedRequest {
  method: string;
  url: string;
  headers: http.IncomingHttpHeaders;
  body: string;
}

export interface TestServer {
  origin: string;
  port: number;
  requests: RecordedRequest[];
  starts: number[];
  maxConcurrent: number;
  close(): Promise<void>;
}

export type Handler = (req: http.IncomingMessage, res: http.ServerResponse, recorded: RecordedRequest) => void;

/** A recording HTTP server on 127.0.0.1 (random port). Tracks arrival times and peak concurrency. */
export async function startServer(handler: Handler): Promise<TestServer> {
  const requests: RecordedRequest[] = [];
  const starts: number[] = [];
  let active = 0;
  let maxConcurrent = 0;
  const server = http.createServer((req, res) => {
    active++;
    maxConcurrent = Math.max(maxConcurrent, active);
    starts.push(Date.now());
    res.on("close", () => active--);
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      const recorded: RecordedRequest = { method: req.method ?? "", url: req.url ?? "", headers: req.headers, body };
      requests.push(recorded);
      handler(req, res, recorded);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    origin: `http://127.0.0.1:${port}`,
    port,
    requests,
    starts,
    get maxConcurrent() {
      return maxConcurrent;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

export function ep(p: Partial<EntryPoint> & { path: string }): EntryPoint {
  return {
    id: p.id ?? `ep_${p.path.replace(/[^A-Za-z0-9]+/g, "_")}`,
    kind: p.kind ?? "http_route",
    service: p.service ?? "api",
    framework: p.framework ?? "express",
    method: p.method ?? "GET",
    path: p.path,
    ...(p.name ? { name: p.name } : {}),
    file: p.file ?? "src/app.ts",
    line: p.line ?? 1,
    auth: p.auth ?? { guarded: false, via: null },
    declaredPublic: p.declaredPublic ?? false,
    callsPaidApi: p.callsPaidApi ?? false,
    writesDb: p.writesDb ?? false,
  };
}

export function staticFinding(p: {
  id: string;
  ruleId: string;
  severity?: Finding["severity"];
  service?: Finding["service"];
  file?: string;
  line?: number;
  advisory?: boolean;
  entryPointId?: string;
  evidence?: string;
}): Finding {
  return {
    id: p.id,
    ruleId: p.ruleId,
    title: p.ruleId,
    severity: p.severity ?? "high",
    advisory: p.advisory ?? false,
    maturity: "experimental",
    service: p.service ?? "api",
    location: { file: p.file ?? "src/app.ts", line: p.line ?? 1 },
    ...(p.entryPointId ? { entryPointId: p.entryPointId } : {}),
    evidence: p.evidence ?? "static evidence",
    why: "static why",
    fix: { summary: "fix it" },
    status: "open",
  };
}

/** Write a minimal latest.json so runProbe has an inventory + findings to work with. */
export function writeLatest(root: string, inventory: EntryPoint[], findings: Finding[], units: ServiceUnit[] = [{ kind: "api", framework: "express", root: "" }]): RunResult {
  const result: RunResult = {
    runId: "20260101T000000Z",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    secorVersion: "1.0.0",
    rulesVersion: "1.0.0",
    project: { name: "probe-fixture", root },
    units,
    inventory,
    findings,
    coverage: { applicable: 5, ran: 5, percent: 100, notChecked: [] },
    score: computeScore(findings, units, 100, null),
  };
  return writeRun(root, result);
}
