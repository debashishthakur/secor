// Start or reuse the dashboard (spec section 12.1). ~/.secor/dashboard.json (mode 0600) names the live server:
// {pid, port, token, startedAt, projectRoot}. A recorded server is reused only when its process is alive, it answers
// with that token, and it serves the same project. A new server is started in this process; when it closes, the
// file is removed if it still names that server. Starting a server also starts the background drift check (9.7).

import { spawn } from "node:child_process";
import { request } from "node:http";
import { realpathSync, unlinkSync } from "node:fs";
import { join, resolve } from "node:path";
import { readJsonFile, writeFileAtomic } from "../engine/util/fsx.js";
import { secorHome } from "../engine/util/paths.js";
import { COOKIE_NAME, type DashboardServer, dashboardUrl, startDashboardServer } from "./server.js";

export interface DashboardInfo {
  pid: number;
  port: number;
  token: string;
  startedAt: string;
  projectRoot: string;
}

export interface OpenDashboardOptions {
  root: string;
  /** Open the browser (default true), or a function that opens the URL (tests). */
  open?: boolean | ((url: string) => void);
  idleMs?: number;
  /** Background drift check when a new server starts: default runs driftCheckAll({onlyStaleHours: 24}); false skips. */
  driftCheck?: false | (() => Promise<void>);
}

export interface OpenDashboardResult {
  url: string;
  reused: boolean;
  /** The server, when it runs in this process. */
  server?: DashboardServer;
}

/** The project root as a canonical path, so a symlinked path and its target count as the same project. */
export function canonicalRoot(p: string): string {
  try {
    return realpathSync.native(resolve(p));
  } catch {
    return resolve(p);
  }
}

export function dashboardInfoPath(): string {
  return join(secorHome(), "dashboard.json");
}

function isInfo(v: unknown): v is DashboardInfo {
  if (!v || typeof v !== "object") return false;
  const o = v as Record<string, unknown>;
  return (
    Number.isInteger(o.pid) &&
    (o.pid as number) > 0 &&
    Number.isInteger(o.port) &&
    (o.port as number) > 0 &&
    (o.port as number) < 65536 &&
    typeof o.token === "string" &&
    /^[0-9a-f]{64}$/.test(o.token) &&
    typeof o.startedAt === "string" &&
    typeof o.projectRoot === "string"
  );
}

export function readDashboardInfo(path = dashboardInfoPath()): DashboardInfo | null {
  try {
    const v = readJsonFile<unknown>(path);
    return isInfo(v) ? v : null;
  } catch {
    return null;
  }
}

function writeDashboardInfo(s: DashboardServer): void {
  const info: DashboardInfo = { pid: process.pid, port: s.port, token: s.token, startedAt: s.startedAt, projectRoot: s.root };
  writeFileAtomic(dashboardInfoPath(), `${JSON.stringify(info, null, 2)}\n`, 0o600);
}

function removeDashboardInfoIfOurs(s: DashboardServer): void {
  const info = readDashboardInfo();
  if (!info || info.pid !== process.pid || info.port !== s.port || info.token !== s.token) return;
  try {
    unlinkSync(dashboardInfoPath());
  } catch {
    // already gone
  }
}

export function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e) {
    return (e as NodeJS.ErrnoException).code === "EPERM";
  }
}

/** True when a dashboard on 127.0.0.1:<port> accepts `token` (GET / with the cookie answers 200). */
export function dashboardAnswers(port: number, token: string, timeoutMs = 1500): Promise<boolean> {
  return new Promise((done) => {
    const req = request(
      { host: "127.0.0.1", port, path: "/", method: "GET", headers: { Host: `127.0.0.1:${port}`, Cookie: `${COOKIE_NAME}=${token}` }, timeout: timeoutMs },
      (res) => {
        res.resume();
        done(res.statusCode === 200);
      },
    );
    req.on("timeout", () => req.destroy());
    req.on("error", () => done(false));
    req.end();
  });
}

/**
 * Open `url` in the default browser (open, xdg-open or start). Failures are ignored: the URL is also printed or
 * returned. The URL is built by SECOR (loopback address, port, hex token), so it needs no shell quoting.
 */
export function openBrowser(url: string): void {
  try {
    const child =
      process.platform === "win32"
        ? spawn("cmd", ["/c", "start", '""', url], { stdio: "ignore", detached: true, windowsHide: true, windowsVerbatimArguments: true })
        : spawn(process.platform === "darwin" ? "open" : "xdg-open", [url], { stdio: "ignore", detached: true });
    child.on("error", () => {});
    child.unref();
  } catch {
    // no browser opener available
  }
}

/** driftCheckAll({onlyStaleHours: 24}) from src/connect/drift.ts (loaded lazily), or null if it cannot be loaded. */
async function loadDriftCheck(): Promise<(() => Promise<void>) | null> {
  try {
    const { driftCheckAll } = await import("../connect/drift.js");
    return () => driftCheckAll({ onlyStaleHours: 24 });
  } catch {
    return null;
  }
}

/** Run the drift check in the background; every error is swallowed (the dashboard works without it). */
export function backgroundDrift(check?: false | (() => Promise<void>)): Promise<void> {
  if (check === false) return Promise.resolve();
  return (async () => {
    try {
      const run = check ?? (await loadDriftCheck());
      if (run) await run();
    } catch {
      // swallowed: drift results show up in servers.json when a check succeeds
    }
  })();
}

/** Servers started by this process, by project root. */
const local = new Map<string, DashboardServer>();

export async function openDashboard(o: OpenDashboardOptions): Promise<OpenDashboardResult> {
  const root = canonicalRoot(o.root);
  let result: OpenDashboardResult;
  const mine = local.get(root);
  if (mine && !mine.isClosed()) {
    writeDashboardInfo(mine);
    result = { url: mine.url, reused: true, server: mine };
  } else {
    const info = readDashboardInfo();
    if (info && canonicalRoot(info.projectRoot) === root && pidAlive(info.pid) && (await dashboardAnswers(info.port, info.token))) {
      result = { url: dashboardUrl(info.port, info.token), reused: true };
    } else {
      const server = await startDashboardServer({ root, ...(o.idleMs !== undefined ? { idleMs: o.idleMs } : {}) });
      try {
        writeDashboardInfo(server);
      } catch (e) {
        await server.close();
        throw e;
      }
      local.set(root, server);
      void server.closed.then(() => {
        if (local.get(root) === server) local.delete(root);
        removeDashboardInfoIfOurs(server);
      });
      void backgroundDrift(o.driftCheck);
      result = { url: server.url, reused: false, server };
    }
  }
  if (o.open !== false) (typeof o.open === "function" ? o.open : openBrowser)(result.url);
  return result;
}

/** Close every dashboard this process started (MCP server shutdown). */
export async function closeLocalDashboards(): Promise<void> {
  await Promise.all([...local.values()].map((s) => s.close()));
}
