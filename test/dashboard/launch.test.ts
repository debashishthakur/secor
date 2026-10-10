// Start-or-reuse logic (spec 12.1): ~/.secor/dashboard.json (mode 0600), reuse only a live, answering dashboard of
// the same project, cleanup on close, browser opener, background drift check with errors swallowed.

import { spawnSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { backgroundDrift, closeLocalDashboards, dashboardAnswers, dashboardInfoPath, openDashboard, pidAlive, readDashboardInfo } from "../../src/dashboard/launch.js";
import { startDashboardServer } from "../../src/dashboard/server.js";
import { type TempHome, tempProject, useTempHome } from "../mcp/synthetic.js";

let env: TempHome;
beforeAll(() => {
  env = useTempHome();
});
afterEach(async () => {
  await closeLocalDashboards();
});
afterAll(() => env.restore());

const noDrift = { driftCheck: false as const };

function writeInfo(info: Record<string, unknown>): void {
  writeFileSync(dashboardInfoPath(), JSON.stringify(info), { mode: 0o600 });
}

describe("openDashboard", () => {
  it("starts a server on 127.0.0.1 and records it in ~/.secor/dashboard.json with mode 0600", async () => {
    const root = tempProject();
    const opened: string[] = [];
    const r = await openDashboard({ root, open: (u) => opened.push(u), ...noDrift });
    expect(r.reused).toBe(false);
    expect(r.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/\?t=[0-9a-f]{64}$/);
    expect(opened).toEqual([r.url]);
    const path = dashboardInfoPath();
    expect(statSync(path).mode & 0o777).toBe(0o600);
    const info = JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
    expect(Object.keys(info).sort()).toEqual(["pid", "port", "projectRoot", "startedAt", "token"]);
    expect(info).toMatchObject({ pid: process.pid, port: r.server?.port, token: r.server?.token, projectRoot: r.server?.root });
    expect(new Date(String(info.startedAt)).toISOString()).toBe(info.startedAt);
    expect(await dashboardAnswers(r.server!.port, r.server!.token)).toBe(true);
  });

  it("reuses the running dashboard of the same project (and opens it again)", async () => {
    const root = tempProject();
    const opened: string[] = [];
    const drift = vi.fn(async () => {});
    const a = await openDashboard({ root, open: (u) => opened.push(u), driftCheck: drift });
    const b = await openDashboard({ root, open: (u) => opened.push(u), driftCheck: drift });
    expect(b.reused).toBe(true);
    expect(b.url).toBe(a.url);
    expect(opened).toEqual([a.url, a.url]);
    expect(drift).toHaveBeenCalledTimes(1);
  });

  it("treats a symlinked path and its target as the same project", async () => {
    const root = tempProject();
    const link = `${root}-link`;
    symlinkSync(root, link);
    const a = await openDashboard({ root: link, open: false, ...noDrift });
    const b = await openDashboard({ root: realpathSync(root), open: false, ...noDrift });
    expect(b.reused).toBe(true);
    expect(b.url).toBe(a.url);
    expect(readDashboardInfo()?.projectRoot).toBe(realpathSync(root));
  });

  it("open: false does not open a browser", async () => {
    const r = await openDashboard({ root: tempProject(), open: false, ...noDrift });
    expect(r.url).toContain("127.0.0.1");
  });

  it("reuses a dashboard recorded by another process when its pid is alive, it answers, and it serves the same project", async () => {
    const root = tempProject();
    const other = await startDashboardServer({ root, summary: () => ({}) as never });
    try {
      writeInfo({ pid: process.pid, port: other.port, token: other.token, startedAt: other.startedAt, projectRoot: root });
      const r = await openDashboard({ root, open: false, ...noDrift });
      expect(r).toEqual({ url: other.url, reused: true });
    } finally {
      await other.close();
    }
  });

  it("does not reuse a dashboard of another project", async () => {
    const rootA = tempProject();
    const rootB = tempProject();
    const other = await startDashboardServer({ root: rootA });
    try {
      writeInfo({ pid: process.pid, port: other.port, token: other.token, startedAt: other.startedAt, projectRoot: rootA });
      const r = await openDashboard({ root: rootB, open: false, ...noDrift });
      expect(r.reused).toBe(false);
      expect(r.url).not.toBe(other.url);
      expect(readDashboardInfo()?.projectRoot).toBe(r.server?.root);
    } finally {
      await other.close();
    }
  });

  it("does not reuse a record whose process is gone", async () => {
    const root = tempProject();
    const dead = spawnSync(process.execPath, ["-e", ""]).pid;
    expect(pidAlive(dead)).toBe(false);
    writeInfo({ pid: dead, port: 1, token: "a".repeat(64), startedAt: new Date().toISOString(), projectRoot: root });
    const r = await openDashboard({ root, open: false, ...noDrift });
    expect(r.reused).toBe(false);
    expect(readDashboardInfo()?.pid).toBe(process.pid);
  });

  it("does not reuse a live process that does not answer, or answers with another token", async () => {
    const root = tempProject();
    const closedOne = await startDashboardServer({ root });
    await closedOne.close();
    writeInfo({ pid: process.pid, port: closedOne.port, token: closedOne.token, startedAt: closedOne.startedAt, projectRoot: root });
    const r1 = await openDashboard({ root, open: false, ...noDrift });
    expect(r1.reused).toBe(false);
    await closeLocalDashboards();

    const live = await startDashboardServer({ root });
    try {
      writeInfo({ pid: process.pid, port: live.port, token: "b".repeat(64), startedAt: live.startedAt, projectRoot: root });
      const r2 = await openDashboard({ root, open: false, ...noDrift });
      expect(r2.reused).toBe(false);
      expect(r2.url).not.toContain("b".repeat(64));
    } finally {
      await live.close();
    }
  });

  it("ignores a malformed dashboard.json", async () => {
    writeFileSync(dashboardInfoPath(), "{ nope");
    expect(readDashboardInfo()).toBeNull();
    writeInfo({ pid: "1", port: 80, token: "x", startedAt: "", projectRoot: "/" });
    expect(readDashboardInfo()).toBeNull();
    const r = await openDashboard({ root: tempProject(), open: false, ...noDrift });
    expect(r.reused).toBe(false);
  });

  it("removes dashboard.json when the server closes, but only if the file still names it", async () => {
    const a = await openDashboard({ root: tempProject(), open: false, idleMs: 150, ...noDrift });
    await a.server!.closed;
    await new Promise((r) => setTimeout(r, 20));
    expect(existsSync(dashboardInfoPath())).toBe(false);

    const b = await openDashboard({ root: tempProject(), open: false, ...noDrift });
    const c = await openDashboard({ root: tempProject(), open: false, ...noDrift });
    await b.server!.close();
    await new Promise((r) => setTimeout(r, 20));
    expect(readDashboardInfo()?.port).toBe(c.server?.port);
  });
});

describe("background drift check (spec 9.7)", () => {
  it("runs once when a new dashboard starts", async () => {
    const drift = vi.fn(async () => {});
    await openDashboard({ root: tempProject(), open: false, driftCheck: drift });
    expect(drift).toHaveBeenCalledTimes(1);
  });

  it("swallows errors (sync throw or rejection)", async () => {
    await expect(backgroundDrift(() => Promise.reject(new Error("docker exploded")))).resolves.toBeUndefined();
    await expect(
      backgroundDrift(() => {
        throw new Error("sync");
      }),
    ).resolves.toBeUndefined();
    const r = await openDashboard({ root: tempProject(), open: false, driftCheck: () => Promise.reject(new Error("x")) });
    expect(r.reused).toBe(false);
  });

  it("the default check loads Connect's driftCheckAll when present and never throws", async () => {
    await expect(backgroundDrift(undefined)).resolves.toBeUndefined();
  });
});
