// `secor dashboard [--no-open]` end to end (spec 11.1 / 12.1): prints the URL, serves the current project, records
// ~/.secor/dashboard.json (0600), is reused by a second invocation, and on SIGTERM stops and removes the record.

import { type ChildProcess, spawn, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, realpathSync, statSync, writeFileSync } from "node:fs";
import { request } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildCli } from "../helpers/build-cli.js";

let cli: string;
let home: string;
let project: string;
const children: ChildProcess[] = [];

beforeAll(async () => {
  cli = await buildCli("dashboard-e2e");
  home = mkdtempSync(join(tmpdir(), "secor-dash-e2e-home-"));
  project = mkdtempSync(join(tmpdir(), "secor-dash-e2e-proj-"));
  writeFileSync(join(project, "package.json"), JSON.stringify({ name: "dash-e2e" }));
}, 120_000);
afterAll(() => {
  for (const c of children) if (c.exitCode === null) c.kill("SIGKILL");
});

function env(): NodeJS.ProcessEnv {
  const e: NodeJS.ProcessEnv = { ...process.env, HOME: home, SECOR_HOME: join(home, ".secor"), NO_COLOR: "1" };
  delete e.CLAUDE_PROJECT_DIR;
  return e;
}

function httpGet(url: string, headers: Record<string, string> = {}): Promise<{ status: number; body: string; setCookie?: string[] }> {
  const u = new URL(url);
  return new Promise((resolve, reject) => {
    const req = request({ host: u.hostname, port: u.port, path: `${u.pathname}${u.search}`, headers }, (res) => {
      let body = "";
      res.setEncoding("utf8");
      res.on("data", (c: string) => (body += c));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body, setCookie: res.headers["set-cookie"] }));
    });
    req.on("error", reject);
    req.end();
  });
}

describe("secor dashboard", () => {
  it("--help lists --no-open", () => {
    const r = spawnSync(process.execPath, [cli, "dashboard", "--help"], { cwd: project, env: env(), encoding: "utf8" });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain("--no-open");
  });

  it("starts, serves the project, is reused, and stops on SIGTERM", async () => {
    const child = spawn(process.execPath, [cli, "dashboard", "--no-open"], { cwd: project, env: env(), stdio: ["ignore", "pipe", "pipe"] });
    children.push(child);
    const exited = new Promise<number | null>((r) => child.on("exit", (code) => r(code)));
    const url = await new Promise<string>((resolve, reject) => {
      let out = "";
      const timer = setTimeout(() => reject(new Error(`no URL printed: ${out}`)), 20_000);
      child.stdout?.on("data", (d: Buffer) => {
        out += d.toString();
        const m = /http:\/\/127\.0\.0\.1:\d+\/\?t=[0-9a-f]{64}/.exec(out);
        if (m) {
          clearTimeout(timer);
          resolve(m[0]);
        }
      });
      void exited.then((code) => reject(new Error(`exited early with ${code}: ${out}`)));
    });

    const page = await httpGet(url);
    expect(page.status).toBe(200);
    expect(page.body).toContain("OPEN FINDINGS");
    const cookie = page.setCookie?.[0]?.split(";")[0] ?? "";
    const summary = await httpGet(new URL("/api/summary", url).toString(), { Cookie: cookie });
    expect(summary.status).toBe(200);
    expect(JSON.parse(summary.body)).toMatchObject({ project: "dash-e2e", lastCheck: null, scoringVersion: 1 });

    const infoPath = join(home, ".secor", "dashboard.json");
    expect(statSync(infoPath).mode & 0o777).toBe(0o600);
    const info = JSON.parse(readFileSync(infoPath, "utf8")) as Record<string, unknown>;
    expect(info.pid).toBe(child.pid);
    expect(info.projectRoot).toBe(realpathSync(project));

    const second = spawnSync(process.execPath, [cli, "dashboard", "--no-open"], { cwd: project, env: env(), encoding: "utf8", timeout: 20_000 });
    expect(second.status).toBe(0);
    expect(second.stdout).toContain("already running");
    expect(second.stdout).toContain(url);

    child.kill("SIGTERM");
    expect(await exited).toBe(0);
    expect(existsSync(infoPath)).toBe(false);
  });
});
