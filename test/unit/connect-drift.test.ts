// Drift (spec 9.7) and `secor connect approve`, with the demo server whose tools change via DEMO_VARIANT.

import { join } from "node:path";
import { readFileSync, writeFileSync } from "node:fs";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { requireTerminal } from "../../src/cli/connect.js";
import { connectAdd, connectApprove } from "../../src/connect/add.js";
import { diffToolHashes, driftCheckAll, runDrift } from "../../src/connect/drift.js";
import { resetDockerCache } from "../../src/connect/sandbox.js";
import { loadServers } from "../../src/connect/servers.js";
import { scripted, SERVERS_DIR, type TempEnv, tempEnv } from "../connect/helpers.js";

let env: TempEnv;
let clock = new Date("2026-10-10T12:00:00.000Z");
const now = () => clock;

function config(variant: string, extra: Record<string, unknown> = {}): void {
  writeFileSync(
    join(env.project, ".mcp.json"),
    JSON.stringify({ mcpServers: { drifty: { command: process.execPath, args: [join(SERVERS_DIR, "drift.mjs")], env: { DEMO_VARIANT: variant } }, ...extra } }, null, 2),
  );
}

beforeEach(async () => {
  env = tempEnv();
  clock = new Date("2026-10-10T12:00:00.000Z");
  config("1");
  const code = await connectAdd({ name: "drifty", projectRoot: env.project, allowUnsandboxed: true, now, timeoutMs: 15_000 }, scripted(["", "", ""]));
  expect(code).toBe(0);
});
afterEach(() => env.restore());

describe("diffToolHashes", () => {
  it("lists added, removed and changed tools by name", () => {
    expect(diffToolHashes({ a: "1", b: "2", c: "3" }, { b: "2", c: "9", d: "4" })).toEqual([
      { tool: "a", change: "removed" },
      { tool: "c", change: "changed" },
      { tool: "d", change: "added" },
    ]);
    expect(diffToolHashes({ x: "1" }, { x: "1" })).toEqual([]);
  });
});

describe("drift", () => {
  it("records changes without touching the approval state, keeps changed until approval, and re-vets changed tools", async () => {
    const approved = loadServers().servers.drifty!;
    expect(Object.keys(approved.toolHashes)).toEqual(["alpha", "beta"]);

    // No change.
    clock = new Date("2026-10-11T00:00:00.000Z");
    let [r] = await runDrift({ allowUnsandboxed: true, now, timeoutMs: 15_000 });
    expect(r).toMatchObject({ server: "drifty", status: "unchanged", changes: [], awaitingApproval: false, verdict: "ok" });
    expect(loadServers().servers.drifty!.lastDriftCheck).toBe("2026-10-11T00:00:00.000Z");

    // Variant 2: alpha removed, beta changed, gamma added.
    config("2");
    [r] = await runDrift({ allowUnsandboxed: true, now, timeoutMs: 15_000 });
    expect(r!.status).toBe("changed");
    expect(r!.changes).toEqual([
      { tool: "alpha", change: "removed" },
      { tool: "beta", change: "changed" },
      { tool: "gamma", change: "added" },
    ]);
    let m = loadServers().servers.drifty!;
    expect(m.changed).toBe(true);
    expect(m.changes).toEqual(r!.changes);
    expect(m.toolHashes).toEqual(approved.toolHashes); // approval state untouched
    expect(m.approvedAt).toBe(approved.approvedAt);

    // Back to the approved definitions: still awaiting a human approval.
    config("1");
    [r] = await runDrift({ allowUnsandboxed: true, now, timeoutMs: 15_000 });
    expect(r).toMatchObject({ status: "unchanged", awaitingApproval: true });
    expect(loadServers().servers.drifty!.changed).toBe(true);

    // Variant 3: the changed tool now carries hidden instructions; the vet checks re-run on it.
    config("3");
    [r] = await runDrift({ allowUnsandboxed: true, now, timeoutMs: 15_000 });
    expect(r!.verdict).toBe("high-risk");
    expect(r!.findings.map((f) => [f.checkId, f.tool])).toContainEqual(["vet/hidden-instructions", "beta"]);
    m = loadServers().servers.drifty!;
    expect(m.vet!.verdict).toBe("high-risk");
  });

  it("checks only stale servers when asked, and skips servers that are gone or cannot be listed", async () => {
    clock = new Date("2026-10-10T20:00:00.000Z");
    expect(await runDrift({ allowUnsandboxed: true, now, onlyStaleHours: 24 })).toEqual([]);
    clock = new Date("2026-10-12T00:00:00.000Z");
    expect(await runDrift({ allowUnsandboxed: true, now, onlyStaleHours: 24, timeoutMs: 15_000 })).toHaveLength(1);

    writeFileSync(join(env.project, ".mcp.json"), JSON.stringify({ mcpServers: {} }));
    const [gone] = await runDrift({ allowUnsandboxed: true, now });
    expect(gone).toMatchObject({ status: "not-found" });

    config("1", {});
    const before = loadServers().servers.drifty!.lastDriftCheck;
    const saved = process.env.PATH;
    process.env.PATH = join(env.home, "no-docker-here");
    resetDockerCache();
    try {
      const [inc] = await runDrift({ now }); // no --allow-unsandboxed and no Docker → not run at all
      expect(inc).toMatchObject({ status: "incomplete" });
      expect(inc!.incompleteReason).toMatch(/Docker is not available/);
      expect(loadServers().servers.drifty!.lastDriftCheck).toBe(before);
      await expect(driftCheckAll({ onlyStaleHours: 0 })).resolves.toBeUndefined();
    } finally {
      process.env.PATH = saved;
      resetDockerCache();
    }
  });

  it("driftCheckAll never throws, even with a corrupt servers.json", async () => {
    writeFileSync(join(env.secorHome, "servers.json"), "{ broken");
    await expect(driftCheckAll()).resolves.toBeUndefined();
  });
});

describe("connect approve", () => {
  it("refuses to run without a terminal", () => {
    expect(() => requireTerminal("approve", { isTTY: false })).toThrow(/an AI agent must ask the user/);
  });

  it("stores the new hashes and clears changed after a human confirms", async () => {
    config("2");
    await runDrift({ allowUnsandboxed: true, now, timeoutMs: 15_000 });
    expect(loadServers().servers.drifty!.changed).toBe(true);
    clock = new Date("2026-10-12T09:00:00.000Z");

    const declined = scripted(["n"]);
    expect(await connectApprove({ name: "drifty", projectRoot: env.project, allowUnsandboxed: true, now, timeoutMs: 15_000 }, declined)).toBe(2);
    expect(loadServers().servers.drifty!.changed).toBe(true);

    const io = scripted(["y"]);
    expect(await connectApprove({ name: "drifty", projectRoot: env.project, allowUnsandboxed: true, now, timeoutMs: 15_000 }, io)).toBe(0);
    const text = io.out.join("\n");
    expect(text).toContain("removed  alpha");
    expect(text).toContain("added    gamma");
    expect(text).toContain("New tools not in the allowed list");
    const m = loadServers().servers.drifty!;
    expect(m).toMatchObject({ changed: false, changes: [], approvedAt: "2026-10-12T09:00:00.000Z", lastDriftCheck: "2026-10-12T09:00:00.000Z" });
    expect(Object.keys(m.toolHashes)).toEqual(["beta", "gamma"]);
    // scopes.yaml is never changed by approve.
    expect(readFileSync(join(env.secorHome, "scopes.yaml"), "utf8")).toContain("tools: [alpha, beta]");
  });

  it("requires typing the name to approve high-risk definitions", async () => {
    config("3");
    const wrong = scripted(["yes"]);
    expect(await connectApprove({ name: "drifty", projectRoot: env.project, allowUnsandboxed: true, now, timeoutMs: 15_000 }, wrong)).toBe(2);
    const right = scripted(["drifty"]);
    expect(await connectApprove({ name: "drifty", projectRoot: env.project, allowUnsandboxed: true, now, timeoutMs: 15_000 }, right)).toBe(0);
    expect(loadServers().servers.drifty!.vet!.verdict).toBe("high-risk");
  });

  it("refuses unmanaged servers and unreadable tool lists", async () => {
    expect(await connectApprove({ name: "other", projectRoot: env.project, now }, scripted([]))).toBe(2);
    writeFileSync(join(env.project, ".mcp.json"), JSON.stringify({ mcpServers: { drifty: { command: join(env.home, "missing-binary") } } }));
    const io = scripted([]);
    expect(await connectApprove({ name: "drifty", projectRoot: env.project, allowUnsandboxed: true, now }, io)).toBe(2);
    expect(io.out.join("\n")).toContain("Cannot approve");
  });
});
