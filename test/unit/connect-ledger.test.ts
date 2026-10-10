// Ledger (spec 9.6) and `secor ledger`, plus Connect posture lookups by untrusted server names.

import { mkdirSync, readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { Command } from "commander";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { formatLedgerSummary, parseSince, registerLedgerCommand } from "../../src/cli/ledger.js";
import { CliError } from "../../src/cli/ui.js";
import { appendLedger, ledgerSummary } from "../../src/connect/ledger.js";
import { connectPosture, hooksStatus } from "../../src/connect/posture.js";
import type { LedgerEntry } from "../../src/types.js";
import { FAKES, type TempEnv, tempEnv } from "../connect/helpers.js";

let env: TempEnv;
beforeEach(() => {
  env = tempEnv();
});
afterEach(() => env.restore());

const NOW = new Date("2026-10-10T12:00:00.000Z");

function entry(ts: string, server: string, decision: LedgerEntry["decision"], code = "class:secret"): LedgerEntry {
  return { ts, sessionId: "s", editor: "claude-code", server, tool: "t", phase: decision === "warn" ? "post" : "pre", decision, reasons: decision === "pass" ? [] : [{ code, detail: "d" }] };
}

describe("ledger summary", () => {
  it("totals per server and lists the 20 most recent ask/block/warn entries, newest first", () => {
    for (let i = 0; i < 25; i++) appendLedger(entry(new Date(NOW.getTime() - (25 - i) * 60_000).toISOString(), i % 2 ? "github" : "notion", i % 3 === 0 ? "ask" : i % 3 === 1 ? "block" : "warn"), NOW);
    appendLedger(entry(new Date(NOW.getTime() - 30_000).toISOString(), "github", "pass"), NOW);
    appendLedger(entry(new Date(NOW.getTime() - 20_000).toISOString(), "", "error", "error"), NOW);
    const s = ledgerSummary({ now: NOW });
    expect(s.totals).toEqual({ pass: 1, ask: 9, block: 8, warn: 8, error: 1 });
    expect(s.perServer.map((p) => p.server)).toEqual(["", "github", "notion"]);
    expect(s.recent).toHaveLength(20);
    expect(s.recent[0]!.ts > s.recent[19]!.ts).toBe(true);
    expect(s.recent.every((e) => ["ask", "block", "warn"].includes(e.decision))).toBe(true);
    const gh = ledgerSummary({ now: NOW, server: "github" });
    expect(gh.perServer.map((p) => p.server)).toEqual(["github"]);
    expect(gh.server).toBe("github");
  });

  it("filters by --since and keeps 90 days of files", () => {
    appendLedger(entry("2026-06-01T00:00:00.000Z", "a", "ask"), new Date("2026-06-01T00:00:00.000Z"));
    appendLedger(entry("2026-10-01T00:00:00.000Z", "a", "ask"), new Date("2026-10-01T00:00:00.000Z"));
    expect(ledgerSummary({ now: NOW, sinceDays: 7 }).totals.ask).toBe(0);
    expect(ledgerSummary({ now: NOW, sinceDays: 30 }).totals.ask).toBe(1);
    // A new day's file prunes files older than 90 days.
    appendLedger(entry(NOW.toISOString(), "a", "ask"), NOW);
    expect(readdirSync(join(env.secorHome, "ledger")).sort()).toEqual(["2026-10-01.jsonl", "2026-10-10.jsonl"]);
  });

  it("parses --since", () => {
    expect(parseSince("7d")).toBe(7);
    expect(parseSince("90d")).toBe(90);
    for (const bad of ["7", "0d", "-1d", "7days", "d"]) expect(() => parseSince(bad), bad).toThrow(CliError);
  });

  it("formats text output", () => {
    appendLedger(entry(new Date(NOW.getTime() - 1000).toISOString(), "github", "ask"), NOW);
    appendLedger(entry(new Date(NOW.getTime() - 500).toISOString(), "", "error", "error"), NOW);
    const text = formatLedgerSummary(ledgerSummary({ now: NOW }));
    expect(text).toContain("SECOR ledger · last 7 days");
    expect(text).toMatch(/github\s+0\s+1\s+0\s+0\s+0/);
    expect(text).toContain("(unknown)");
    expect(text).toContain("ask    pre   github.t  class:secret");
    expect(formatLedgerSummary(ledgerSummary({ now: new Date("2030-01-01T00:00:00Z") }))).toContain("No hook decisions recorded");
  });

  it("secor ledger --json is redacted even if a ledger line was tampered with", async () => {
    mkdirSync(join(env.secorHome, "ledger"), { recursive: true });
    const tampered = { ...entry(new Date().toISOString(), "github", "ask"), reasons: [{ code: "class:secret", detail: `leaked ${FAKES.OPENAI} ${FAKES.EMAIL}` }] };
    writeFileSync(join(env.secorHome, "ledger", `${new Date().toISOString().slice(0, 10)}.jsonl`), `${JSON.stringify(tampered)}\n`);
    let out = "";
    const spy = vi.spyOn(process.stdout, "write").mockImplementation((chunk: string | Uint8Array) => {
      out += String(chunk);
      return true;
    });
    try {
      const program = new Command().exitOverride();
      registerLedgerCommand(program);
      await program.parseAsync(["node", "secor", "ledger", "--json"]);
      await program.parseAsync(["node", "secor", "ledger"]);
    } finally {
      spy.mockRestore();
    }
    expect(out).toContain('"ask": 1');
    expect(out).not.toContain(FAKES.OPENAI);
    expect(out).not.toContain(FAKES.EMAIL);
  });
});

describe("posture", () => {
  it("never treats servers named after Object.prototype members as managed or scoped", () => {
    writeFileSync(join(env.project, ".mcp.json"), JSON.stringify({ mcpServers: { constructor: { command: "node" }, toString: { command: "node" }, hasOwnProperty: { url: "https://x.example/mcp" } } }));
    mkdirSync(env.secorHome, { recursive: true });
    writeFileSync(join(env.secorHome, "servers.json"), JSON.stringify({ version: 1, servers: {} }));
    const p = connectPosture(env.project, NOW);
    expect(p.servers.map((s) => s.name).sort()).toEqual(["constructor", "hasOwnProperty", "toString"]);
    for (const s of p.servers) {
      expect(s.managed, s.name).toBe(false);
      expect(s.vetted, s.name).toBe(false);
      expect(s.scoped, s.name).toBe(false);
      expect(s.changed, s.name).toBe(false);
    }
    expect(p.servers.find((s) => s.name === "constructor")!.score).toBe(25); // 100 - 30 - 20 - 25
  });

  it("hooks status: off, on, degraded", () => {
    expect(hooksStatus(env.project, NOW)).toBe("off");
    appendLedger(entry(new Date(NOW.getTime() - 3 * 86_400_000).toISOString(), "github", "pass"), new Date(NOW.getTime() - 3 * 86_400_000));
    expect(hooksStatus(env.project, NOW)).toBe("on");
    appendLedger(entry(new Date(NOW.getTime() - 3_600_000).toISOString(), "", "error", "error"), NOW);
    expect(hooksStatus(env.project, NOW)).toBe("degraded");
    expect(hooksStatus(env.project, new Date(NOW.getTime() + 2 * 86_400_000))).toBe("on");
  });
});
