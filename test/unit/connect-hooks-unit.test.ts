// Hook internals (spec 9.4): server-name resolution, lenient fail mode, text views of tool data, policy-file paths,
// and a static check that the hook path never imports tree-sitter, commander or the MCP SDK.

import { existsSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { detectorText, fingerprintText, isPolicyFile, lenientFailMode, resolveServerName, runHook, stringLeaves } from "../../src/connect/hooks.js";
import { normalizeMcpName, parseMcpToolName } from "../../src/connect/names.js";
import { REPO_ROOT, type TempEnv, tempEnv } from "../connect/helpers.js";

let env: TempEnv;
beforeEach(() => {
  env = tempEnv();
});
afterEach(() => env.restore());

describe("names", () => {
  it("parses mcp__<server>__<tool> (server up to the first __)", () => {
    expect(parseMcpToolName("mcp__github__create_issue")).toEqual({ server: "github", tool: "create_issue" });
    expect(parseMcpToolName("mcp__plugin_secor_secor__ship_check")).toEqual({ server: "plugin_secor_secor", tool: "ship_check" });
    expect(parseMcpToolName("mcp__a__b__c")).toEqual({ server: "a", tool: "b__c" });
    expect(parseMcpToolName("Read")).toBeNull();
    expect(parseMcpToolName(42)).toBeNull();
    expect(normalizeMcpName("my.server name")).toBe("my_server_name");
  });

  it("maps a tool-name server part back to the configured name, own keys only", () => {
    const scopes = { servers: { "my.server": {} } };
    const servers = { servers: { github: {} } };
    expect(resolveServerName("github", scopes, servers, undefined)).toBe("github");
    expect(resolveServerName("my_server", scopes, servers, undefined)).toBe("my.server");
    expect(resolveServerName("my_server", scopes, servers, "my server")).toBe("my server");
    expect(resolveServerName("constructor", scopes, servers, undefined)).toBe("constructor");
    expect(resolveServerName("unknown", scopes, servers, "something else")).toBe("unknown");
  });
});

describe("fail mode when scopes.yaml cannot be loaded", () => {
  it("reads failMode leniently and defaults to open", () => {
    expect(lenientFailMode(null)).toBe("open");
    expect(lenientFailMode("version: 1\ndefaults:\n  failMode: closed\n  bogus: [\n")).toBe("closed");
    expect(lenientFailMode("defaults:\n  failMode: 'closed'  # strict\n")).toBe("closed");
    expect(lenientFailMode("defaults:\n  failMode: open\n")).toBe("open");
    expect(lenientFailMode("# failMode: closed\n")).toBe("open");
  });
});

describe("text views", () => {
  it("collects string leaves with limits", () => {
    expect(stringLeaves({ a: "x", b: [1, "y", { c: "z" }], d: null })).toEqual(["x", "y", "z"]);
    let deep: unknown = "bottom";
    for (let i = 0; i < 200; i++) deep = { n: deep };
    expect(stringLeaves(deep)).toEqual([]);
  });

  it("adds unescaped leaves to the detector text only when JSON escaping changes them", () => {
    const input = { plain: "hello", code: 'a = "b"\nc' };
    const serialised = JSON.stringify(input);
    const text = detectorText(serialised, input, 1_000_000);
    expect(text).toBe(`${serialised}\na = "b"\nc`);
    expect(detectorText("x".repeat(50), { s: "y\n" }, 10)).toHaveLength(10);
  });

  it("fingerprints string values, not JSON text", () => {
    expect(fingerprintText("abc")).toBe("abc");
    expect(fingerprintText({ content: [{ type: "text", text: "line1\nline2" }] })).toBe("text\nline1\nline2");
  });
});

describe("protect: policy file resolution", () => {
  it("matches the four policy files through relative paths, .., ~, case and symlinks", () => {
    const sh = env.secorHome;
    mkdirSync(sh, { recursive: true });
    writeFileSync(join(sh, "scopes.yaml"), "version: 1\n");
    mkdirSync(join(env.project, "a", "b"), { recursive: true });
    expect(isPolicyFile("secor.config.yaml", env.project)).toBe(true);
    expect(isPolicyFile("../../.secor/ignore.yaml", join(env.project, "a", "b"))).toBe(true);
    expect(isPolicyFile("~/.secor/servers.json", env.project)).toBe(true);
    expect(isPolicyFile(join(sh, "SCOPES.YAML"), env.project)).toBe(true);
    symlinkSync(sh, join(env.project, "alias"));
    expect(isPolicyFile("alias/scopes.yaml", env.project)).toBe(true);
    symlinkSync(join(env.project, "chain2"), join(env.project, "chain1"));
    symlinkSync(join(sh, "servers.json"), join(env.project, "chain2"));
    expect(isPolicyFile("chain1", env.project)).toBe(true);
    expect(isPolicyFile("src/secor.config.yaml.example", env.project)).toBe(false);
    expect(isPolicyFile(join(sh, "ledger", "2026-10-10.jsonl"), env.project)).toBe(false);
  });

  it("protects the real ~/.secor files when SECOR_HOME points elsewhere", () => {
    const saved = process.env.SECOR_HOME;
    process.env.SECOR_HOME = join(env.home, "custom-secor");
    try {
      expect(isPolicyFile(join(env.home, ".secor", "scopes.yaml"), env.project)).toBe(true);
      expect(isPolicyFile(join(env.home, "custom-secor", "servers.json"), env.project)).toBe(true);
    } finally {
      process.env.SECOR_HOME = saved;
    }
  });
});

describe("runHook never throws and never says allow", () => {
  it("handles odd inputs", async () => {
    for (const phase of ["pre", "post", "protect"] as const) {
      for (const stdin of ["", "null", "[]", "42", '"x"', "{}", '{"tool_name": null}', '{"tool_name":"mcp__x__y","tool_input":"str"}']) {
        const out = await runHook(phase, stdin);
        expect(out).not.toContain('"allow"');
      }
    }
  });
});

// ---------------------------------------------------------------- static import graph of the hook path

const HEAVY = /^(?:web-tree-sitter|tree-sitter|commander|@modelcontextprotocol\/sdk)(?:\/|$)/;

function importsOf(file: string): string[] {
  const text = readFileSync(file, "utf8").replace(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, "");
  const out: string[] = [];
  for (const m of text.matchAll(/(?:^|\n)\s*(?:import|export)\s+(?!type\b)[^;'"]*?from\s+["']([^"']+)["']|(?:^|\n)\s*import\s+["']([^"']+)["']|\bimport\(\s*["']([^"']+)["']\s*\)/g)) {
    out.push((m[1] ?? m[2] ?? m[3])!);
  }
  return out;
}

describe("hook path imports", () => {
  it("reaches no tree-sitter, commander or MCP SDK module from src/cli/hook.ts", () => {
    const seen = new Set<string>();
    const bare = new Set<string>();
    const stack = [join(REPO_ROOT, "src", "cli", "hook.ts")];
    while (stack.length) {
      const file = stack.pop()!;
      if (seen.has(file)) continue;
      seen.add(file);
      for (const spec of importsOf(file)) {
        if (spec.startsWith(".")) {
          const target = resolve(dirname(file), spec.replace(/\.js$/, ".ts"));
          if (existsSync(target)) stack.push(target);
        } else bare.add(spec);
      }
    }
    expect(seen.has(join(REPO_ROOT, "src", "connect", "hooks.ts"))).toBe(true);
    expect([...bare].filter((b) => HEAVY.test(b))).toEqual([]);
    expect([...seen].map((f) => f.slice(REPO_ROOT.length + 1)).filter((f) => /engine\/(ast|parse|context|detect|inventory)\.ts$/.test(f))).toEqual([]);
  });
});
