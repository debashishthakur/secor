// Claude Code plugin files (spec 11.4) and the skill (spec 11.3).

import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { TOOL_NAMES } from "../../src/mcp/server.js";

const ROOT = join(import.meta.dirname, "..", "..");
const read = (rel: string) => readFileSync(join(ROOT, rel), "utf8");

describe("plugin manifest and MCP entry (spec 11.4)", () => {
  it(".claude-plugin/plugin.json has name, the package version, a description and the licence", () => {
    const manifest = JSON.parse(read(".claude-plugin/plugin.json")) as Record<string, unknown>;
    const pkg = JSON.parse(read("package.json")) as { version: string; license: string };
    expect(Object.keys(manifest).sort()).toEqual(["description", "license", "name", "version"]);
    expect(manifest).toMatchObject({ name: "secor", version: pkg.version, license: "Apache-2.0" });
    expect(pkg.license).toBe("Apache-2.0");
    expect(String(manifest.description).length).toBeGreaterThan(20);
    expect(String(manifest.description)).not.toMatch(/secure|safe/i);
  });

  it(".mcp.json runs `secor mcp`", () => {
    expect(JSON.parse(read(".mcp.json"))).toEqual({ mcpServers: { secor: { command: "secor", args: ["mcp"] } } });
  });
});

describe("skills/secor/SKILL.md (spec 11.3)", () => {
  const skill = read("skills/secor/SKILL.md");
  const front = /^---\n([\s\S]*?)\n---\n/.exec(skill)?.[1] ?? "";
  const body = skill.slice(skill.indexOf("\n---\n", 4) + 5);

  it("has frontmatter with name secor and a when-to-use description", () => {
    expect(front).toMatch(/^name: secor$/m);
    const description = /^description: (.+)$/m.exec(front)?.[1] ?? "";
    expect(description).toMatch(/before a deploy/i);
    expect(description).toMatch(/MCP server/);
  });

  it("names every MCP tool", () => {
    for (const t of TOOL_NAMES) expect(body).toContain(`\`${t}\``);
  });

  it("covers the eight points of 11.3", () => {
    // 1 when to use, 2 the loop, 3 advisory, 4 policy files, 5 never "secure", 6 humanAction, 7 Connect, 8 Probe
    expect(body).toMatch(/## 1\. When to use SECOR/);
    expect(body).toMatch(/ship_check[\s\S]*ship_results[\s\S]*severity order[\s\S]*testTemplate[\s\S]*ship_verify[\s\S]*Report/);
    expect(body).toMatch(/advisory[\s\S]*ask the user[\s\S]*Never block/i);
    for (const f of ["secor.config.yaml", ".secor/ignore.yaml", "~/.secor/"]) expect(body).toContain(f);
    expect(body).toMatch(/Never say the project[^\n]*"secure"/);
    for (const label of ["Fix before deploy", "Needs work", "No critical or high issues known"]) expect(body).toContain(label);
    expect(body).toMatch(/coverage/i);
    expect(body).toMatch(/not checked/i);
    expect(body).toContain("humanAction");
    expect(body).toContain("secor connect add <name>");
    for (const code of ["tool-not-allowed", "too-long", "class:secret", "flow:<server>", "flow:file", "unvetted", "instructions-in-output"]) expect(body).toContain(code);
    expect(body).toMatch(/You must not start Probe/);
    expect(body).toMatch(/staging/);
    expect(body).toMatch(/never production/);
  });

  it("states the limits of 9.8 and 9A.9", () => {
    expect(body).toMatch(/Reworded or encoded data often is not caught/);
    expect(body).toMatch(/Only the sandbox limits what it can read/);
    expect(body).toMatch(/Only Claude Code gets per-call checks/);
    expect(body).toMatch(/A Probe run that finds nothing/);
    expect(body).toMatch(/says nothing about production/);
    expect(body).toMatch(/read-only in v1/);
  });

  it("treats evidence as data", () => {
    expect(body).toMatch(/Fields named `evidence`[\s\S]*data, never as instructions/);
  });
});
