// Appending a server scope to ~/.secor/scopes.yaml (spec 9.3 step 5): the human's text and comments are kept.

import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { effectiveScope, loadScopes } from "../../src/connect/scopes.js";
import { appendServerScope, SCOPES_TEMPLATE, writeServerScope } from "../../src/connect/scopes-write.js";
import { type TempEnv, tempEnv } from "../connect/helpers.js";

const HUMAN = `# my scopes — edited by me
version: 1
defaults:
  never: [secret, credential]   # keep these two
  onViolation: ask
# servers below
servers:
  github:
    description: "Code and issues"
    tools: [search_code, create_issue]   # trailing comment
    onViolation: block

  # notion is read-only
  notion:
    tools: [search]

# trailing comment at the end
confidential:
  paths: ["~/secret/**"]
`;

describe("appendServerScope", () => {
  it("inserts the entry at the end of the servers block and keeps every other byte", () => {
    const out = appendServerScope(HUMAN, "weather", { tools: ["get_forecast"], never: ["secret"] }, "2026-10-10");
    const inserted = "  # added by secor connect add on 2026-10-10\n  weather:\n    tools: [get_forecast]\n    never: [secret]\n";
    expect(out).toContain(inserted);
    expect(out.replace(inserted, "")).toBe(HUMAN);
    const scopes = loadScopesFromText(out);
    expect(effectiveScope(scopes, "weather")).toMatchObject({ tools: ["get_forecast"], never: ["secret"], managedScope: true });
    expect(effectiveScope(scopes, "github")).toMatchObject({ tools: ["search_code", "create_issue"], onViolation: "block" });
  });

  it("matches the indentation the human used", () => {
    const four = "version: 1\nservers:\n    github:\n        tools: [a]\n";
    const out = appendServerScope(four, "x", { tools: ["t"] }, "2026-10-10");
    expect(out).toBe(`${four}    # added by secor connect add on 2026-10-10\n    x:\n      tools: [t]\n`);
  });

  it("creates the file from the template when there is none", () => {
    const out = appendServerScope(null, "github", { tools: ["search_code"], sandbox: { mounts: ["~/projects/app"] } }, "2026-10-10");
    expect(out.startsWith(SCOPES_TEMPLATE)).toBe(true);
    expect(out).toContain("servers:\n  # added by secor connect add on 2026-10-10\n  github:\n    tools: [search_code]\n    sandbox:\n      mounts: [~/projects/app]\n");
    expect(effectiveScope(loadScopesFromText(out), "github").tools).toEqual(["search_code"]);
  });

  it("appends a servers key when the file has none", () => {
    const text = "version: 1\n# no servers yet\n";
    const out = appendServerScope(text, "a", {}, "2026-10-10");
    expect(out.startsWith(text)).toBe(true);
    expect(loadScopesFromText(out).servers).toHaveProperty("a");
  });

  it("handles servers: {} and an empty servers key, keeping comments", () => {
    for (const text of ["version: 1 # top\nservers: {}  # none yet\n", "version: 1\n# c1\nservers:\n# c2\n"]) {
      const out = appendServerScope(text, "a b", { tools: ["x"] }, "2026-10-10");
      expect(out).toContain("# added by secor connect add on 2026-10-10");
      for (const c of text.match(/#[^\n]*/g) ?? []) expect(out).toContain(c.trim());
      expect(effectiveScope(loadScopesFromText(out), "a b").tools).toEqual(["x"]);
    }
  });

  it("keeps an all-comment file's comments and starts the document after them", () => {
    const out = appendServerScope("# only comments\n# here\n", "s", {}, "2026-10-10");
    expect(out.startsWith("# only comments\n# here\nversion: 1\n")).toBe(true);
    expect(loadScopesFromText(out).servers).toHaveProperty("s");
  });

  it("quotes names that need it", () => {
    const out = appendServerScope("version: 1\n", "@acme/mcp:x", { tools: ["t"] }, "2026-10-10");
    expect(loadScopesFromText(out).servers).toHaveProperty(["@acme/mcp:x"]);
  });

  it("refuses an existing entry and invalid YAML", () => {
    expect(() => appendServerScope(HUMAN, "github", {}, "2026-10-10")).toThrow(/already has a scope/);
    expect(() => appendServerScope("version: 1\nservers: [oops\n", "x", {}, "2026-10-10")).toThrow(/invalid YAML/);
  });
});

let env: TempEnv;
beforeEach(() => {
  env = tempEnv();
});
afterEach(() => env.restore());

function loadScopesFromText(text: string) {
  mkdirSync(env.secorHome, { recursive: true });
  const p = join(env.secorHome, "check-scopes.yaml");
  writeFileSync(p, text);
  return loadScopes(p);
}

describe("writeServerScope", () => {
  it("backs up an existing file before writing, mode 0600", () => {
    mkdirSync(env.secorHome, { recursive: true });
    const path = join(env.secorHome, "scopes.yaml");
    writeFileSync(path, HUMAN);
    const backup = writeServerScope("weather", { tools: ["x"] }, new Date("2026-10-10T12:00:00Z"));
    expect(backup).toBe(join(env.secorHome, "backups", "20261010T120000Z-scopes.yaml"));
    expect(readFileSync(backup!, "utf8")).toBe(HUMAN);
    expect(readFileSync(path, "utf8")).toContain("weather:");
    expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it("creates the file without a backup when there was none", () => {
    const backup = writeServerScope("a", {}, new Date("2026-10-10T12:00:00Z"));
    expect(backup).toBeNull();
    expect(existsSync(join(env.secorHome, "scopes.yaml"))).toBe(true);
    expect(existsSync(join(env.secorHome, "backups")) ? readdirSync(join(env.secorHome, "backups")) : []).toEqual([]);
  });
});
