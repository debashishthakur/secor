// Editor-config edits (invariant 3: only during install-hooks or add --apply-sandbox, after a backup):
// minimal JSON/JSONC value replacement, the sandbox rewrite, and the hooks installer.

import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { applySandboxToConfig, sandboxWrapper } from "../../src/connect/add.js";
import { discoverServers } from "../../src/connect/discover.js";
import { hasSecorBlock, installHooks, mergeSecorHooks, removeSecorHooks, SECOR_HOOKS, uninstallHooks } from "../../src/connect/install.js";
import { findValueSpan, replaceJsonValue } from "../../src/connect/jsonedit.js";
import { hooksStatus, settingsHaveSecorHook } from "../../src/connect/posture.js";
import { parseJsonc } from "../../src/engine/resolve.js";
import { NODE_IMAGE } from "../../src/connect/sandbox.js";
import { REPO_ROOT, type TempEnv, tempEnv } from "../connect/helpers.js";

let env: TempEnv;
beforeEach(() => {
  env = tempEnv();
});
afterEach(() => env.restore());

function write(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, text);
}

describe("JSONC value spans", () => {
  const text = `{
  // comment with "quotes" and { braces }
  "mcpServers": {
    "a": { "command": "node", "args": ["x}y", "\\"q\\""] }, /* block */
    "b": { "url": "https://x" },
  },
  "mcpServers2": [1, 2, {"k": null}],
}`;

  it("finds nested values past comments, escapes and trailing commas", () => {
    const span = findValueSpan(text, ["mcpServers", "a"])!;
    expect(parseJsonc(text.slice(span.start, span.end))).toEqual({ command: "node", args: ["x}y", '"q"'] });
    const arr = findValueSpan(text, ["mcpServers2", "2", "k"])!;
    expect(text.slice(arr.start, arr.end)).toBe("null");
    expect(findValueSpan(text, ["nope"])).toBeNull();
  });

  it("uses the last occurrence of a duplicated key, like JSON.parse", () => {
    const dup = '{"s": {"command": "first"}, "s": {"command": "second"}}';
    const span = findValueSpan(dup, ["s"])!;
    expect(dup.slice(span.start, span.end)).toBe('{"command": "second"}');
  });

  it("replaces one value and keeps every other byte", () => {
    const out = replaceJsonValue(text, ["mcpServers", "a"], { command: "docker", args: ["run"] });
    const span = findValueSpan(text, ["mcpServers", "a"])!;
    expect(out.slice(0, span.start)).toBe(text.slice(0, span.start));
    expect(out.endsWith(text.slice(span.end))).toBe(true);
    expect((parseJsonc(out) as { mcpServers: { a: unknown } }).mcpServers.a).toEqual({ command: "docker", args: ["run"] });
    expect(out).toContain('    "a": {\n      "command": "docker",\n      "args": [\n        "run"\n      ]\n    }, /* block */');
  });

  it("throws on invalid JSON", () => {
    expect(() => findValueSpan('{"a": }', ["a"])).toThrow(/invalid JSON/);
    expect(() => findValueSpan('{"a": 1', ["a"])).toThrow(/invalid JSON/);
  });
});

describe("--apply-sandbox rewrite", () => {
  it("backs up the config and rewrites only that entry, keeping ${VAR} placeholders and env names", () => {
    const file = join(env.project, ".mcp.json");
    const original = `{
  "mcpServers": {
    "github": {
      "command": "npx",
      "args": ["-y", "@acme/github", "--org", "\${GH_ORG}"],
      "env": { "GITHUB_TOKEN": "\${GH_TOKEN}" }
    },
    "other": { "command": "uvx", "args": ["thing"] }
  }
}
`;
    write(file, original);
    process.env.GH_ORG = "acme-expanded";
    try {
      const server = discoverServers(env.project).find((s) => s.name === "github")!;
      const raw = (parseJsonc(original) as { mcpServers: { github: Record<string, unknown> } }).mcpServers.github;
      const wrapper = sandboxWrapper(server, raw, ["/Users/me/projects/app"]);
      if ("error" in wrapper) throw new Error(wrapper.error);
      const backup = applySandboxToConfig(server, wrapper, new Date("2026-10-10T08:09:10Z"));
      expect(backup).toBe(join(env.secorHome, "backups", "20261010T080910Z-.mcp.json"));
      expect(readFileSync(backup, "utf8")).toBe(original);
      const after = readFileSync(file, "utf8");
      const parsed = parseJsonc(after) as { mcpServers: Record<string, { command: string; args: string[]; env?: Record<string, string> }> };
      expect(parsed.mcpServers.github!.command).toBe("docker");
      expect(parsed.mcpServers.github!.args).toEqual([
        "run", "--rm", "-i", "--init", "--read-only", "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=1g", "--tmpfs", "/root:rw,exec,nosuid,nodev,size=1g", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "-v", "/Users/me/projects/app:/Users/me/projects/app:ro", "-e", "GITHUB_TOKEN", NODE_IMAGE, "npx", "-y", "@acme/github", "--org", "${GH_ORG}",
      ]);
      expect(parsed.mcpServers.github!.env).toEqual({ GITHUB_TOKEN: "${GH_TOKEN}" });
      expect(after).not.toContain("acme-expanded");
      expect(parsed.mcpServers.other).toEqual({ command: "uvx", args: ["thing"] });
      expect(after.endsWith('    "other": { "command": "uvx", "args": ["thing"] }\n  }\n}\n')).toBe(true);
      // The rewritten entry now counts as sandboxed.
      expect(discoverServers(env.project).find((s) => s.name === "github")!.sandbox).toBe("yes");
    } finally {
      delete process.env.GH_ORG;
    }
  });

  it("has no wrapper for commands without a sandbox image", () => {
    write(join(env.project, ".mcp.json"), JSON.stringify({ mcpServers: { b: { command: "bun", args: ["x.ts"] } } }));
    const server = discoverServers(env.project)[0]!;
    expect(sandboxWrapper(server, { command: "bun" }, [])).toEqual({ error: "no sandbox image for this command" });
  });
});

describe("install-hooks / uninstall-hooks", () => {
  const userSettings = () => join(env.home, ".claude", "settings.json");

  it("ships the same block as hooks/hooks.json (plugin route) with anchored matchers", () => {
    expect(JSON.parse(readFileSync(join(REPO_ROOT, "hooks", "hooks.json"), "utf8"))).toEqual(SECOR_HOOKS);
    const m = SECOR_HOOKS.hooks;
    expect(m.PreToolUse.map((g) => g.matcher)).toEqual(["^mcp__.*", "Edit|Write|MultiEdit"]);
    expect(m.PostToolUse.map((g) => g.matcher)).toEqual(["^(mcp__.*|Read)$"]);
    const pre = new RegExp(m.PreToolUse[0]!.matcher);
    expect(pre.test("mcp__github__x")).toBe(true);
    expect(pre.test("xmcp__github__x")).toBe(false);
    const post = new RegExp(m.PostToolUse[0]!.matcher);
    expect(post.test("Read")).toBe(true);
    expect(post.test("mcp__a__b")).toBe(true);
    expect(post.test("ReadMcpResourceTool")).toBe(false);
    expect(post.test("NotebookRead")).toBe(false);
  });

  it("creates the user settings file when missing (mode 0600)", () => {
    const r = installHooks("user", env.project);
    expect(r).toMatchObject({ path: userSettings(), changed: true, backup: null });
    expect(JSON.parse(readFileSync(userSettings(), "utf8"))).toEqual(SECOR_HOOKS);
    expect(statSync(userSettings()).mode & 0o777).toBe(0o600);
  });

  it("merges into existing settings, keeps other hooks and keys, backs up, and is idempotent", () => {
    const existing = {
      model: "opus",
      env: { FOO: "bar" },
      hooks: {
        PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "my-linter" }] }],
        Stop: [{ hooks: [{ type: "command", command: "notify-done" }] }],
      },
    };
    write(userSettings(), `${JSON.stringify(existing, null, 2)}\n`);
    const first = installHooks("user", env.project, new Date("2026-10-10T01:02:03Z"));
    expect(first.changed).toBe(true);
    expect(first.backup).toBe(join(env.secorHome, "backups", "20261010T010203Z-settings.json"));
    const merged = JSON.parse(readFileSync(userSettings(), "utf8")) as typeof existing;
    expect(merged.model).toBe("opus");
    expect(merged.env).toEqual({ FOO: "bar" });
    expect(merged.hooks.Stop).toEqual(existing.hooks.Stop);
    expect(merged.hooks.PreToolUse[0]).toEqual(existing.hooks.PreToolUse[0]);
    expect(merged.hooks.PreToolUse).toHaveLength(3);
    expect(hasSecorBlock(merged)).toBe(true);
    const before = readFileSync(userSettings(), "utf8");
    const second = installHooks("user", env.project);
    expect(second).toMatchObject({ changed: false, backup: null });
    expect(readFileSync(userSettings(), "utf8")).toBe(before);
    expect(readdirSync(join(env.secorHome, "backups"))).toHaveLength(1);
  });

  it("replaces an older SECOR entry instead of adding a second one", () => {
    const old = { hooks: { PreToolUse: [{ matcher: "mcp__.*", hooks: [{ type: "command", command: "secor hook pre", timeout: 10 }, { type: "command", command: "audit-log" }] }] } };
    const { settings, changed } = mergeSecorHooks(old);
    expect(changed).toBe(true);
    const groups = (settings.hooks as typeof SECOR_HOOKS.hooks).PreToolUse as unknown as { matcher: string; hooks: { command: string }[] }[];
    expect(groups[0]).toEqual({ matcher: "mcp__.*", hooks: [{ type: "command", command: "audit-log" }] });
    expect(groups.flatMap((g) => g.hooks.map((h) => h.command)).filter((c) => c.startsWith("secor"))).toEqual(["secor hook pre", "secor hook protect"]);
  });

  it("uninstall removes only SECOR's entries, with a backup", () => {
    write(userSettings(), JSON.stringify({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "my-linter" }] }] } }));
    installHooks("user", env.project);
    installHooks("project", env.project);
    expect(settingsHaveSecorHook(env.project)).toBe(true);
    expect(hooksStatus(env.project)).toBe("on");
    const results = uninstallHooks(env.project);
    expect(results.filter((r) => r.changed).map((r) => r.path).sort()).toEqual([join(env.project, ".claude", "settings.json"), userSettings()].sort());
    for (const r of results.filter((x) => x.changed)) expect(existsSync(r.backup!)).toBe(true);
    expect(JSON.parse(readFileSync(userSettings(), "utf8"))).toEqual({ hooks: { PreToolUse: [{ matcher: "Bash", hooks: [{ type: "command", command: "my-linter" }] }] } });
    expect(JSON.parse(readFileSync(join(env.project, ".claude", "settings.json"), "utf8"))).toEqual({});
    expect(settingsHaveSecorHook(env.project)).toBe(false);
    expect(hooksStatus(env.project)).toBe("off");
    expect(uninstallHooks(env.project).some((r) => r.changed)).toBe(false);
  });

  it("refuses to touch a settings file that is not valid JSON", () => {
    write(userSettings(), "{ not json");
    expect(() => installHooks("user", env.project)).toThrow(/not valid JSON/);
    expect(readFileSync(userSettings(), "utf8")).toBe("{ not json");
    expect(removeSecorHooks({ hooks: "weird" }).changed).toBe(false);
  });
});
