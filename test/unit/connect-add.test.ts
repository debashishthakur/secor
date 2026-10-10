// `secor connect add` (spec 9.3) driven through scripted answers, with demo servers run unsandboxed.

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { NOT_A_TERMINAL, requireTerminal } from "../../src/cli/connect.js";
import { CliError } from "../../src/cli/ui.js";
import { connectAdd, parseToggleAnswer } from "../../src/connect/add.js";
import { discoverServers } from "../../src/connect/discover.js";
import { loadScopes } from "../../src/connect/scopes.js";
import { loadServers } from "../../src/connect/servers.js";
import { scripted, SERVERS_DIR, type TempEnv, tempEnv } from "../connect/helpers.js";

let env: TempEnv;
const NOW = () => new Date("2026-10-10T12:00:00.000Z");

function writeMcpJson(servers: Record<string, unknown>): void {
  writeFileSync(join(env.project, ".mcp.json"), `${JSON.stringify({ mcpServers: servers }, null, 2)}\n`);
}

const demo = (file: string, extra: Record<string, unknown> = {}) => ({ command: process.execPath, args: [join(SERVERS_DIR, file)], ...extra });

beforeEach(() => {
  env = tempEnv();
  writeMcpJson({
    notes: demo("normal-notes.mjs"),
    tools: demo("powerful-tools.mjs"),
    danger: demo("hidden-tool-description.mjs"),
    github: demo("normal-github.mjs"),
    collide: demo("name-collision.mjs"),
    remote: { type: "http", url: "http://127.0.0.1:9/mcp" },
  });
});
afterEach(() => env.restore());

const add = (name: string, answers: string[], extra: { applySandbox?: boolean } = {}) => {
  const io = scripted(answers);
  return connectAdd({ name, projectRoot: env.project, allowUnsandboxed: true, now: NOW, timeoutMs: 15_000, ...extra }, io).then((code) => ({ code, io, text: io.out.join("\n") }));
};

describe("parseToggleAnswer", () => {
  it("parses Enter, all, none, numbers and ranges", () => {
    expect(parseToggleAnswer("", 3)).toEqual({ kind: "accept" });
    expect(parseToggleAnswer(" ALL ", 3)).toEqual({ kind: "all" });
    expect(parseToggleAnswer("none", 3)).toEqual({ kind: "none" });
    expect(parseToggleAnswer("1, 3", 3)).toEqual({ kind: "toggle", indexes: [0, 2] });
    expect(parseToggleAnswer("1-3", 3)).toEqual({ kind: "toggle", indexes: [0, 1, 2] });
    expect(parseToggleAnswer("4", 3).kind).toBe("error");
    expect(parseToggleAnswer("x", 3).kind).toBe("error");
    expect(parseToggleAnswer("3-1", 3).kind).toBe("error");
  });
});

describe("connect add", () => {
  it("refuses to run without a terminal (an AI agent must ask the user)", () => {
    expect(() => requireTerminal("add", { isTTY: false })).toThrow(CliError);
    try {
      requireTerminal("add", {});
    } catch (e) {
      expect((e as CliError).exitCode).toBe(2);
      expect((e as Error).message).toContain(NOT_A_TERMINAL);
    }
    expect(() => requireTerminal("add", { isTTY: true })).not.toThrow();
  });

  it("vets, scopes, records and prints the sandbox wrapper (defaults accepted)", async () => {
    const { code, text, io } = await add("notes", ["", "", ""]);
    expect(code).toBe(0);
    expect(io.asked).toHaveLength(3);
    expect(text).toContain("Verdict: ok");
    const scopes = loadScopes();
    expect(scopes.servers.notes).toMatchObject({ tools: ["get_note", "search_notes"] });
    expect(scopes.servers.notes!.never).toBeUndefined(); // equal to defaults.never → inherited
    const raw = readFileSync(join(env.secorHome, "scopes.yaml"), "utf8");
    expect(raw).toContain("# added by secor connect add on 2026-10-10");
    const m = loadServers().servers.notes!;
    expect(m).toMatchObject({ transport: "stdio", approvedAt: "2026-10-10T12:00:00.000Z", addedAt: "2026-10-10T12:00:00.000Z", changed: false, changes: [], sandbox: "no", lastDriftCheck: "2026-10-10T12:00:00.000Z" });
    expect(m.vet).toMatchObject({ verdict: "ok", findings: [] });
    expect(Object.keys(m.toolHashes)).toEqual(["get_note", "search_notes"]);
    expect(m.source).toBe(`claude-code:project:${join(env.project, ".mcp.json")}`);
    expect(text).toContain("docker run --rm -i --init --read-only --tmpfs /tmp:rw,exec,nosuid,nodev,size=1g --tmpfs /root:rw,exec,nosuid,nodev,size=1g");
    expect(text).toContain("node:22-slim node");
    expect(text).toContain("--apply-sandbox");
    expect(text).toContain("Least privilege");
    // The editor config was not touched without --apply-sandbox.
    expect(discoverServers(env.project).find((s) => s.name === "notes")!.sandbox).toBe("no");
  });

  it("starts powerful tools unticked and lets the human toggle them", async () => {
    const { code, text } = await add("tools", ["1", "", "", ""]);
    expect(code).toBe(0);
    expect(text).toMatch(/\[ \]\s+1\s+delete_file\s+\(powerful\)/);
    expect(text).toMatch(/\[x\]\s+2\s+list_files/);
    expect(loadScopes().servers.tools!.tools).toEqual(["delete_file", "list_files"]);
  });

  it("records chosen data classes when they differ from the defaults", async () => {
    const { code } = await add("notes", ["", "4", "", ""]);
    expect(code).toBe(0);
    expect(loadScopes().servers.notes!.never).toEqual(["secret", "credential", "personal_data"]);
  });

  it("requires typing the name of a high-risk server", async () => {
    const wrong = await add("danger", ["danger please"]);
    expect(wrong.code).toBe(2);
    expect(wrong.text).toContain("Verdict: high-risk");
    expect(wrong.text).toContain("Not added");
    expect(existsSync(join(env.secorHome, "servers.json"))).toBe(false);
    expect(existsSync(join(env.secorHome, "scopes.yaml"))).toBe(false);
    const right = await add("danger", ["danger", "", "", ""]);
    expect(right.code).toBe(0);
    expect(loadServers().servers.danger!.vet!.verdict).toBe("high-risk");
  });

  it("checks name collisions against already managed servers", async () => {
    expect((await add("github", ["", "", ""])).code).toBe(0);
    const { code, text } = await add("collide", ["", "", ""]);
    expect(code).toBe(0);
    expect(text).toContain("vet/name-collision");
    expect(loadServers().servers.collide!.vet!.verdict).toBe("review");
  });

  it("applies the sandbox to the editor config when asked (backup first)", async () => {
    const { code, text } = await add("notes", ["", "", "~/projects/app"], { applySandbox: true });
    expect(code).toBe(0);
    expect(loadScopes().servers.notes!.sandbox).toEqual({ mounts: ["~/projects/app"] });
    const s = discoverServers(env.project).find((x) => x.name === "notes")!;
    expect(s.sandbox).toBe("yes");
    expect(s.args).toContain(`${join(env.home, "projects", "app")}:${join(env.home, "projects", "app")}:ro`);
    expect(loadServers().servers.notes!.sandbox).toBe("yes");
    expect(readdirSync(join(env.secorHome, "backups"))).toContain("20261010T120000Z-.mcp.json");
    expect(text).toContain("Restart your editor");
    // Other entries are untouched.
    expect(discoverServers(env.project).find((x) => x.name === "tools")!.command).toBe(process.execPath);
  });

  it("re-asks for mounts that are not absolute", async () => {
    const { code, text } = await add("notes", ["", "", "relative/dir", "/abs/dir"]);
    expect(code).toBe(0);
    expect(text).toContain("not an absolute path");
    expect(loadScopes().servers.notes!.sandbox).toEqual({ mounts: ["/abs/dir"] });
  });

  it("asks before adding a server whose vet was incomplete", async () => {
    const no = await add("remote", ["n"]);
    expect(no.code).toBe(2);
    expect(no.text).toContain("Verdict: incomplete");
    expect(existsSync(join(env.secorHome, "servers.json"))).toBe(false);
    const yes = await add("remote", ["y", ""]);
    expect(yes.code).toBe(0);
    expect(loadScopes().servers.remote!.tools).toBeUndefined();
    expect(loadServers().servers.remote).toMatchObject({ transport: "http", sandbox: "n/a", toolHashes: {}, lastDriftCheck: null });
    expect(yes.text).toContain("Least privilege");
  });

  it("keeps a scope the human already wrote and refuses servers that are already managed", async () => {
    mkdirSync(env.secorHome, { recursive: true });
    const scopes = "version: 1\nservers:\n  notes:\n    tools: [search_notes]  # mine\n";
    writeFileSync(join(env.secorHome, "scopes.yaml"), scopes);
    const first = await add("notes", []);
    expect(first.code).toBe(0);
    expect(first.text).toContain("Keeping your existing scope");
    expect(readFileSync(join(env.secorHome, "scopes.yaml"), "utf8")).toBe(scopes);
    const again = await add("notes", []);
    expect(again.code).toBe(2);
    expect(again.text).toContain("already managed");
  });

  it("stops when scopes.yaml is invalid, without writing", async () => {
    mkdirSync(env.secorHome, { recursive: true });
    writeFileSync(join(env.secorHome, "scopes.yaml"), "version: 1\nunknownKey: 1\n");
    const { code, text } = await add("notes", []);
    expect(code).toBe(2);
    expect(text).toContain("unknownKey");
    expect(existsSync(join(env.secorHome, "servers.json"))).toBe(false);
  });

  it("reports unknown and ambiguous names", async () => {
    expect((await add("nope", [])).text).toContain("No MCP server named");
    mkdirSync(join(env.project, ".cursor"), { recursive: true });
    writeFileSync(join(env.project, ".cursor", "mcp.json"), JSON.stringify({ mcpServers: { notes: { command: "node", args: ["other.js"] } } }));
    const amb = await add("notes", []);
    expect(amb.code).toBe(2);
    expect(amb.text).toContain("--source");
  });
});
