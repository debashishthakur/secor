// Server discovery (spec 9.1) with a temp HOME: every config location, ${VAR} expansion, http vs stdio,
// duplicate names that need --source, and source strings that round-trip for drift.

import { mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { connectListText } from "../../src/cli/connect.js";
import { definitionKey, discoverServers, expandVars, findServer, serverFromSource, specFromSource } from "../../src/connect/discover.js";
import { FAKES, type TempEnv, tempEnv } from "../connect/helpers.js";

function write(path: string, data: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  // "__proto__" cannot be written as an object-literal key, so it goes in as a placeholder.
  writeFileSync(path, typeof data === "string" ? data : JSON.stringify(data, null, 2).replace('"__PROTO_KEY__"', '"__proto__"'));
}

let env: TempEnv;
const saved: Record<string, string | undefined> = {};
beforeEach(() => {
  env = tempEnv();
  for (const k of ["GH_ORG", "GH_TOKEN", "API_KEY", "EMPTY_VAR"]) saved[k] = process.env[k];
  process.env.GH_ORG = "acme";
  process.env.GH_TOKEN = FAKES.GITHUB!;
  delete process.env.API_KEY;
  process.env.EMPTY_VAR = "";
});
afterEach(() => {
  for (const [k, v] of Object.entries(saved)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  env.restore();
});

function writeAllConfigs(): void {
  write(join(env.project, ".mcp.json"), {
    mcpServers: {
      github: { command: "npx", args: ["-y", "@acme/github-mcp", "--org=${GH_ORG}"], env: { GITHUB_TOKEN: "${GH_TOKEN}" } },
      remote: { url: "https://mcp.example.com/mcp", headers: { Authorization: "Bearer ${API_KEY:-unset-key}" } },
      legacy: { type: "sse", url: "https://legacy.example.com/sse" },
      streamy: { type: "streamable-http", url: "https://s.example.com/mcp" },
      constructor: { command: "node", args: ["c.js"] },
      __PROTO_KEY__: { command: "node", args: ["evil.js"] },
      broken: { args: ["no command"] },
    },
  });
  write(join(env.home, ".claude.json"), {
    mcpServers: { userwide: { type: "stdio", command: "uvx", args: ["mcp-server-time"] } },
    projects: { [env.project]: { mcpServers: { localonly: { type: "http", url: "http://localhost:3000/mcp" } } }, "/some/other/project": { mcpServers: { elsewhere: { command: "node" } } } },
  });
  write(join(env.home, ".cursor", "mcp.json"), { mcpServers: { github: { command: "npx", args: ["-y", "@other/github"] } } });
  write(join(env.project, ".cursor", "mcp.json"), { mcpServers: { cursorproj: { command: "node", args: ["server.js"] } } });
  write(join(env.project, ".vscode", "mcp.json"), `{
  // VS Code uses "servers", and allows comments and trailing commas
  "servers": {
    "vsnotes": { "type": "http", "url": "https://vs.example.com/mcp", },
    "vslocal": { "command": "python", "args": ["-m", "notes_server"], },
  },
  "inputs": [],
}`);
  if (process.platform === "darwin") {
    write(join(env.home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), { mcpServers: { desktop: { command: "docker", args: ["run", "-i", "--rm", "mcp/time"] } } });
  }
}

describe("discovery", () => {
  it("expands ${VAR} and ${VAR:-default}; unset variables without a default stay as written", () => {
    expect(expandVars("${GH_ORG}/x")).toBe("acme/x");
    expect(expandVars("${API_KEY:-fallback}")).toBe("fallback");
    expect(expandVars("${EMPTY_VAR:-d}")).toBe("d");
    expect(expandVars("${NOT_SET_ANYWHERE}")).toBe("${NOT_SET_ANYWHERE}");
    expect(expandVars("$GH_ORG and ${GH_ORG")).toBe("$GH_ORG and ${GH_ORG");
  });

  it("reads all six config locations with their keys", () => {
    writeAllConfigs();
    const all = discoverServers(env.project);
    const by = (name: string) => all.filter((s) => s.name === name);
    expect(by("github").map((s) => s.source)).toEqual([`claude-code:project:${join(env.project, ".mcp.json")}`, `cursor:user:${join(env.home, ".cursor", "mcp.json")}`]);
    expect(by("localonly")[0]!.source).toBe(`claude-code:local:${join(env.home, ".claude.json")}#${env.project}`);
    expect(by("userwide")[0]!.source).toBe(`claude-code:user:${join(env.home, ".claude.json")}`);
    expect(by("cursorproj")[0]!.source).toBe(`cursor:project:${join(env.project, ".cursor", "mcp.json")}`);
    expect(by("vsnotes")[0]!.source).toBe(`vscode:project:${join(env.project, ".vscode", "mcp.json")}`);
    expect(by("vslocal")[0]!.transport).toBe("stdio");
    expect(by("elsewhere")).toEqual([]); // another project's local servers are not this project's
    expect(by("broken")).toEqual([]);
    expect(by("__proto__")).toEqual([]);
    expect(by("constructor")).toHaveLength(1);
    if (process.platform === "darwin") {
      const d = by("desktop")[0]!;
      expect(d.editor).toBe("claude-desktop");
      expect(d.sandbox).toBe("yes");
    }
    // Sorted by name, then source.
    const names = all.map((s) => `${s.name}\u0000${s.source}`);
    expect([...names].sort()).toEqual(names);
  });

  it("classifies http vs stdio and expands values", () => {
    writeAllConfigs();
    const all = discoverServers(env.project);
    const get = (name: string) => all.find((s) => s.name === name)!;
    const gh = get("github");
    expect(gh).toMatchObject({ transport: "stdio", command: "npx", args: ["-y", "@acme/github-mcp", "--org=acme"], sandbox: "no" });
    expect(gh.env).toEqual({ GITHUB_TOKEN: FAKES.GITHUB });
    expect(get("remote")).toMatchObject({ transport: "http", type: "http", url: "https://mcp.example.com/mcp", sandbox: "n/a" });
    expect(get("remote").headers).toEqual({ Authorization: "Bearer unset-key" });
    expect(get("legacy")).toMatchObject({ transport: "http", type: "sse" });
    expect(get("streamy")).toMatchObject({ transport: "http", type: "streamable-http" });
    expect(get("localonly")).toMatchObject({ transport: "http", type: "http" });
    expect(get("userwide")).toMatchObject({ transport: "stdio", command: "uvx" });
    expect(gh.keyPath).toEqual(["mcpServers", "github"]);
    expect(get("localonly").keyPath).toEqual(["projects", env.project, "mcpServers", "localonly"]);
    expect(get("vsnotes").keyPath).toEqual(["servers", "vsnotes"]);
  });

  it("needs --source when a name is defined differently in two places", () => {
    writeAllConfigs();
    const all = discoverServers(env.project);
    const ambiguous = findServer(all, "github");
    expect(ambiguous.server).toBeUndefined();
    expect(ambiguous.error).toContain("--source");
    expect(ambiguous.error).toContain(`cursor:user:${join(env.home, ".cursor", "mcp.json")}`);
    const picked = findServer(all, "github", `cursor:user:${join(env.home, ".cursor", "mcp.json")}`);
    expect(picked.server?.args).toEqual(["-y", "@other/github"]);
    expect(findServer(all, "nope").error).toContain("No MCP server named");
  });

  it("treats identical definitions in two places as one server", () => {
    write(join(env.project, ".mcp.json"), { mcpServers: { same: { command: "node", args: ["s.js"] } } });
    write(join(env.project, ".cursor", "mcp.json"), { mcpServers: { same: { command: "node", args: ["s.js"] } } });
    const all = discoverServers(env.project);
    expect(all.filter((s) => s.name === "same")).toHaveLength(2);
    expect(findServer(all, "same").server).toBeDefined();
  });

  it("counts different env values as different definitions, without keeping the values", () => {
    write(join(env.project, ".mcp.json"), { mcpServers: { s: { command: "node", env: { T: "aaaaaaaaaaaa" } } } });
    write(join(env.project, ".cursor", "mcp.json"), { mcpServers: { s: { command: "node", env: { T: "bbbbbbbbbbbb" } } } });
    const all = discoverServers(env.project);
    expect(findServer(all, "s").error).toContain("--source");
    for (const s of all) expect(definitionKey(s)).not.toMatch(/aaaa|bbbb/);
  });

  it("round-trips every source string (used by drift and approve)", () => {
    writeAllConfigs();
    for (const s of discoverServers(env.project)) {
      expect(specFromSource(s.source), s.source).not.toBeNull();
      expect(serverFromSource(s.name, s.source)).toEqual(s);
    }
    expect(specFromSource("bogus:thing:/x")).toBeNull();
    expect(specFromSource(`claude-code:local:${join(env.home, ".claude.json")}`)).toBeNull();
    expect(serverFromSource("github", `claude-code:project:${join(env.project, "missing.json")}`)).toBeNull();
  });

  it("uses the real path of the project for ~/.claude.json local entries", () => {
    const link = join(env.home, "proj-link");
    symlinkSync(env.project, link);
    write(join(env.home, ".claude.json"), { projects: { [env.project]: { mcpServers: { viaLink: { command: "node" } } } } });
    expect(discoverServers(link).map((s) => s.name)).toEqual(["viaLink"]);
  });

  it("connect list shows servers without env or header values", async () => {
    writeAllConfigs();
    const text = await connectListText(env.project);
    expect(text).toContain("github");
    expect(text).toContain("unmanaged");
    expect(text).toContain("Hooks: off");
    expect(text).not.toContain(FAKES.GITHUB!);
    expect(text).not.toContain("unset-key");
    expect(text).not.toContain("@acme/github-mcp");
  });
});
