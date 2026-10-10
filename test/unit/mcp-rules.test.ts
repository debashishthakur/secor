// Focused tests for the mcp pack (spec 8.5, 8.8): patches apply cleanly, test templates render and parse, and edge
// cases that the fixture cases do not pin down (finding text, inline projects, determinism).

import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { initParsers, parseSource } from "../../src/engine/parse.js";
import { type LineEdit, applyEdits } from "../../src/engine/patch.js";
import { allRules } from "../../src/engine/rules/index.js";
import { fillTemplate, loadTemplate } from "../../src/engine/templates.js";
import type { Finding, RunResult } from "../../src/types.js";
import { FIXTURES, cleanup, runFixture } from "../helpers/fixtures.js";

const MCP = join(FIXTURES, "mcp");
const temps: string[] = [];
const savedEnv = { HOME: process.env.HOME, SECOR_HOME: process.env.SECOR_HOME };

beforeAll(async () => {
  const home = mkdtempSync(join(tmpdir(), "secor-mcp-home-"));
  temps.push(home);
  process.env.HOME = home;
  process.env.SECOR_HOME = join(home, ".secor");
  await initParsers();
});

afterAll(() => {
  process.env.HOME = savedEnv.HOME;
  if (savedEnv.SECOR_HOME === undefined) delete process.env.SECOR_HOME;
  else process.env.SECOR_HOME = savedEnv.SECOR_HOME;
  temps.forEach(cleanup);
});

async function run(dir: string, rule: string): Promise<{ result: RunResult; findings: Finding[]; root: string }> {
  const { result, root } = await runFixture(dir, { onlyRules: [rule] });
  temps.push(root);
  return { result, findings: result.findings.filter((f) => f.ruleId === rule), root };
}

/** A throwaway project from inline files. */
function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "secor-mcp-src-"));
  temps.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

/**
 * Turn a unified diff into line edits, asserting that every context and removed line matches the original
 * (the patch applies cleanly), so applyEdits can produce the patched file.
 */
function diffToEdits(original: string, patch: string): LineEdit[] {
  const lines = (original.endsWith("\n") ? original.slice(0, -1) : original).split("\n");
  const body = patch.split("\n");
  expect(body[0]).toMatch(/^--- a\//);
  expect(body[1]).toMatch(/^\+\+\+ b\//);
  const edits: LineEdit[] = [];
  let i = 2;
  while (i < body.length) {
    const h = /^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(body[i] ?? "");
    if (!h) {
      i++;
      continue;
    }
    let oldNo = Number(h[2]) === 0 ? Number(h[1]) + 1 : Number(h[1]);
    let removed = 0;
    let added = 0;
    let cur: LineEdit | null = null;
    i++;
    for (; i < body.length && !/^@@ /.test(body[i]!); i++) {
      const l = body[i]!;
      if (l === "" && i === body.length - 1) break;
      if (l.startsWith("\\")) continue;
      const kind = l[0];
      const text = l.slice(1);
      if (kind === " ") {
        expect(lines[oldNo - 1], `context line ${oldNo}`).toBe(text);
        if (cur) edits.push(cur);
        cur = null;
        oldNo++;
      } else if (kind === "-") {
        expect(lines[oldNo - 1], `removed line ${oldNo}`).toBe(text);
        cur ??= { startLine: oldNo, endLine: oldNo - 1, newLines: [] };
        cur.endLine = oldNo;
        oldNo++;
        removed++;
      } else if (kind === "+") {
        cur ??= { startLine: oldNo, endLine: oldNo - 1, newLines: [] };
        cur.newLines.push(text);
        added++;
      } else throw new Error(`bad diff line: ${l}`);
    }
    if (cur) edits.push(cur);
    expect(removed + added).toBeGreaterThan(0);
  }
  return edits;
}

function applyPatch(root: string, f: Finding): string {
  expect(f.fix.patch, "finding has a patch").toBeTruthy();
  const original = readFileSync(join(root, f.location.file), "utf8");
  return applyEdits(original, diffToEdits(original, f.fix.patch!));
}

function parsesTs(text: string): boolean {
  const tree = parseSource(text, "typescript");
  try {
    return !tree.rootNode.hasError;
  } finally {
    tree.delete();
  }
}

function parsesPy(text: string): boolean {
  const tree = parseSource(text, "python");
  try {
    return !tree.rootNode.hasError;
  } finally {
    tree.delete();
  }
}

// ---------------------------------------------------------------- registration

describe("mcp pack registration", () => {
  it("registers the five MCP rules with sources; only validated ones are stable", () => {
    const rules = allRules().filter((r) => r.pack === "mcp");
    expect(rules.map((r) => r.id).sort()).toEqual(["mcp/auth-required", "mcp/local-binding", "mcp/session-handling", "mcp/token-passthrough", "mcp/tool-scope"]);
    for (const r of rules) {
      expect(r.maturity).toBe(r.id === "mcp/tool-scope" ? "stable" : "experimental");
      expect(r.source?.url).toMatch(/^https:\/\//);
    }
  });
});

// ---------------------------------------------------------------- mcp/local-binding

describe("mcp/local-binding patches", () => {
  it("adds the loopback host to listen(port, callback) and lists both failing parts", async () => {
    const { findings, root } = await run(join(MCP, "local-binding/vulnerable/ts-listen-no-host"), "mcp/local-binding");
    expect(findings).toHaveLength(1);
    const f = findings[0]!;
    expect(f.evidence).toContain("(a) listens on all interfaces; (b) no Origin or Host validation");
    expect(f.fix.summary).toBe("Bind to 127.0.0.1 and validate the Origin header.");
    const patched = applyPatch(root, f);
    expect(patched).toContain('app.listen(3000, "127.0.0.1", () => {');
    expect(parsesTs(patched)).toBe(true);
  });

  it("adds the host to listen(PORT) and reports only (a) when createMcpExpressApp() validates Host", async () => {
    const { findings, root } = await run(join(MCP, "local-binding/vulnerable/ts-mcp-express-app"), "mcp/local-binding");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence).toContain("(a) listens on all interfaces");
    expect(findings[0]!.evidence).not.toContain("(b)");
    const patched = applyPatch(root, findings[0]!);
    expect(patched).toContain('app.listen(PORT, "127.0.0.1");');
    expect(parsesTs(patched)).toBe(true);
  });

  it("replaces 0.0.0.0 in FastMCP(host=...) and in an environment default", async () => {
    const a = await run(join(MCP, "local-binding/vulnerable/py-fastmcp-host"), "mcp/local-binding");
    const patchedA = applyPatch(a.root, a.findings[0]!);
    expect(patchedA).toContain('mcp = FastMCP("desktop-notes", host="127.0.0.1", port=8765)');
    expect(patchedA).not.toContain("0.0.0.0");
    expect(parsesPy(patchedA)).toBe(true);

    const b = await run(join(MCP, "local-binding/vulnerable/py-uvicorn-all"), "mcp/local-binding");
    expect(b.findings[0]!.evidence).not.toContain("(b)");
    const patchedB = applyPatch(b.root, b.findings[0]!);
    expect(patchedB).toContain('host=os.environ.get("HOST", "127.0.0.1")');
    expect(parsesPy(patchedB)).toBe(true);
  });

  it("patches exactly the host argument when the same literal appears earlier on the line", async () => {
    const dir = project({
      "package.json": JSON.stringify({ name: "x", type: "module", dependencies: { "@modelcontextprotocol/sdk": "1.30.1", express: "5.1.0" } }),
      "src/server.ts": [
        'import express from "express";',
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
        'import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";',
        'const server = new McpServer({ name: "x", version: "1.0.0" });',
        "const app = express();",
        'app.post("/mcp", async (req, res) => {',
        "  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });",
        "  await server.connect(transport);",
        "  await transport.handleRequest(req, res, req.body);",
        "});",
        'const label = "0.0.0.0 — héllo 😀"; const shown = "0.0.0.0"; app.listen(3000, "0.0.0.0");',
        "",
      ].join("\n"),
    });
    const { findings, root } = await run(dir, "mcp/local-binding");
    const patched = applyPatch(root, findings[0]!);
    expect(patched).toContain('const label = "0.0.0.0 — héllo 😀"; const shown = "0.0.0.0"; app.listen(3000, "127.0.0.1");');
    expect(parsesTs(patched)).toBe(true);
  });

  it("gives no patch when only Origin/Host validation is missing", async () => {
    const { findings } = await run(join(MCP, "local-binding/vulnerable/ts-only-origin"), "mcp/local-binding");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.evidence.startsWith("(b) no Origin or Host validation")).toBe(true);
    expect(findings[0]!.fix.patch).toBeUndefined();
  });

  it("gives no patch when two listeners bind all interfaces, and keeps the single quote style", async () => {
    const dir = project({
      "package.json": JSON.stringify({ name: "x", type: "module", dependencies: { "@modelcontextprotocol/sdk": "1.30.1", express: "5.1.0" } }),
      "src/server.ts": [
        "import express from 'express';",
        "import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';",
        "import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';",
        "const server = new McpServer({ name: 'x', version: '1.0.0' });",
        "const app = express();",
        "app.post('/mcp', async (req, res) => {",
        "  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });",
        "  await server.connect(transport);",
        "  await transport.handleRequest(req, res, req.body);",
        "});",
        "app.listen(3000);",
        "app.listen(3001, '::');",
        "",
      ].join("\n"),
    });
    const { findings } = await run(dir, "mcp/local-binding");
    expect(findings).toHaveLength(1);
    expect(findings[0]!.location.line).toBe(11);
    expect(findings[0]!.fix.patch).toBeUndefined();

    const single = project({
      "package.json": JSON.stringify({ name: "x", type: "module", dependencies: { "@modelcontextprotocol/sdk": "1.30.1", express: "5.1.0" } }),
      "src/server.ts": readFileSync(join(dir, "src/server.ts"), "utf8").replace("app.listen(3001, '::');\n", ""),
    });
    const s = await run(single, "mcp/local-binding");
    expect(applyPatch(s.root, s.findings[0]!)).toContain("app.listen(3000, '127.0.0.1');");
  });
});

// ---------------------------------------------------------------- mcp/session-handling

describe("mcp/session-handling patches", () => {
  it("replaces a Math.random generator with randomUUID and adds the import", async () => {
    const { findings, root } = await run(join(MCP, "session-handling/vulnerable/ts-math-random"), "mcp/session-handling");
    expect(findings).toHaveLength(1);
    const patched = applyPatch(root, findings[0]!);
    expect(patched).toContain("      sessionIdGenerator: () => randomUUID(),");
    expect(patched).toContain('import { randomUUID } from "node:crypto";');
    expect(patched).not.toContain("Math.random");
    expect(findings[0]!.fix.summary).toContain('import { randomUUID } from "node:crypto"');
    expect(parsesTs(patched)).toBe(true);
  });

  const pkg = JSON.stringify({ name: "x", type: "module", dependencies: { "@modelcontextprotocol/sdk": "1.30.1" } });
  const serverWith = (imports: string, generator: string) =>
    [
      imports,
      'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
      'import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";',
      'const server = new McpServer({ name: "x", version: "1.0.0" });',
      `const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: ${generator} });`,
      "await server.connect(transport);",
      "",
    ].join("\n");

  it("reuses an existing crypto import, flags Date.now and counters, and accepts strong generators", async () => {
    const ns = await run(project({ "package.json": pkg, "src/server.ts": serverWith('import crypto from "node:crypto";', "() => `${Date.now()}`") }), "mcp/session-handling");
    expect(ns.findings).toHaveLength(1);
    const patched = applyPatch(ns.root, ns.findings[0]!);
    expect(patched).toContain("sessionIdGenerator: () => crypto.randomUUID() }");
    expect(patched.match(/^import /gm)).toHaveLength(3);

    const counter = await run(project({ "package.json": pkg, "src/server.ts": serverWith("let n = 0;", "() => String(n++)") }), "mcp/session-handling");
    expect(counter.findings).toHaveLength(1);

    const literal = await run(project({ "package.json": pkg, "src/server.ts": serverWith("", '() => "session"') }), "mcp/session-handling");
    expect(literal.findings).toHaveLength(1);

    for (const strong of [
      ['import { randomBytes } from "node:crypto";', '() => randomBytes(16).toString("hex")'],
      ['import { v4 as uuidv4 } from "uuid";', "() => uuidv4()"],
      ['import { randomUUID } from "node:crypto";', "randomUUID"],
      ["", "() => crypto.randomUUID()"],
      ["", "undefined"],
    ]) {
      const r = await run(project({ "package.json": pkg, "src/server.ts": serverWith(strong[0]!, strong[1]!) }), "mcp/session-handling");
      expect(r.findings, strong[1]).toHaveLength(0);
    }

    const short = await run(project({ "package.json": pkg, "src/server.ts": serverWith('import { randomBytes } from "node:crypto";', '() => randomBytes(8).toString("hex")') }), "mcp/session-handling");
    expect(short.findings).toHaveLength(1);
  });

  it("gives no patch for a multi-line generator", async () => {
    const r = await run(project({ "package.json": pkg, "src/server.ts": serverWith("", "() => {\n  return Math.random().toString(36);\n}") }), "mcp/session-handling");
    expect(r.findings).toHaveLength(1);
    expect(r.findings[0]!.fix.patch).toBeUndefined();
  });
});

// ---------------------------------------------------------------- mcp/tool-scope templates

describe("mcp/tool-scope test templates", () => {
  it("renders the TS template for file findings, with the tool's argument name, and it parses", async () => {
    const { findings } = await run(join(MCP, "tool-scope/vulnerable/ts-file-access"), "mcp/tool-scope");
    expect(findings).toHaveLength(2);
    const byTool = new Map(findings.map((f) => [/read_note|save_note/.exec(f.fix.testTemplate ?? "")?.[0], f]));
    const read = byTool.get("read_note")!.fix.testTemplate!;
    const save = byTool.get("save_note")!.fix.testTemplate!;
    for (const t of [read, save]) {
      expect(t).not.toMatch(/\{\{|\}\}/);
      expect(t).toMatch(/^\/\/ Suggested location: tests\/secor\/mcp-tool-scope-[0-9a-f]{6}\.test\.ts\n/);
      expect(t).toContain('import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";');
      expect(t).toContain('import * as serverModule from "../../src/server";');
      expect(t).toContain('(serverModule as Record<string, unknown>)["server"]');
      expect(t).toContain("../outside.txt");
      expect(parsesTs(t)).toBe(true);
    }
    expect(read).toContain("const toolArguments = { path: target };");
    expect(save).toContain("const toolArguments = { name: target };");
  });

  it("renders the Python template for file findings only, and it parses", async () => {
    const { findings } = await run(join(MCP, "tool-scope/vulnerable/py-file-and-shell"), "mcp/tool-scope");
    const files = findings.filter((f) => f.fix.testTemplate);
    expect(files.map((f) => f.location.line).sort((a, b) => a - b)).toEqual([14, 28, 42]);
    expect(findings.filter((f) => !f.fix.testTemplate).every((f) => /subprocess|os\.system/.test(f.evidence))).toBe(true);
    for (const f of files) {
      const t = f.fix.testTemplate!;
      expect(t).not.toMatch(/\{\{|\}\}/);
      expect(t).toMatch(/^# Suggested location: tests\/secor\/test_mcp_tool_scope_[0-9a-f]{6}\.py\n/);
      expect(t).toContain("from mcp.shared.memory import create_connected_server_and_client_session");
      expect(t).toContain('importlib.import_module("server")');
      expect(t).toContain('getattr(module, "mcp")');
      expect(parsesPy(t)).toBe(true);
    }
    const keys = files.map((f) => /arguments = \{("\w+")/.exec(f.fix.testTemplate!)?.[1]).sort();
    expect(keys).toEqual(['"name"', '"path"', '"title"']);
  });

  it("picks the tool of the switch case for a low-level CallTool handler", async () => {
    const { findings } = await run(join(MCP, "tool-scope/vulnerable/ts-lowlevel-switch"), "mcp/tool-scope");
    expect(findings).toHaveLength(1);
    const t = findings[0]!.fix.testTemplate!;
    expect(t).toContain('name: "read_file"');
    expect(t).toContain("const toolArguments = { file: target };");
  });

  it("renders every Python flavour and the TS template without leftover placeholders, even with no values", () => {
    const py = loadTemplate("mcp/tool-scope", "mcp-py")!;
    const ts = loadTemplate("mcp/tool-scope", "mcp-ts")!;
    expect(py).toBeTruthy();
    expect(ts).toBeTruthy();
    const vars = { toolName: "read_file", importPath: "app.server", handlerExport: "mcp" };
    for (const flavour of ["mcp1", "mcp2", "fastmcp"]) {
      const out = fillTemplate(py, vars, new Set([flavour]));
      expect(out).not.toMatch(/\{\{|\}\}/);
      expect(parsesPy(out), flavour).toBe(true);
    }
    expect(fillTemplate(py, vars, new Set(["fastmcp"]))).toContain("except ToolError:");
    const bare = fillTemplate(ts, {});
    expect(bare).not.toMatch(/\{\{|\}\}/);
    expect(bare).toContain("TODO(secor): toolName");
    expect(parsesTs(bare)).toBe(true);
    expect(parsesPy(fillTemplate(py, {}, new Set(["mcp1"])))).toBe(true);
  });
});

// ---------------------------------------------------------------- inline edge cases

describe("mcp rules: edge cases", () => {
  const tsPkg = JSON.stringify({ name: "x", type: "module", dependencies: { "@modelcontextprotocol/sdk": "1.30.1", express: "5.1.0", zod: "3.25.76" } });

  it("tool-scope follows tool input into a same-file helper and respects a check in the caller", async () => {
    const files = (check: string) => ({
      "package.json": tsPkg,
      "src/server.ts": [
        'import fs from "node:fs";',
        'import path from "node:path";',
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
        'import { z } from "zod";',
        'const ROOT = path.resolve("data");',
        'const server = new McpServer({ name: "x", version: "1.0.0" });',
        "function load(p: string) {",
        '  return fs.readFileSync(p, "utf8");',
        "}",
        'server.tool("load", { file: z.string() }, async ({ file }) => {',
        "  const full = path.resolve(ROOT, file);",
        check,
        '  return { content: [{ type: "text", text: load(full) }] };',
        "});",
        "",
      ].join("\n"),
    });
    const open = await run(project(files("")), "mcp/tool-scope");
    expect(open.findings.map((f) => [f.severity, f.location.line])).toEqual([["high", 8]]);
    const checked = await run(project(files('  if (!full.startsWith(ROOT + path.sep)) throw new Error("outside");')), "mcp/tool-scope");
    expect(checked.findings).toHaveLength(0);
  });

  it("tool-scope does not treat the request metadata of a schema-less tool as input", async () => {
    const r = await run(
      project({
        "package.json": tsPkg,
        "src/server.ts": [
          'import fs from "node:fs";',
          'import path from "node:path";',
          'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
          'import { z } from "zod";',
          'const server = new McpServer({ name: "x", version: "1.0.0" });',
          'server.tool("session_log", async (extra) => ({ content: [{ type: "text", text: fs.readFileSync(path.join("logs", String(extra.sessionId)), "utf8") }] }));',
          'server.registerTool("ping", { description: "Ping" }, async (extra) => ({ content: [{ type: "text", text: fs.readFileSync(String(extra.requestId), "utf8") }] }));',
          'server.tool("read", "Read a file", { file: z.string() }, async ({ file }) => ({ content: [{ type: "text", text: fs.readFileSync(file, "utf8") }] }));',
          "",
        ].join("\n"),
      }),
      "mcp/tool-scope",
    );
    expect(r.findings.map((f) => f.location.line)).toEqual([8]);
  });

  it("tool-scope treats shlex.quote as neutralising the shell, but still reports input-derived arguments", async () => {
    const r = await run(
      project({
        "requirements.txt": "mcp>=1.23\n",
        "server.py": [
          "import shlex",
          "import subprocess",
          "from mcp.server.fastmcp import FastMCP",
          'mcp = FastMCP("x")',
          "@mcp.tool()",
          "def grep(pattern: str) -> str:",
          '    return subprocess.run(f"grep -r {shlex.quote(pattern)} .", shell=True, capture_output=True).stdout',
          "@mcp.tool()",
          "def tail(name: str) -> str:",
          '    return subprocess.check_output(["sh", "-c", f"tail -n 5 {name}"])',
          "mcp.run()",
          "",
        ].join("\n"),
      }),
      "mcp/tool-scope",
    );
    expect(r.findings.map((f) => [f.severity, f.location.line])).toEqual([
      ["critical", 10],
      ["high", 7],
    ]);
  });

  it("token-passthrough flags forwarding the whole incoming header set, not other headers", async () => {
    const r = await run(
      project({
        "package.json": tsPkg,
        "src/server.ts": [
          'import express from "express";',
          'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
          'import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";',
          'const server = new McpServer({ name: "x", version: "1.0.0" });',
          "const app = express();",
          'app.get("/proxy", async (req, res) => {',
          '  const upstream = await fetch("https://api.example.com/data", { headers: { ...req.headers, host: "api.example.com" } });',
          '  const trace = await fetch("https://api.example.com/trace", { headers: { "x-trace": String(req.headers["x-trace-id"]) } });',
          "  res.json({ a: await upstream.json(), b: trace.status });",
          "});",
          'app.post("/mcp", async (req, res) => {',
          "  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });",
          "  await server.connect(transport);",
          "  await transport.handleRequest(req, res, req.body);",
          "});",
          'app.listen(3000, "127.0.0.1");',
          "",
        ].join("\n"),
      }),
      "mcp/token-passthrough",
    );
    expect(r.findings.map((f) => f.location.line)).toEqual([7]);
  });

  it("auth-required accepts app.use(guard) before the MCP route, and reports when the guard comes after it", async () => {
    const files = (before: boolean) => ({
      "package.json": tsPkg,
      Dockerfile: "FROM node:24-slim\n",
      "src/server.ts": [
        'import express from "express";',
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
        'import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";',
        'import { requireAuth } from "./auth.js";',
        'const server = new McpServer({ name: "x", version: "1.0.0" });',
        "const app = express();",
        before ? "app.use(requireAuth);" : "",
        'app.post("/mcp", async (req, res) => {',
        "  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });",
        "  await server.connect(transport);",
        "  await transport.handleRequest(req, res, req.body);",
        "});",
        before ? "" : "app.use(requireAuth);",
        "app.listen(8080);",
        "",
      ].join("\n"),
      "src/auth.ts": "export function requireAuth(req: any, res: any, next: any) { next(); }\n",
    });
    expect((await run(project(files(true)), "mcp/auth-required")).findings).toHaveLength(0);
    const after = await run(project(files(false)), "mcp/auth-required");
    expect(after.findings.map((f) => [f.severity, f.location.line])).toEqual([["critical", 5]]);
  });

  it("auth-required accepts a known auth middleware package (express-oauth2-jwt-bearer) and still reports without it", async () => {
    const files = (useAuth: boolean) => ({
      "package.json": JSON.stringify({ name: "x", type: "module", dependencies: { "@modelcontextprotocol/sdk": "1.30.1", express: "5.1.0", "express-oauth2-jwt-bearer": "1.6.1" } }),
      "fly.toml": 'app = "x"\n',
      "src/server.ts": [
        'import express from "express";',
        'import { auth } from "express-oauth2-jwt-bearer";',
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
        'import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";',
        'const server = new McpServer({ name: "x", version: "1.0.0" });',
        "const app = express();",
        useAuth ? 'app.use(auth({ audience: "https://mcp.example.com", issuerBaseURL: "https://example.eu.auth0.com/" }));' : "",
        'app.post("/mcp", async (req, res) => {',
        "  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });",
        "  await server.connect(transport);",
        "  await transport.handleRequest(req, res, req.body);",
        "});",
        "app.listen(8080);",
        "",
      ].join("\n"),
    });
    expect((await run(project(files(true)), "mcp/auth-required")).findings).toHaveLength(0);
    expect((await run(project(files(false)), "mcp/auth-required")).findings).toHaveLength(1);
  });

  it("token-passthrough does not report validating the token at its authorization server (userinfo)", async () => {
    const r = await run(
      project({
        "package.json": tsPkg,
        "src/server.ts": [
          'import express from "express";',
          'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
          'import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";',
          'const server = new McpServer({ name: "x", version: "1.0.0" });',
          "const app = express();",
          "app.use(async (req, res, next) => {",
          "  const auth = req.headers.authorization ?? \"\";",
          '  const check = await fetch("https://example.eu.auth0.com/userinfo", { headers: { Authorization: auth } });',
          "  if (!check.ok) return res.status(401).end();",
          '  const repos = await fetch("https://api.github.com/user/repos", { headers: { Authorization: auth } });',
          "  res.locals.repos = await repos.json();",
          "  next();",
          "});",
          'app.post("/mcp", async (req, res) => {',
          "  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });",
          "  await server.connect(transport);",
          "  await transport.handleRequest(req, res, req.body);",
          "});",
          'app.listen(3000, "127.0.0.1");',
          "",
        ].join("\n"),
      }),
      "mcp/token-passthrough",
    );
    expect(r.findings.map((f) => f.location.line)).toEqual([10]);
  });

  it("token-passthrough follows a headers variable built from the incoming header set (Python)", async () => {
    const r = await run(
      project({
        "requirements.txt": "mcp>=1.23\nhttpx>=0.28\n",
        "server.py": [
          "import httpx",
          "from mcp.server.fastmcp import Context, FastMCP",
          'mcp = FastMCP("x")',
          "@mcp.tool()",
          "async def fetch_profile(ctx: Context) -> str:",
          "    request = ctx.request_context.request",
          "    headers = dict(request.headers)",
          '    resp = httpx.get("https://api.example.com/me", headers=headers)',
          "    return resp.text",
          'mcp.run(transport="sse")',
          "",
        ].join("\n"),
      }),
      "mcp/token-passthrough",
    );
    expect(r.findings.map((f) => [f.severity, f.location.line])).toEqual([["critical", 8]]);
  });

  it("local-binding reports a listener in the file that serves MCP before an auxiliary one", async () => {
    const pkg = JSON.stringify({ name: "x", type: "module", dependencies: { "@modelcontextprotocol/sdk": "1.30.1", express: "5.1.0" } });
    const r = await run(
      project({
        "package.json": pkg,
        "src/a-oauth.ts": 'import express from "express";\nconst authApp = express();\nauthApp.listen(3001);\n',
        "src/server.ts": [
          'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
          'import { createMcpExpressApp } from "@modelcontextprotocol/sdk/server/express.js";',
          'import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";',
          'const server = new McpServer({ name: "x", version: "1.0.0" });',
          "const app = createMcpExpressApp();",
          'app.post("/mcp", async (req, res) => {',
          "  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });",
          "  await server.connect(transport);",
          "  await transport.handleRequest(req, res, req.body);",
          "});",
          "app.listen(3000);",
          "",
        ].join("\n"),
      }),
      "mcp/local-binding",
    );
    expect(r.findings.map((f) => `${f.location.file}:${f.location.line}`)).toEqual(["src/server.ts:11"]);
    expect(r.findings[0]!.fix.patch).toBeUndefined();
  });

  it("local-binding counts an Origin comparison as validation, but not a Host header used to build a URL", async () => {
    const pkg = JSON.stringify({ name: "x", type: "module", dependencies: { "@modelcontextprotocol/sdk": "1.30.1" } });
    const server = (middleware: string) =>
      [
        'import http from "node:http";',
        'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
        'import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";',
        'const server = new McpServer({ name: "x", version: "1.0.0" });',
        'const ALLOWED_ORIGINS = ["http://localhost:3000"];',
        "const httpServer = http.createServer(async (req, res) => {",
        middleware,
        "  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });",
        "  await server.connect(transport);",
        "  await transport.handleRequest(req, res);",
        "});",
        'httpServer.listen(3000, "127.0.0.1");',
        "",
      ].join("\n");
    const checked = await run(
      project({
        "package.json": pkg,
        "src/server.ts": server('  const origin = req.headers.origin;\n  if (origin && !ALLOWED_ORIGINS.includes(origin)) { res.writeHead(403).end(); return; }'),
      }),
      "mcp/local-binding",
    );
    expect(checked.findings).toHaveLength(0);
    const urlOnly = await run(
      project({
        "package.json": pkg,
        "src/server.ts": server('  const url = new URL(req.url ?? "/", `http://${req.headers.host}`);\n  if (url.pathname !== "/mcp") { res.writeHead(404).end(); throw new Error("not found"); }'),
      }),
      "mcp/local-binding",
    );
    expect(urlOnly.findings.map((f) => f.evidence.split(":")[0])).toEqual(["(b) no Origin or Host validation"]);
  });

  it("auth-required ignores credential words in comments when the handler does not read a credential", async () => {
    const r = await run(
      project({
        "package.json": tsPkg,
        Dockerfile: "FROM node:24-slim\n",
        "src/server.ts": [
          'import express from "express";',
          'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";',
          'import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";',
          'const server = new McpServer({ name: "x", version: "1.0.0" });',
          "const app = express();",
          'app.post("/mcp", async (req, res) => {',
          "  // TODO: add bearer token auth (Authorization header) before launch",
          '  if (req.headers["content-type"] !== "application/json") return res.status(403).end();',
          "  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });",
          "  await server.connect(transport);",
          "  await transport.handleRequest(req, res, req.body);",
          "});",
          "app.listen(8080);",
          "",
        ].join("\n"),
      }),
      "mcp/auth-required",
    );
    expect(r.findings.map((f) => [f.severity, f.location.line])).toEqual([["critical", 4]]);
  });

  it("findings are identical across runs (determinism)", async () => {
    const strip = (fs: Finding[]) => JSON.stringify(fs);
    for (const [dir, rule] of [
      ["tool-scope/vulnerable/py-file-and-shell", "mcp/tool-scope"],
      ["local-binding/vulnerable/ts-listen-no-host", "mcp/local-binding"],
      ["session-handling/vulnerable/py-weak-session", "mcp/session-handling"],
    ] as const) {
      const a = await run(join(MCP, dir), rule);
      const b = await run(join(MCP, dir), rule);
      expect(strip(a.findings)).toBe(strip(b.findings));
    }
  });
});

