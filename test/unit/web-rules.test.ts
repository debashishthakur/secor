// Cross-cutting checks for the web pack: rule metadata, coverage gaps, determinism, redaction, and the
// client-reachable file graph.

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { clientGraph, isKnownServerFile, runtimeImports, viteEntries } from "../../src/engine/client-graph.js";
import { defaultConfig } from "../../src/engine/config.js";
import { ProjectContext } from "../../src/engine/context.js";
import { detectUnits } from "../../src/engine/detect.js";
import { listFiles } from "../../src/engine/files.js";
import { initParsers } from "../../src/engine/parse.js";
import { clientSecretSeverity, evidenceAround } from "../../src/engine/rules/web/client-secrets.js";
import { isRoleCondition, normaliseUrl, pathMatches, roleGatedSubtrees } from "../../src/engine/rules/web/client-only-checks.js";
import { webRules } from "../../src/engine/rules/web/index.js";
import { parseCsp, parseHeadersFile } from "../../src/engine/rules/web/security-headers.js";
import { serviceFor } from "../../src/engine/rules/web/util.js";
import { runShip } from "../../src/ship/run.js";
import { cleanup, FAKE, listCases, mockNet, prepareFixture } from "../helpers/fixtures.js";

const temp: string[] = [];
afterAll(() => temp.forEach(cleanup));

function project(files: Record<string, string>): string {
  const root = mkdtempSync(join(tmpdir(), "secor-web-"));
  temp.push(root);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
  return root;
}

async function context(root: string): Promise<ProjectContext> {
  await initParsers();
  const listing = listFiles(root, []);
  const ctx = new ProjectContext({ root, name: "t", config: defaultConfig(), files: listing.files, git: listing.git, packs: new Set(["core", "web", "api"]), network: false, net: mockNet({}), runStartedAt: new Date(0) });
  ctx.detection = detectUnits({ files: ctx.files, read: (f) => ctx.read(f), mcpDeployment: "auto" });
  ctx.units = ctx.detection.units;
  return ctx;
}

describe("web rules metadata", () => {
  it("registers the six spec rules as web-pack rules; only validated ones are stable", () => {
    expect(webRules.map((r) => r.id).sort()).toEqual(["web/client-only-checks", "web/client-secrets", "web/cookie-flags", "web/database-rules", "web/production-debug", "web/security-headers"]);
    for (const r of webRules) {
      expect(r.pack).toBe("web");
      expect(r.maturity).toBe(r.id === "web/security-headers" ? "stable" : "experimental");
      expect(r.title).not.toMatch(/\b(?:secure|safe|passed)\b/i);
    }
  });
});

describe("web/database-rules coverage", () => {
  it("is applicable but not ran without migrations or rules files, with the spec's notChecked entry", async () => {
    const root = project({ "package.json": JSON.stringify({ name: "x", dependencies: { "@supabase/supabase-js": "2.45.0" } }) });
    const { result } = await runShip({ root, write: false, offline: true, onlyRules: ["web/database-rules"] });
    expect(result.coverage.applicable).toBe(1);
    expect(result.coverage.ran).toBe(0);
    expect(result.coverage.notChecked).toContainEqual({ area: "Database rules", reason: "no Supabase migrations or Firebase rules files in the repo" });
  });

  it("records a partial gap when one detected backend has no files", async () => {
    const root = project({
      "package.json": JSON.stringify({ name: "x", dependencies: { "@supabase/supabase-js": "2.45.0", firebase: "10.0.0" } }),
      "firestore.rules": "service cloud.firestore { match /databases/{db}/documents { match /x/{id} { allow read: if false; } } }\n",
    });
    const { result } = await runShip({ root, write: false, offline: true, onlyRules: ["web/database-rules"] });
    expect(result.coverage.ran).toBe(1);
    expect(result.coverage.notChecked).toContainEqual({ area: "Database rules", reason: "no Supabase migrations in the repo" });
  });

  it("does not apply without Supabase or Firebase", async () => {
    const root = project({ "package.json": JSON.stringify({ name: "x", dependencies: { express: "4.19.2" } }) });
    const { result } = await runShip({ root, write: false, offline: true, onlyRules: ["web/database-rules"] });
    expect(result.coverage.applicable).toBe(0);
  });
});

describe("web fixtures: determinism and redaction", () => {
  const cases = listCases().filter((c) => c.name.startsWith("web/") && c.variant === "vulnerable");
  const fakeValues = Object.values(FAKE).flatMap((v) => [v, ...v.split("\n").filter((l) => l.length >= 16)]);

  for (const c of cases) {
    it(c.name, async () => {
      const a = prepareFixture(c.dir);
      const b = prepareFixture(c.dir);
      temp.push(a, b);
      const ra = await runShip({ root: a, write: false, offline: true, onlyRules: [c.spec.rule] });
      const rb = await runShip({ root: b, write: false, offline: true, onlyRules: [c.spec.rule] });
      const strip = (r: typeof ra) => JSON.stringify(r.result.findings).split(r.result.project.root).join("<root>");
      expect(strip(ra)).toBe(strip(rb));
      const json = JSON.stringify(ra.result.findings);
      for (const v of fakeValues) expect(json.includes(v), `a fake secret appears unredacted in ${c.name}`).toBe(false);
      for (const f of ra.result.findings) {
        expect(f.evidence.length).toBeLessThanOrEqual(200);
        expect(f.evidence).not.toContain("\n");
        // Invariant 5: no verdict wording ("secure" / "safe" / "passed" about the system); cookie flag names are fine.
        const prose = `${f.fix.summary} ${f.why} ${f.fix.humanAction ?? ""}`;
        expect(prose).not.toMatch(/\b(?:is|are|now|looks|considered)\s+(?:secure|safe)\b|\bpassed\b/i);
      }
    });
  }
});

describe("client-reachable graph", () => {
  it("follows use-client files through tsconfig paths, skips server-only modules and type-only imports", async () => {
    const root = project({
      "package.json": JSON.stringify({ name: "x", dependencies: { next: "15.0.0" } }),
      "tsconfig.json": JSON.stringify({ compilerOptions: { baseUrl: ".", paths: { "~/*": ["./src/*"] } } }),
      "src/app/page.tsx": 'import "~/lib/server";\nexport default function P() { return null; }\n',
      "src/components/A.tsx": '"use client";\nimport { b } from "~/lib/b";\nimport type { T } from "~/lib/types";\nimport { act } from "~/app/actions";\nconst L = () => import("./Lazy");\nexport * from "./reexported";\n',
      "src/components/Lazy.tsx": "export default 1;\n",
      "src/components/reexported.ts": "export const r = 1;\n",
      "src/lib/b.ts": 'import data from "./data.json";\nexport const b = data;\n',
      "src/lib/data.json": "{}\n",
      "src/lib/types.ts": "export type T = string;\n",
      "src/lib/server.ts": 'import "server-only";\nexport const s = 1;\n',
      "src/app/actions.ts": '"use server";\nexport async function act() {}\n',
      "src/app/api/x/route.ts": "export async function GET() { return new Response(); }\n",
    });
    const ctx = await context(root);
    const web = ctx.unitsOf("web")[0]!;
    const g = clientGraph(ctx, web);
    expect(g.seeds).toEqual(["src/components/A.tsx"]);
    expect(g.files).toEqual(["src/components/A.tsx", "src/components/Lazy.tsx", "src/components/reexported.ts", "src/lib/b.ts", "src/lib/data.json"]);
    expect(isKnownServerFile(ctx, web, "src/app/api/x/route.ts")).toBe(true);
    expect(isKnownServerFile(ctx, web, "src/app/actions.ts")).toBe(true);
    expect(isKnownServerFile(ctx, web, "src/lib/server.ts")).toBe(true);
    expect(isKnownServerFile(ctx, web, "src/lib/b.ts")).toBe(false);
    const pf = ctx.parse("src/components/A.tsx")!;
    expect(runtimeImports(pf).map((i) => i.spec)).toEqual(["~/lib/b", "~/app/actions", "./Lazy", "./reexported"]);
    ctx.dispose();
  });

  it("starts Vite graphs at index.html script entries", async () => {
    const root = project({
      "package.json": JSON.stringify({ name: "x", devDependencies: { vite: "5.0.0" } }),
      "index.html": '<script type="module" src="/src/main.ts"></script>\n<script src="https://cdn.example.org/x.js"></script>\n<!-- <script src="/src/old.ts"></script> -->\n',
      "src/main.ts": 'import "./a";\n',
      "src/a.ts": "export {};\n",
      "src/old.ts": "export {};\n",
    });
    const ctx = await context(root);
    const web = ctx.unitsOf("web")[0]!;
    expect(viteEntries(ctx, web)).toEqual(["src/main.ts"]);
    expect(clientGraph(ctx, web).files).toEqual(["src/a.ts", "src/main.ts"]);
    ctx.dispose();
  });

  it("attributes findings to api only when the file sits in an api-only unit", async () => {
    const root = project({
      "package.json": JSON.stringify({ name: "x", dependencies: { next: "15.0.0" } }),
      "app/page.tsx": "export default function P() { return null; }\n",
      "server/package.json": JSON.stringify({ name: "s", dependencies: { express: "4.19.2" } }),
      "server/index.js": "module.exports = 1;\n",
    });
    const ctx = await context(root);
    expect(serviceFor(ctx, "app/page.tsx")).toBe("web");
    expect(serviceFor(ctx, "server/index.js")).toBe("api");
    expect(serviceFor(ctx, "elsewhere.txt")).toBe("web");
    ctx.dispose();
  });
});

describe("client-secrets helpers", () => {
  it("keeps detector severities below high and raises the rest to critical", () => {
    const base = { class: "secret" as const, kind: "x", label: "x", start: 0, end: 1, value: "v", valueStart: 0 };
    expect(clientSecretSeverity({ ...base, severity: "low" })).toBe("low");
    expect(clientSecretSeverity({ ...base, severity: "medium" })).toBe("medium");
    expect(clientSecretSeverity({ ...base, severity: "high" })).toBe("critical");
    expect(clientSecretSeverity({ ...base })).toBe("critical");
  });

  it("windows long minified lines only after redacting them", () => {
    const secret = FAKE.SERVICE_ROLE_JWT!;
    const other = FAKE.OPENAI!;
    const line = `${"a".repeat(300)}var x="${other}";${"b".repeat(40)}var k="${secret}";${"c".repeat(300)}`;
    const start = line.indexOf(secret);
    const ev = evidenceAround(line, { start, end: start + secret.length, value: secret, prefix: "eyJ" });
    expect(ev).toContain("eyJ…");
    expect(ev).not.toContain(secret);
    expect(ev).not.toContain(other.slice(0, 20));
    expect(ev.length).toBeLessThan(260);
  });
});

describe("client-only-checks helpers", () => {
  it("matches request paths against inventory paths, preferring literal segments", () => {
    expect(pathMatches("/api/users/:p", "/api/users/:id")).toBe(2);
    expect(pathMatches("/api/users/me", "/api/users/:id")).toBe(2);
    expect(pathMatches("/api/users/me", "/api/users/me")).toBe(3);
    expect(pathMatches("/api/users/1/posts", "/api/users/:id")).toBe(-1);
    expect(pathMatches("/api/files/a/b", "/api/files/:path*")).toBe(2);
    expect(pathMatches("/api/files", "/api/files/:path*?")).toBe(2);
    expect(normaliseUrl("https://example.org/api/x?y=1")).toBe("/api/x");
    expect(normaliseUrl(":p/api/x")).toBe("/api/x");
    expect(normaliseUrl("api/x")).toBeNull();
  });

  it("recognises role conditions and the subtrees they gate", async () => {
    const root = project({
      "package.json": JSON.stringify({ name: "x", devDependencies: { vite: "5.0.0" } }),
      "index.html": '<script type="module" src="/src/a.tsx"></script>\n',
      "src/a.tsx": [
        "export function A({ user, roles, isAdmin, can }: any) {",
        "  if (!isAdmin) return null;",
        "  return <div>",
        '    {user.role === "admin" && <b onClick={() => 1} />}',
        '    {roles.includes("editor") ? <i /> : <u />}',
        '    {!isAdmin ? <em /> : <strong />}',
        "    {user.name && <s />}",
        '    {can("x") && <p />}',
        "  </div>;",
        "}",
      ].join("\n"),
    });
    const ctx = await context(root);
    const pf = ctx.parse("src/a.tsx")!;
    const gated = roleGatedSubtrees(pf).map((g) => `${(g.cond.text)} -> ${g.subtree.type}`);
    expect(gated).toEqual(["(!isAdmin) -> return_statement", 'user.role === "admin" -> jsx_self_closing_element', 'roles.includes("editor") -> jsx_self_closing_element', "!isAdmin -> jsx_self_closing_element"]);
    const subtrees = roleGatedSubtrees(pf).map((g) => g.subtree.text);
    expect(subtrees).toContain("<i />");
    expect(subtrees).toContain("<strong />");
    expect(subtrees).not.toContain("<u />");
    expect(subtrees).not.toContain("<em />");
    ctx.dispose();
  });

  it("isRoleCondition accepts the spec's patterns only", async () => {
    const root = project({
      "package.json": JSON.stringify({ name: "x" }),
      "c.ts": ["a = role === 'admin';", "b = isAdmin;", "c = user.role;", "d = permissions.includes('x');", "e = user.type === 'superadmin';", "f = user.name === 'bob';", "g = isLoading;", "h = hasRole('x');"].join("\n"),
    });
    const ctx = await context(root);
    const pf = ctx.parse("c.ts")!;
    const rights = pf.root.descendantsOfType("assignment_expression").map((n) => n!.childForFieldName("right")!);
    expect(rights.map((r) => isRoleCondition(r))).toEqual([true, true, true, true, true, false, false, true]);
    ctx.dispose();
  });
});

describe("security-headers helpers", () => {
  it("parses CSP directives and _headers blocks", () => {
    const csp = parseCsp("default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' ;frame-ancestors 'none'");
    expect(csp.get("script-src")).toEqual(["'self'", "'unsafe-inline'", "'unsafe-eval'"]);
    expect(csp.has("frame-ancestors")).toBe(true);
    expect(parseHeadersFile("# c\n/*\n  X-Frame-Options: DENY\n/api/*\n  Cache-Control: no-store\n")).toEqual([
      { path: "/*", line: 2, headers: [{ name: "X-Frame-Options", value: "DENY", line: 3 }] },
      { path: "/api/*", line: 4, headers: [{ name: "Cache-Control", value: "no-store", line: 5 }] },
    ]);
  });
});
