// core/paid-api-limit: severity from auth and declaredPublic, Next.js middleware rate limiting, inventory linkage.

import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runShip } from "../../src/ship/run.js";
import type { RunResult } from "../../src/types.js";
import { FIXTURES, cleanup } from "../helpers/fixtures.js";

const temp: string[] = [];
const saved = { HOME: process.env.HOME, SECOR_HOME: process.env.SECOR_HOME };

beforeAll(() => {
  const home = mkdtempSync(join(tmpdir(), "secor-home-"));
  temp.push(home);
  process.env.HOME = home;
  process.env.SECOR_HOME = join(home, ".secor");
});

afterAll(() => {
  process.env.HOME = saved.HOME;
  process.env.SECOR_HOME = saved.SECOR_HOME;
  temp.forEach(cleanup);
});

function copyFixture(variant: string, name: string): string {
  const dir = mkdtempSync(join(tmpdir(), "secor-core-paid-"));
  temp.push(dir);
  cpSync(join(FIXTURES, "core", "paid-api-limit", variant, name), dir, { recursive: true, filter: (s) => !s.endsWith("case.json") });
  return dir;
}

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(join(tmpdir(), "secor-core-paid-"));
  temp.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  return dir;
}

async function ship(root: string): Promise<RunResult> {
  const { result } = await runShip({ root, write: false, offline: true, onlyRules: ["core/paid-api-limit"] });
  return result;
}

const paid = (r: RunResult) => r.findings.filter((f) => f.ruleId === "core/paid-api-limit");

describe("core/paid-api-limit", () => {
  it("counts Upstash rate limiting in middleware.ts only for the paths its matcher covers", async () => {
    const root = copyFixture("clean", "nextjs-middleware-ratelimit");
    expect(paid(await ship(root))).toEqual([]);
    writeFileSync(join(root, "middleware.ts"), readFileSync(join(root, "middleware.ts"), "utf8").replace('["/api/:path*"]', '["/dashboard/:path*"]'));
    expect(paid(await ship(root)).map((f) => [f.severity, f.location.file])).toEqual([["high", "app/api/chat/route.ts"]]);
    rmSync(join(root, "middleware.ts"));
    const r = await ship(root);
    expect(paid(r)).toHaveLength(1);
    expect(r.inventory.find((e) => e.path === "/api/chat")?.callsPaidApi).toBe(true);
  });

  it("is high for a guarded entry point declared public, and links the finding to the entry point", async () => {
    const r = await ship(copyFixture("vulnerable", "nextjs-declared-public"));
    const entry = r.inventory.find((e) => e.path === "/api/chat" && e.method === "POST")!;
    expect(entry.auth.guarded).toBe(true);
    expect(entry.declaredPublic).toBe(true);
    const fs = paid(r);
    expect(fs.map((f) => [f.severity, f.entryPointId, f.service, f.maturity])).toEqual([["high", entry.id, "core", "stable"]]);
    expect(fs[0]!.fix.summary).toBe("Add a per-user or per-IP rate limit and a spend cap at the provider.");
  });

  it("covers server actions and keeps finding IDs stable when an unrelated route changes", async () => {
    const files = {
      "package.json": '{"dependencies":{"next":"15.0.0","openai":"^4"}}',
      "app/page.tsx": "export default function Page() { return null; }\n",
      "app/actions.ts": [
        '"use server";',
        'import OpenAI from "openai";',
        "const openai = new OpenAI();",
        "export async function rewrite(text: string) {",
        '  const r = await openai.chat.completions.create({ model: "m", messages: [{ role: "user", content: text }] });',
        "  return r.choices[0]?.message.content;",
        "}",
        "",
      ].join("\n"),
      "app/api/other/route.ts": "export async function GET() { return Response.json({ ok: 1 }); }\n",
    };
    const root = project(files);
    const first = paid(await ship(root));
    expect(first.map((f) => [f.severity, f.location.file, f.location.line, f.evidence.startsWith("server action app/actions.ts#rewrite: openai.chat.completions.create(")])).toEqual([
      ["high", "app/actions.ts", 4, true],
    ]);
    writeFileSync(join(root, "app/api/other/route.ts"), "export async function GET() { return Response.json({ ok: 2 }); }\n");
    expect(paid(await ship(root)).map((f) => f.id)).toEqual(first.map((f) => f.id));
  });

  it("does not apply when no entry point calls a paid API", async () => {
    const r = await ship(project({ "package.json": '{"dependencies":{"express":"^4"}}', "src/app.js": 'const app = require("express")();\napp.get("/x", (req, res) => res.json({}));\n' }));
    expect(r.coverage.applicable).toBe(0);
  });
});
