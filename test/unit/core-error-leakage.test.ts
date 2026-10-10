// core/error-leakage edge cases beyond the fixtures.

import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { runShip } from "../../src/ship/run.js";
import { cleanup } from "../helpers/fixtures.js";

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

async function lines(files: Record<string, string>): Promise<string[]> {
  const dir = mkdtempSync(join(tmpdir(), "secor-core-leak-"));
  temp.push(dir);
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(dir, rel)), { recursive: true });
    writeFileSync(join(dir, rel), text);
  }
  const { result } = await runShip({ root: dir, write: false, offline: true, onlyRules: ["core/error-leakage"] });
  return result.findings.filter((f) => f.ruleId === "core/error-leakage").map((f) => `${f.location.file}:${f.location.line}`);
}

const express = (src: string) => lines({ "package.json": '{"dependencies":{"express":"^4"}}', "src/app.ts": src });

describe("core/error-leakage", () => {
  it("flags concatenation, arrays, util.inspect, stack methods and TS casts", async () => {
    const src = [
      'import express from "express";',
      'import util from "node:util";',
      "const app = express();",
      'app.get("/a", async (req, res) => {',
      "  try { await a(); } catch (err) {",
      '    res.status(500).send("Error: " + err);', // 6
      "  }",
      "});",
      'app.get("/b", async (req, res) => {',
      "  try { await b(); } catch (err) {",
      "    res.status(500).json({ errors: [err.stack] });", // 11
      "  }",
      "});",
      'app.get("/c", async (req, res) => {',
      "  try { await c(); } catch (err) {",
      "    res.status(500).send(util.inspect(err));", // 16
      "  }",
      "});",
      'app.get("/d", async (req, res) => {',
      "  try { await d(); } catch (err) {",
      '    res.status(500).json({ lines: (err as Error).stack?.split("\\n") });', // 21
      "  }",
      "});",
      'app.get("/e", async (request, reply) => {',
      "  try { await e(); } catch (problem) {",
      "    reply.json({ detail: { inner: problem } });", // 26
      "  }",
      "});",
      "",
    ].join("\n");
    expect(await express(src)).toEqual(["src/app.ts:6", "src/app.ts:11", "src/app.ts:16", "src/app.ts:21", "src/app.ts:26"]);
  });

  it("does not flag messages, spreads, JSON.stringify, unrelated objects or non-response calls", async () => {
    const src = [
      'import express from "express";',
      "const app = express();",
      'app.get("/a", async (req, res) => {',
      "  try { await a(); } catch (err) {",
      "    res.status(500).json({ ...err });",
      "    res.status(500).send(JSON.stringify(err));",
      "    res.status(500).json({ message: `${err.message}` });",
      "    logger.json(err);",
      "    cache.send(err.stack);",
      "  }",
      "});",
      "function combine(a, b, c, d) {",
      "  return c.json(a);",
      "}",
      "",
    ].join("\n");
    expect(await express(src)).toEqual([]);
  });

  it("covers the Next.js pages router and new Response / new NextResponse", async () => {
    const files = {
      "package.json": '{"dependencies":{"next":"15.0.0"}}',
      "pages/api/items.ts": [
        "export default async function handler(req, res) {",
        "  try {",
        "    res.status(200).json(await list());",
        "  } catch (e) {",
        "    res.status(500).json({ error: e });", // 5
        "  }",
        "}",
        "",
      ].join("\n"),
      "app/api/raw/route.ts": [
        'import { NextResponse } from "next/server";',
        "export async function GET() {",
        "  try {",
        "    return new Response(await read());",
        "  } catch (err) {",
        "    return new Response(err.stack, { status: 500 });", // 6
        "  }",
        "}",
        "export async function POST() {",
        "  try {",
        "    return NextResponse.json({});",
        "  } catch (err) {",
        "    return new NextResponse(String(err), { status: 500 });", // 13
        "  }",
        "}",
        "",
      ].join("\n"),
    };
    expect(await lines(files)).toEqual(["app/api/raw/route.ts:6", "app/api/raw/route.ts:13", "pages/api/items.ts:5"]);
  });

  it("flags FastAPI tracebacks bound through from-imports and add_exception_handler", async () => {
    const files = {
      "requirements.txt": "fastapi==0.115.0\n",
      "main.py": [
        "from traceback import format_exc, format_exception",
        "from fastapi import FastAPI",
        "from fastapi.responses import PlainTextResponse",
        "",
        "app = FastAPI()",
        "",
        "async def on_error(request, exc):",
        '    return {"trace": "".join(format_exception(exc))}', // 8
        "",
        "app.add_exception_handler(Exception, on_error)",
        "",
        '@app.get("/plain")',
        "def plain():",
        "    try:",
        "        return work()",
        "    except Exception:",
        "        return PlainTextResponse(format_exc(), status_code=500)", // 17
        "",
      ].join("\n"),
    };
    expect(await lines(files)).toEqual(["main.py:8", "main.py:17"]);
  });

  it("does not apply without an api unit", async () => {
    const dir = mkdtempSync(join(tmpdir(), "secor-core-leak-"));
    temp.push(dir);
    writeFileSync(join(dir, "index.js"), "try { a() } catch (e) { res.json(e) }\n");
    const { result } = await runShip({ root: dir, write: false, offline: true, onlyRules: ["core/error-leakage"] });
    expect(result.coverage.applicable).toBe(0);
  });
});
