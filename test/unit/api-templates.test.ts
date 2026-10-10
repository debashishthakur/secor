// api pack test templates (spec section 8.8): every template renders with no leftover placeholders, keeps its
// TODO(secor) lines, carries the expected assertion, and parses without syntax errors.

import { beforeAll, describe, expect, it } from "vitest";
import type { Framework } from "../../src/types.js";
import { type Lang, type SyntaxNode, initParsers, parseSource } from "../../src/engine/parse.js";
import { renderTestTemplate } from "../../src/engine/templates.js";

const ASSERTS: Record<string, { ts: string; py: string }> = {
  "api/missing-auth": { ts: "[401, 403]", py: "in (401, 403)" },
  "api/missing-ownership": { ts: "[403, 404]", py: "in (403, 404)" },
  "api/mass-assignment": { ts: 'not.toBe("admin")', py: '!= "admin"' },
  "api/webhook-signature": { ts: "toBe(400)", py: "== 400" },
  "api/cors-credentials": { ts: "access-control-allow-origin", py: '"access-control-allow-origin" not in' },
};

const NEXT_VARIANTS: Record<string, string[]> = {
  "api/missing-auth": ["route", "pages", "action"],
  "api/missing-ownership": ["route", "pages", "action"],
  "api/mass-assignment": ["route", "pages", "action"],
  "api/webhook-signature": ["route", "pages"],
  "api/cors-credentials": ["route", "pages", "middleware"],
};

const ID = "api-missing-auth-0123456789ab";

beforeAll(async () => {
  await initParsers();
});

function syntaxErrors(source: string, lang: Lang): string[] {
  const tree = parseSource(source, lang);
  const out: string[] = [];
  const visit = (n: SyntaxNode) => {
    if (n.type === "ERROR" || n.isMissing) out.push(`${n.type} at ${n.startPosition.row + 1}:${n.startPosition.column + 1}: ${n.text.slice(0, 60)}`);
    for (const c of n.children) if (c) visit(c);
  };
  visit(tree.rootNode);
  tree.delete();
  return out;
}

function render(rule: string, framework: Framework, flags: string[], vars: Record<string, string>): string {
  const out = renderTestTemplate(rule, framework, ID, vars, new Set(flags));
  expect(out, `${rule} ${framework} template exists`).toBeDefined();
  return out!;
}

function common(out: string): void {
  expect(out).not.toMatch(/\{\{/);
  expect(out).not.toMatch(/TODO\(secor\): (?:method|path|importPath|handlerExport|toolName)\b/);
  expect(out).toContain("TODO(secor):");
  expect(out).not.toMatch(/\b(?:secure|safe|passed)\b/i);
}

describe("api test templates", () => {
  for (const rule of Object.keys(ASSERTS)) {
    for (const runner of ["vitest", "jest"]) {
      it(`${rule} express (${runner})`, () => {
        const out = render(rule, "express", [runner], { method: "POST", path: "/api/notes/:id", importPath: "../../src/app", handlerExport: "default" });
        common(out);
        expect(out).toContain(runner === "vitest" ? 'from "vitest"' : 'from "@jest/globals"');
        expect(out).not.toContain(runner === "vitest" ? "@jest/globals" : 'from "vitest"');
        expect(out).toContain('import request from "supertest"');
        expect(out).toContain(ASSERTS[rule]!.ts);
        expect(out.split("\n")[0]).toBe(`// Suggested location: tests/secor/${rule.replace("/", "-")}-012345.test.ts`);
        expect(syntaxErrors(out, "typescript")).toEqual([]);
      });
    }
    for (const variant of NEXT_VARIANTS[rule]!) {
      it(`${rule} nextjs (${variant})`, () => {
        const vars =
          variant === "action"
            ? { method: "action", path: "app/actions.ts#deleteNote", importPath: "../../app/actions", handlerExport: "deleteNote" }
            : variant === "middleware"
              ? { method: "GET", path: "/api/notes", importPath: "../../middleware", handlerExport: "middleware" }
              : { method: "DELETE", path: "/api/notes/:id", importPath: "../../app/api/notes/[id]/route", handlerExport: variant === "pages" ? "default" : "DELETE" };
        const out = render(rule, "nextjs", [variant], vars);
        common(out);
        expect(out).toContain('from "vitest"');
        if (variant !== "action") expect(out).toContain(ASSERTS[rule]!.ts);
        expect(syntaxErrors(out, "typescript")).toEqual([]);
        // Only the selected variant's test is kept.
        expect(out.match(/\bit\(/g)?.length).toBe(1);
      });
    }
    it(`${rule} fastapi`, () => {
      const out = render(rule, "fastapi", [], { method: "GET", path: "/items/:item_id", importPath: "app.main", handlerExport: "app" });
      common(out);
      expect(out).toContain("from fastapi.testclient import TestClient");
      expect(out).toContain("from app.main import app as app");
      expect(out).toContain(ASSERTS[rule]!.py);
      expect(out.split("\n")[0]).toBe(`# Suggested location: tests/secor/test_${rule.replace("/", "_").replace(/-/g, "_")}_012345.py`);
      expect(syntaxErrors(out, "python")).toEqual([]);
    });
  }
});
