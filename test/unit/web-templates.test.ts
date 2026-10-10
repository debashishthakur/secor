// web/cookie-flags test templates (spec 8.8): render without leftover placeholders and parse.

import { beforeAll, describe, expect, it } from "vitest";
import { initParsers, type Lang, parseSource } from "../../src/engine/parse.js";
import { loadTemplate, renderTestTemplate } from "../../src/engine/templates.js";
import { runShip } from "../../src/ship/run.js";
import type { Framework } from "../../src/types.js";
import { cleanup, listCases, prepareFixture } from "../helpers/fixtures.js";

const RULE = "web/cookie-flags";
const FRAMEWORKS: { framework: Framework; lang: Lang }[] = [
  { framework: "express", lang: "typescript" },
  { framework: "nextjs", lang: "typescript" },
  { framework: "fastapi", lang: "python" },
];

beforeAll(async () => {
  await initParsers();
});

function errorsIn(text: string, lang: Lang): string[] {
  const tree = parseSource(text, lang);
  const errs = tree.rootNode.descendantsOfType(["ERROR"]).map((n) => n?.text ?? "");
  const missing = tree.rootNode.hasError && errs.length === 0 ? ["(missing node)"] : [];
  tree.delete();
  return [...errs, ...missing];
}

describe("web/cookie-flags templates", () => {
  for (const { framework, lang } of FRAMEWORKS) {
    it(`${framework}: renders and parses`, () => {
      expect(loadTemplate(RULE, framework), "template file exists").not.toBeNull();
      const vars = { method: "POST", path: "/api/login", importPath: framework === "fastapi" ? "app.main" : "../../src/app", handlerExport: "POST" };
      const flagSets = framework === "express" ? [new Set(["vitest"]), new Set(["jest"])] : [new Set<string>()];
      for (const flags of flagSets) {
        const out = renderTestTemplate(RULE, framework, "web-cookie-flags-0123456789ab", vars, flags)!;
        expect(out).not.toMatch(/\{\{/);
        expect(out).not.toContain("TODO(secor): method");
        expect(errorsIn(out, lang)).toEqual([]);
        expect(out).toMatch(/httponly/i);
        expect(out).toMatch(/secure/i);
        expect(out).toMatch(/samesite/i);
        expect(out.split("\n")[0]).toMatch(framework === "fastapi" ? /^# Suggested location: tests\/secor\/test_web_cookie_flags_012345\.py$/ : /^\/\/ Suggested location: tests\/secor\/web-cookie-flags-012345\.test\.ts$/);
      }
      if (framework === "express") {
        expect(renderTestTemplate(RULE, framework, "x-0123456789ab", vars, new Set(["jest"]))).toContain('from "@jest/globals"');
        expect(renderTestTemplate(RULE, framework, "x-0123456789ab", vars, new Set(["vitest"]))).toContain('from "vitest"');
      }
    });

    if (lang !== "python") {
      it(`${framework}: still parses when values are missing (TODO markers)`, () => {
        const out = renderTestTemplate(RULE, framework, "web-cookie-flags-0123456789ab", {}, new Set(["vitest"]))!;
        expect(out).not.toMatch(/\{\{/);
        expect(out).toContain("TODO(secor):");
        expect(errorsIn(out, lang)).toEqual([]);
      });
    }
  }

  it("templates attached to fixture findings render fully and parse", async () => {
    const cases = listCases().filter((c) => c.spec.rule === RULE && c.variant === "vulnerable");
    let seen = 0;
    for (const c of cases) {
      const root = prepareFixture(c.dir);
      try {
        const { result } = await runShip({ root, write: false, offline: true, onlyRules: [RULE] });
        for (const f of result.findings) {
          const t = f.fix.testTemplate;
          expect(t, `${c.name}: ${f.location.file}:${f.location.line} has a test template`).toBeDefined();
          expect(t).not.toMatch(/\{\{/);
          expect(errorsIn(t!, f.location.file.endsWith(".py") ? "python" : "typescript")).toEqual([]);
          seen++;
        }
      } finally {
        cleanup(root);
      }
    }
    expect(seen).toBeGreaterThanOrEqual(3);
  });
});
