// Every patch proposed by web/cookie-flags, web/security-headers and web/production-debug on the vulnerable
// fixtures applies cleanly (context and removed lines must match exactly), leaves the file parseable, and
// makes its finding disappear when the rule runs again.

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parse as parseToml } from "smol-toml";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { parseJsonPos } from "../../src/engine/backends/json-pos.js";
import { initParsers, langForFile, parseSource } from "../../src/engine/parse.js";
import { applyEdits, type LineEdit } from "../../src/engine/patch.js";
import { editObjectText, rangeEdit } from "../../src/engine/rules/web/util.js";
import { runShip } from "../../src/ship/run.js";
import type { Finding } from "../../src/types.js";
import { cleanup, listCases, prepareFixture } from "../helpers/fixtures.js";

/** Strict unified-diff application: every context and removed line must match the original exactly. */
export function applyUnifiedDiff(original: string, diff: string): string {
  const finalNewline = original.endsWith("\n");
  const lines = (finalNewline ? original.slice(0, -1) : original).split("\n");
  const dl = diff.split("\n");
  if (!dl[0]?.startsWith("--- a/") || !dl[1]?.startsWith("+++ b/")) throw new Error("missing file headers");
  const out: string[] = [];
  let cursor = 0;
  let i = 2;
  while (i < dl.length) {
    const h = /^@@ -(\d+),(\d+) \+(\d+),(\d+) @@$/.exec(dl[i]!);
    if (!h) {
      if (dl[i] === "" || dl[i]!.startsWith("\\")) {
        i++;
        continue;
      }
      throw new Error(`unexpected diff line: ${dl[i]}`);
    }
    const oldStart = Number(h[1]);
    const oldCount = Number(h[2]);
    const start = oldCount === 0 ? oldStart : oldStart - 1;
    if (start < cursor) throw new Error("overlapping hunks");
    while (cursor < start) out.push(lines[cursor++]!);
    let seenOld = 0;
    let seenNew = 0;
    for (i++; i < dl.length && !dl[i]!.startsWith("@@"); i++) {
      const l = dl[i]!;
      if (l.startsWith(" ") || l.startsWith("-")) {
        if (lines[cursor] !== l.slice(1)) throw new Error(`context mismatch at line ${cursor + 1}: ${JSON.stringify(lines[cursor])} vs ${JSON.stringify(l.slice(1))}`);
        if (l.startsWith(" ")) {
          out.push(lines[cursor]!);
          seenNew++;
        }
        cursor++;
        seenOld++;
      } else if (l.startsWith("+")) {
        out.push(l.slice(1));
        seenNew++;
      }
    }
    if (seenOld !== oldCount || seenNew !== Number(h[4])) throw new Error(`hunk counts do not match: ${dl.join("\n")}`);
  }
  while (cursor < lines.length) out.push(lines[cursor++]!);
  return out.join("\n") + (finalNewline ? "\n" : "");
}

function assertParses(file: string, text: string): void {
  const lang = langForFile(file);
  if (lang) {
    const tree = parseSource(text, lang);
    expect(tree.rootNode.hasError, `${file} has a syntax error after the patch:\n${text}`).toBe(false);
    tree.delete();
  } else if (file.endsWith(".json")) expect(parseJsonPos(text), `${file} is not valid JSON`).not.toBeNull();
  else if (file.endsWith(".toml")) expect(() => parseToml(text)).not.toThrow();
}

const PATCH_RULES = new Set(["web/cookie-flags", "web/security-headers", "web/production-debug"]);
const cases = listCases().filter((c) => c.variant === "vulnerable" && PATCH_RULES.has(c.spec.rule));
const temp: string[] = [];
const rulesWithPatches = new Set<string>();

beforeAll(async () => {
  await initParsers();
});
afterAll(() => temp.forEach(cleanup));

async function findingsFor(root: string, rule: string): Promise<Finding[]> {
  const { result } = await runShip({ root, write: false, offline: true, onlyRules: [rule] });
  return result.findings.filter((f) => f.ruleId === rule);
}

describe("web patches apply cleanly and fix the finding", () => {
  it("has vulnerable fixtures for every patching rule", () => {
    expect(new Set(cases.map((c) => c.spec.rule))).toEqual(PATCH_RULES);
  });

  for (const c of cases) {
    it(c.name, async () => {
      const root = prepareFixture(c.dir);
      temp.push(root);
      const findings = await findingsFor(root, c.spec.rule);
      const patched = findings.filter((f) => f.fix.patch);
      if (patched.length) rulesWithPatches.add(c.spec.rule);
      for (const f of patched) {
        const dir = prepareFixture(c.dir);
        temp.push(dir);
        const path = join(dir, f.location.file);
        const before = readFileSync(path, "utf8");
        expect(f.fix.patch!.split("\n").slice(0, 2)).toEqual([`--- a/${f.location.file}`, `+++ b/${f.location.file}`]);
        const after = applyUnifiedDiff(before, f.fix.patch!);
        expect(after).not.toBe(before);
        assertParses(f.location.file, after);
        writeFileSync(path, after);
        const again = await findingsFor(dir, c.spec.rule);
        expect(again.map((x) => x.id), `finding ${f.id} still reported after its patch`).not.toContain(f.id);
        if (c.spec.rule !== "web/security-headers") {
          // the patched location is clean (security-headers keeps other missing headers on the same line)
          expect(again.filter((x) => x.location.file === f.location.file && x.location.line === f.location.line)).toEqual([]);
        }
        // A patch can fix more than its own finding (the suggested CSP includes frame-ancestors).
        expect(again.length).toBeLessThan(findings.length);
      }
    });
  }

  it("every patching rule produced at least one patch", () => {
    expect(rulesWithPatches).toEqual(PATCH_RULES);
  });
});

describe("text edit helpers", () => {
  const apply = (src: string, e: LineEdit) => applyEdits(src, [e]);

  it("rangeEdit replaces a range inside whole lines", () => {
    const src = "a\nfoo(bar, baz);\nc\n";
    const start = src.indexOf("bar");
    expect(apply(src, rangeEdit(src, start, start + 3, "qux"))).toBe("a\nfoo(qux, baz);\nc\n");
    const multi = "x = {\n  a: 1,\n};\n";
    expect(apply(multi, rangeEdit(multi, multi.indexOf("{"), multi.indexOf("}") + 1, "{ b: 2 }"))).toBe("x = { b: 2 };\n");
    const noNl = "only line";
    expect(apply(noNl, rangeEdit(noNl, 5, 9, "LINE"))).toBe("only LINE");
  });

  it("editObjectText appends and replaces properties in one- and multi-line objects", () => {
    const obj = (src: string) => {
      const tree = parseSource(src, "typescript");
      const node = tree.rootNode.descendantsOfType("object")[0]!;
      return { tree, node };
    };
    const one = "f({ maxAge: 1, secure: false });\n";
    const a = obj(one);
    const props = a.node.namedChildren.filter((x) => x?.type === "pair");
    expect(editObjectText(one, a.node, [{ key: "secure", value: "true", existing: props[1]! }, { key: "httpOnly", value: "true", existing: null }])).toBe("{ maxAge: 1, secure: true, httpOnly: true }");
    const empty = "f({});\n";
    expect(editObjectText(empty, obj(empty).node, [{ key: "a", value: "1", existing: null }])).toBe("{ a: 1 }");
    const multi = "f({\n    maxAge: 1\n  });\n";
    expect(editObjectText(multi, obj(multi).node, [{ key: "httpOnly", value: "true", existing: null }, { key: "sameSite", value: '"lax"', existing: null }])).toBe('{\n    maxAge: 1,\n    httpOnly: true,\n    sameSite: "lax"\n  }');
    const trailing = "f({\n  maxAge: 1,\n});\n";
    expect(editObjectText(trailing, obj(trailing).node, [{ key: "secure", value: "true", existing: null }])).toBe("{\n  maxAge: 1,\n  secure: true,\n}");
    const commented = "f({\n  maxAge: 1, // keep\n});\n";
    expect(editObjectText(commented, obj(commented).node, [{ key: "secure", value: "true", existing: null }])).toBeNull();
  });
});
