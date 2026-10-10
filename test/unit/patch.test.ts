import { describe, expect, it } from "vitest";
import { applyEdits, replaceOnLine, unifiedDiff } from "../../src/engine/patch.js";
import { fillTemplate, suggestedTestPath } from "../../src/engine/templates.js";

const SRC = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"].join("\n") + "\n";

describe("unifiedDiff", () => {
  it("replaces one line with context", () => {
    const edit = replaceOnLine(SRC, 5, "e", "E")!;
    expect(unifiedDiff("x.ts", SRC, [edit])).toBe(["--- a/x.ts", "+++ b/x.ts", "@@ -2,7 +2,7 @@", " b", " c", " d", "-e", "+E", " f", " g", " h", ""].join("\n"));
    expect(applyEdits(SRC, [edit])).toBe(SRC.replace("e\n", "E\n"));
  });

  it("inserts lines without removing any", () => {
    const d = unifiedDiff("x.ts", SRC, [{ startLine: 3, endLine: 2, newLines: ["new1", "new2"] }]);
    expect(d).toContain("@@ -1,5 +1,7 @@");
    expect(d).toContain("+new1\n+new2\n c");
  });

  it("edits at the first and last line", () => {
    expect(unifiedDiff("x.ts", SRC, [{ startLine: 1, endLine: 1, newLines: ["A"] }])).toContain("@@ -1,4 +1,4 @@\n-a\n+A\n b");
    expect(unifiedDiff("x.ts", SRC, [{ startLine: 10, endLine: 10, newLines: ["J"] }])).toContain("@@ -7,4 +7,4 @@\n g\n h\n i\n-j\n+J\n");
  });

  it("merges nearby edits into one hunk and keeps far ones apart", () => {
    const near = unifiedDiff("x.ts", SRC, [replaceOnLine(SRC, 2, "b", "B")!, replaceOnLine(SRC, 4, "d", "D")!]);
    expect(near.match(/^@@/gm)).toHaveLength(1);
    const far = unifiedDiff("x.ts", SRC, [replaceOnLine(SRC, 1, "a", "A")!, replaceOnLine(SRC, 10, "j", "J")!]);
    expect(far.match(/^@@/gm)).toHaveLength(2);
  });

  it("marks a missing final newline and returns empty for no change", () => {
    expect(unifiedDiff("x.ts", "one\ntwo", [replaceOnLine("one\ntwo", 2, "two", "TWO")!])).toMatch(/\+TWO\n\\ No newline at end of file\n$/);
    expect(unifiedDiff("x.ts", SRC, [])).toBe("");
    expect(replaceOnLine(SRC, 3, "zzz", "y")).toBeNull();
  });

  it("rejects overlapping edits", () => {
    expect(() => unifiedDiff("x.ts", SRC, [{ startLine: 2, endLine: 4, newLines: [] }, { startLine: 3, endLine: 3, newLines: ["x"] }])).toThrow();
  });
});

describe("templates", () => {
  it("fills placeholders, keeps flagged lines, marks missing values", () => {
    const t = "{{?vitest}}import { it } from 'vitest';\n{{?jest}}// jest\nit('{{method}} {{path}}', () => {}); // {{toolName}}";
    expect(fillTemplate(t, { method: "GET", path: "/x" }, new Set(["vitest"]))).toBe("import { it } from 'vitest';\nit('GET /x', () => {}); // TODO(secor): toolName");
  });

  it("suggests tests/secor/<rule>-<short id>.test.<ext>", () => {
    expect(suggestedTestPath("api/missing-auth", "api-missing-auth-3f9a1c2b7d4e", "ts")).toBe("tests/secor/api-missing-auth-3f9a1c.test.ts");
  });
});
