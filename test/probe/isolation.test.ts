// Isolation (spec 9A, M6b): no module except src/probe/** and src/cli/probe.ts may import the Probe
// module. The engine, MCP server, hooks, gate and CI must never pull Probe in.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(import.meta.dirname, "..", "..", "src");

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const e of readdirSync(dir)) {
    const p = join(dir, e);
    if (statSync(p).isDirectory()) out.push(...tsFiles(p));
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

/** Import / export-from / dynamic-import specifiers in a source file. */
function importSpecifiers(text: string): string[] {
  const specs: string[] = [];
  const patterns = [/\bimport\s+[^"';]*?from\s*["']([^"']+)["']/g, /\bexport\s+[^"';]*?from\s*["']([^"']+)["']/g, /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g, /\bimport\s+["']([^"']+)["']/g];
  for (const re of patterns) for (const m of text.matchAll(re)) specs.push(m[1]!);
  return specs;
}

describe("Probe module isolation", () => {
  it("no file outside src/probe/** and src/cli/probe.ts imports the probe module", () => {
    const offenders: string[] = [];
    for (const file of tsFiles(SRC)) {
      const rel = relative(SRC, file).split("\\").join("/");
      if (rel.startsWith("probe/") || rel === "cli/probe.ts") continue;
      for (const spec of importSpecifiers(readFileSync(file, "utf8"))) {
        // A specifier that resolves into the probe module has a `probe/` path segment
        // (e.g. "../probe/index.js", "./probe/run.js"). "./probe.js" (the CLI command) does not.
        if (/(^|\/)probe\//.test(spec)) offenders.push(`${rel} -> ${spec}`);
      }
    }
    expect(offenders).toEqual([]);
  });

  it("src/cli/probe.ts loads the probe module only via dynamic import inside actions", () => {
    const text = readFileSync(join(SRC, "cli", "probe.ts"), "utf8");
    // No static (non-type) import of the probe module.
    const staticImport = /\bimport\s+(?!type\b)[^"';]*?from\s*["'][^"']*\/probe\/[^"']*["']/g;
    expect(text.match(staticImport)).toBeNull();
    // It does load it dynamically.
    expect(/\bimport\s*\(\s*["'][^"']*\/probe\/index\.js["']\s*\)/.test(text)).toBe(true);
  });
});
