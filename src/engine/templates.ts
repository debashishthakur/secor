// Test templates (spec section 8.8): src/engine/templates/<ruleId>/<framework>.tmpl, filled deterministically.
// Placeholders: {{method}}, {{path}}, {{importPath}}, {{handlerExport}}, {{toolName}}.
// A line starting with "{{?flag}}" is kept (without the marker) only when `flag` is set, e.g. {{?vitest}} / {{?jest}}.

import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Framework } from "../types.js";
import { packageRoot } from "./util/paths.js";

export interface TemplateVars {
  method?: string;
  path?: string;
  importPath?: string;
  handlerExport?: string;
  toolName?: string;
}

const cache = new Map<string, string | null>();

export function loadTemplate(ruleId: string, framework: Framework): string | null {
  const key = `${ruleId}/${framework}`;
  if (cache.has(key)) return cache.get(key)!;
  let text: string | null;
  try {
    text = readFileSync(join(packageRoot(), "src", "engine", "templates", ...ruleId.split("/"), `${framework}.tmpl`), "utf8");
  } catch {
    text = null;
  }
  cache.set(key, text);
  return text;
}

export function fillTemplate(tmpl: string, vars: TemplateVars, flags: ReadonlySet<string> = new Set()): string {
  const lines: string[] = [];
  for (const raw of tmpl.split("\n")) {
    const m = /^\{\{\?(\w+)\}\}(.*)$/.exec(raw);
    if (m) {
      if (flags.has(m[1]!)) lines.push(m[2]!);
      continue;
    }
    lines.push(raw);
  }
  return lines.join("\n").replace(/\{\{(\w+)\}\}/g, (whole, name: string) => {
    const v = (vars as Record<string, string | undefined>)[name];
    return v === undefined ? `TODO(secor): ${name}` : v;
  });
}

/** tests/secor/<ruleId with "-">-<short id>.test.<ext>; the short id is the first 6 hex digits of the finding hash. */
export function suggestedTestPath(ruleId: string, findingId: string, ext: string): string {
  const hash = findingId.split("-").pop() ?? findingId;
  return `tests/secor/${ruleId.replace(/\//g, "-")}-${hash.slice(0, 6)}.test.${ext}`;
}

/** Load, fill and prefix with the suggested location comment. Undefined when the rule/framework has no template. */
export function renderTestTemplate(ruleId: string, framework: Framework, findingId: string, vars: TemplateVars, flags: ReadonlySet<string> = new Set()): string | undefined {
  const tmpl = loadTemplate(ruleId, framework);
  if (!tmpl) return undefined;
  const py = framework === "fastapi" || framework === "mcp-py";
  const ext = py ? "py" : "ts";
  const comment = py ? "#" : "//";
  const where = py ? suggestedTestPath(ruleId, findingId, ext).replace(/\/([^/]+)\.test\.py$/, (_m, name: string) => `/test_${name.replace(/-/g, "_")}.py`) : suggestedTestPath(ruleId, findingId, ext);
  return `${comment} Suggested location: ${where}\n${fillTemplate(tmpl, vars, flags)}`;
}
