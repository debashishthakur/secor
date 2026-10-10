// Read the project's PUBLIC Supabase anon key + URL and the public table names from migrations, for
// probe/anon-table-read (spec 9A.5). This uses exactly the public bundle anyone can read; the anon key is
// public by design. We read the project from disk with plain fs because Probe has no ProjectContext.

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const ENV_FILES = [".env", ".env.local", ".env.development", ".env.development.local", ".env.production", ".env.staging"];
const URL_KEYS = /(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_)?SUPABASE_URL/;
const ANON_KEYS = /(?:NEXT_PUBLIC_|VITE_|REACT_APP_|PUBLIC_)?SUPABASE_ANON_KEY/;

export interface SupabaseProject {
  url: string | null;
  anonKey: string | null;
  tables: string[];
}

function readEnvValues(root: string): Map<string, string> {
  const values = new Map<string, string>();
  for (const name of ENV_FILES) {
    const path = join(root, name);
    if (!existsSync(path)) continue;
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch {
      continue;
    }
    for (const line of text.split(/\r?\n/)) {
      const m = /^\s*(?:export\s+)?([A-Za-z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
      if (!m) continue;
      let v = m[2]!.trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) v = v.slice(1, -1);
      if (!values.has(m[1]!)) values.set(m[1]!, v);
    }
  }
  return values;
}

/** Public table names in schema `public` from supabase/migrations and supabase/schemas SQL files. */
export function readPublicTables(root: string): string[] {
  const dirs = [join(root, "supabase", "migrations"), join(root, "supabase", "schemas")];
  const tables = new Set<string>();
  const dropped = new Set<string>();
  for (const dir of dirs) {
    if (!existsSync(dir)) continue;
    let files: string[];
    try {
      files = readdirSync(dir).filter((f) => f.endsWith(".sql")).sort();
    } catch {
      continue;
    }
    for (const f of files) {
      let sql: string;
      try {
        sql = readFileSync(join(dir, f), "utf8");
      } catch {
        continue;
      }
      const noComments = sql.replace(/--[^\n]*/g, "");
      for (const m of noComments.matchAll(/create\s+table\s+(?:if\s+not\s+exists\s+)?("?)(?:public\.)?("?)([A-Za-z_][A-Za-z0-9_]*)\2\s*\(/gi)) {
        const name = m[3]!;
        // Skip explicitly non-public schemas (auth., storage., etc.).
        const before = noComments.slice(Math.max(0, m.index! - 40), m.index!);
        if (/\b(auth|storage|realtime|extensions|graphql|vault)\s*\.\s*$/i.test(before + ".")) continue;
        if (/(?:public\.)?(?:auth|storage|realtime|extensions|graphql|vault)\./i.test(m[0])) continue;
        tables.add(name);
      }
      for (const m of noComments.matchAll(/drop\s+table\s+(?:if\s+exists\s+)?(?:public\.)?"?([A-Za-z_][A-Za-z0-9_]*)"?/gi)) {
        dropped.add(m[1]!);
      }
    }
  }
  for (const d of dropped) tables.delete(d);
  return [...tables].sort();
}

export function readSupabaseProject(root: string): SupabaseProject {
  const env = readEnvValues(root);
  let url: string | null = null;
  let anonKey: string | null = null;
  for (const [k, v] of env) {
    if (!url && URL_KEYS.test(k) && /^https?:\/\//.test(v)) url = v.replace(/\/$/, "");
    if (!anonKey && ANON_KEYS.test(k) && v.length > 20) anonKey = v;
  }
  return { url, anonKey, tables: readPublicTables(root) };
}
