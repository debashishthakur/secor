// web/database-rules: Database open to the public (spec 8.5). Supabase migrations / declarative schemas
// and Firebase security rules (Firestore, Storage, Realtime Database).

import { posix } from "node:path";
import { classifyAllow, classifyRtdb, parseRtdbRules, parseRulesFile } from "../../backends/firebase.js";
import { jsonProp, parseJsonPos } from "../../backends/json-pos.js";
import { buildSupabaseModel, displayName, isLiteralTrue, type QName, qkey, type SupabaseModel } from "../../backends/supabase.js";
import type { ProjectContext } from "../../context.js";
import { defineRule, NotChecked, SOURCES } from "../types.js";
import { serviceFor } from "./util.js";

const WHY = "Supabase and Firebase serve the database straight to browsers, so its access rules are the only thing that stops anyone holding the public project keys from reading or changing the data.";
const NO_FILES = "no Supabase migrations or Firebase rules files in the repo";
const SUPABASE_SOURCE = { name: "Supabase docs, Row Level Security", url: "https://supabase.com/docs/guides/database/postgres/row-level-security" };
const FIREBASE_SOURCE = { name: "Firebase docs, avoid insecure rules", url: "https://firebase.google.com/docs/rules/insecure-rules" };
const PUBLIC_ROLES = new Set(["anon", "public"]);
const KNOWN_METHODS = new Set(["read", "write", "get", "list", "create", "update", "delete"]);

const SQL_FILE = /(?:^|\/)supabase\/(migrations|schemas)\/[^/]+\.sql$/;

interface SqlGroup {
  schemas: string[];
  migrations: string[];
}

function supabaseGroups(ctx: ProjectContext): Map<string, SqlGroup> {
  const groups = new Map<string, SqlGroup>();
  for (const f of ctx.files) {
    const m = SQL_FILE.exec(f);
    if (!m) continue;
    const base = f.slice(0, m.index);
    const g = groups.get(base) ?? { schemas: [], migrations: [] };
    (m[1] === "schemas" ? g.schemas : g.migrations).push(f);
    groups.set(base, g);
  }
  for (const g of groups.values()) {
    g.schemas.sort();
    g.migrations.sort();
  }
  return groups;
}

interface RulesFile {
  file: string;
  kind: "rules" | "rtdb";
}

/** firestore.rules / storage.rules / database.rules.json, plus files named in firebase.json. */
function firebaseRulesFiles(ctx: ProjectContext): RulesFile[] {
  const out = new Map<string, RulesFile["kind"]>();
  for (const f of ctx.files) {
    const base = posix.basename(f);
    if (base === "firestore.rules" || base === "storage.rules") out.set(f, "rules");
    else if (base === "database.rules.json") out.set(f, "rtdb");
  }
  for (const f of ctx.files) {
    if (posix.basename(f) !== "firebase.json") continue;
    const root = parseJsonPos(ctx.read(f) ?? "");
    if (!root) continue;
    const dir = posix.dirname(f) === "." ? "" : posix.dirname(f);
    const add = (value: unknown, kind: RulesFile["kind"]) => {
      if (typeof value !== "string") return;
      const rel = posix.normalize(dir ? `${dir}/${value}` : value);
      if (!rel.startsWith("../") && ctx.hasFile(rel) && !out.has(rel)) out.set(rel, kind);
    };
    for (const [section, kind] of [
      ["firestore", "rules"],
      ["storage", "rules"],
      ["database", "rtdb"],
    ] as const) {
      const v = jsonProp(root, section)?.value;
      const items = v?.kind === "array" ? v.items : v ? [v] : [];
      for (const item of items) {
        const r = jsonProp(item, "rules")?.value;
        if (r?.kind === "string") add(r.value, kind);
      }
    }
  }
  return [...out.entries()].map(([file, kind]) => ({ file, kind })).sort((a, b) => (a.file < b.file ? -1 : 1));
}

/** Tables a view reads, following views through views. */
function underlyingTables(model: SupabaseModel, sources: QName[], depth = 0, seen = new Set<string>()): QName[] {
  const out: QName[] = [];
  for (const s of sources) {
    const k = qkey(s);
    if (seen.has(k)) continue;
    seen.add(k);
    const view = model.views.get(k);
    if (view && depth < 8) out.push(...underlyingTables(model, view.sources, depth + 1, seen));
    else out.push(s);
  }
  return out;
}

/** "read", "read and write", "get, list and delete". */
export function listWords(words: readonly string[]): string {
  if (words.length <= 1) return words.join("");
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

function firstLine(text: string): string {
  return text.replace(/\s+/g, " ").trim();
}

export const databaseRulesRule = defineRule({
  id: "web/database-rules",
  title: "Database open to the public",
  pack: "web",
  maturity: "experimental",
  source: SOURCES.owaspTop10,
  appliesTo: (ctx) => (ctx.detection?.backends.size ?? 0) > 0,
  check(ctx, emit) {
    const groups = supabaseGroups(ctx);
    const rulesFiles = firebaseRulesFiles(ctx);
    if (groups.size === 0 && rulesFiles.length === 0) {
      throw new NotChecked(NO_FILES, "Database rules");
    }
    const backends = ctx.detection.backends;
    if (backends.has("supabase") && groups.size === 0) ctx.addGap("Database rules", "no Supabase migrations in the repo");
    if (backends.has("firebase") && rulesFiles.length === 0) ctx.addGap("Database rules", "no Firebase rules files in the repo");

    // ---- Supabase
    for (const base of [...groups.keys()].sort()) {
      const g = groups.get(base)!;
      const files = [...g.schemas, ...g.migrations].map((file) => ({ file, text: ctx.read(file) ?? "" }));
      const model = buildSupabaseModel(files);

      for (const t of [...model.tables.values()].sort((a, b) => (qkey(a) < qkey(b) ? -1 : 1))) {
        if (t.schema !== "public" || t.rls) continue;
        const loc = t.disabledAt ?? t.created;
        if (!loc) continue;
        emit({
          severity: "critical",
          service: serviceFor(ctx, loc.file),
          file: loc.file,
          line: loc.line,
          anchor: `table:${qkey(t)}`,
          evidence: firstLine(loc.text),
          why: WHY,
          fix: {
            summary: `${t.disabledAt ? "Row level security is turned off again here. " : ""}Enable row level security on this table (alter table … enable row level security;) and add owner-based policies, for example using (auth.uid() = user_id).`,
          },
          source: SUPABASE_SOURCE,
        });
      }

      for (const p of [...model.policies.values()].sort((a, b) => (`${qkey(a.table)}\u0000${a.name}` < `${qkey(b.table)}\u0000${b.name}` ? -1 : 1))) {
        if (!p.permissive) continue;
        if (p.roles.length > 0 && !p.roles.some((r) => PUBLIC_ROLES.has(r))) continue;
        if (!isLiteralTrue(p.using) && !isLiteralTrue(p.check)) continue;
        const readOnly = p.command === "select";
        emit({
          severity: readOnly ? "medium" : "high",
          advisory: readOnly,
          service: serviceFor(ctx, p.loc.file),
          file: p.loc.file,
          line: p.loc.line,
          anchor: `policy:${qkey(p.table)}:${p.name}`,
          evidence: firstLine(p.loc.text),
          why: WHY,
          fix: {
            summary: readOnly
              ? "This policy lets anyone, signed in or not, read every row of the table. Keep it only if the rows are meant to be public; otherwise check ownership, for example using (auth.uid() = user_id)."
              : `This policy lets anyone, signed in or not, ${p.command === "all" ? "read and change" : p.command} rows of the table. Replace true with an ownership check such as (auth.uid() = user_id) and limit it to the authenticated role.`,
          },
          source: SUPABASE_SOURCE,
        });
      }

      for (const v of [...model.views.values()].sort((a, b) => (qkey(a) < qkey(b) ? -1 : 1))) {
        if (v.schema !== "public" || v.securityInvoker) continue;
        const protectedTable = underlyingTables(model, v.sources).find((s) => model.tables.get(qkey(s))?.rls === true);
        if (!protectedTable) continue;
        emit({
          severity: "high",
          service: serviceFor(ctx, v.loc.file),
          file: v.loc.file,
          line: v.loc.line,
          anchor: `view:${qkey(v)}`,
          evidence: `reads ${displayName(protectedTable)} (row level security on): ${firstLine(v.loc.text)}`,
          why: WHY,
          fix: {
            summary: v.materialized
              ? "A materialized view does not apply the row level security of the tables it reads. Move it out of the public schema or revoke select on it from anon and authenticated."
              : "The view runs with its owner's rights and skips the row level security of the tables it reads. Recreate it with (security_invoker = true), or revoke select on it from anon and authenticated.",
          },
          source: SUPABASE_SOURCE,
        });
      }
    }

    // ---- Firebase
    for (const rf of rulesFiles) {
      const text = ctx.read(rf.file);
      if (text === null) continue;
      if (rf.kind === "rtdb") {
        const rules = parseRtdbRules(text);
        if (!rules) {
          ctx.addGap("Database rules", `${rf.file} could not be parsed`);
          continue;
        }
        for (const r of rules) {
          const verdict = classifyRtdb(r);
          if (!verdict) continue;
          emit({
            severity: verdict === "open" ? "critical" : "high",
            advisory: verdict === "auth-only",
            service: serviceFor(ctx, rf.file),
            file: rf.file,
            line: r.line,
            anchor: r.path,
            evidence: r.text,
            why: WHY,
            fix: {
              summary:
                verdict === "open"
                  ? `Anyone can ${r.key === ".read" ? "read" : "write"} this path. Require sign-in and check ownership, for example ".${r.key.slice(1)}": "auth != null && auth.uid === $uid" under a "$uid" key.`
                  : `Any signed-in user can ${r.key === ".read" ? "read" : "write"} everything under this path. Compare auth.uid with the owner, for example "auth.uid === $uid".`,
            },
            source: FIREBASE_SOURCE,
          });
        }
        continue;
      }
      const parsed = parseRulesFile(text);
      for (const a of parsed.allows) {
        const verdict = classifyAllow(a, parsed.functions);
        if (!verdict) continue;
        const open = verdict.kind === "open";
        // Method names are project text: only known ones are named in the (fixed) summary.
        const known = a.methods.filter((m) => KNOWN_METHODS.has(m));
        const methods = known.length === a.methods.length && known.length > 0 ? listWords(known) : "access";
        const example = known.length === a.methods.length && known.length > 0 ? known.join(", ") : "read";
        const noun = a.service === "firebase.storage" ? "file" : "document";
        emit({
          severity: open ? "critical" : "high",
          advisory: !open,
          service: serviceFor(ctx, rf.file),
          file: rf.file,
          line: a.line,
          anchor: `${a.service}:${a.paths.join("")}:allow ${a.methods.join(",")}`,
          evidence: a.text,
          why: WHY,
          fix: {
            summary: open
              ? `This rule lets anyone ${methods} (${verdict.reason}). Require sign-in and check ownership, for example: allow ${example}: if request.auth != null && request.auth.uid == userId;`
              : `Any signed-in user can ${methods} every ${noun} matched here. Compare request.auth.uid with the owner, for example the {userId} wildcard or resource.data.ownerId.`,
          },
          source: FIREBASE_SOURCE,
        });
      }
    }
  },
});
