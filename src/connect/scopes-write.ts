// Appending a server scope to ~/.secor/scopes.yaml (spec section 9.3 step 5). This is the one place SECOR writes
// that file, and only from the interactive `secor connect add` command run by a human (invariant 6).
//
// The human's existing text is kept byte for byte where possible: the new entry is inserted as text at the end
// of the `servers:` block. Only when the file's shape makes that impossible (no block map to append to) does it
// fall back to the yaml Document API, which keeps comments but may normalise spacing.

import { existsSync, readFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { Document, isMap, isScalar, isSeq, parseDocument } from "yaml";
import { ConfigError, validate } from "../engine/config.js";
import { writeFileAtomic } from "../engine/util/fsx.js";
import type { DataClass } from "../types.js";
import { backupFile } from "./backup.js";
import { ScopesFileSchema, scopesPath } from "./scopes.js";

export interface NewServerScope {
  tools?: string[];
  never?: DataClass[];
  sandbox?: { mounts: string[] };
}

export const SCOPES_TEMPLATE = `# SECOR Connect scopes (spec section 6.3). Edited by humans only; SECOR appends a server here only
# during the interactive \`secor connect add\` command.
version: 1
# defaults:
#   never: [secret, credential, personal_data, confidential]
#   onViolation: ask          # ask | block
#   unvetted: ask             # pass | ask | block: calls to unmanaged servers
#   maxArgChars: 20000        # larger tool arguments count as a violation
#   failMode: open            # open | closed
# confidential:
#   paths: []                 # files whose content is tracked when the agent reads them
#   patterns: []              # regexes for text you mark confidential
`;

/** YAML text for one `name: {...}` entry at column 0 (lists of scalars in flow style, like the spec example). */
export function scopeEntryYaml(name: string, entry: NewServerScope): string {
  const doc = new Document({ [name]: entry });
  const value = doc.get(name, true);
  if (isMap(value)) {
    for (const item of value.items) {
      if (isSeq(item.value) && item.value.items.every((i) => isScalar(i))) item.value.flow = true;
      if (isMap(item.value)) for (const sub of item.value.items) if (isSeq(sub.value) && sub.value.items.every((i) => isScalar(i))) sub.value.flow = true;
    }
  }
  return doc.toString({ lineWidth: 0, flowCollectionPadding: false });
}

function indentLines(text: string, indent: string): string {
  return text
    .split("\n")
    .map((l) => (l ? indent + l : l))
    .join("\n");
}

function lineStart(text: string, offset: number): number {
  const nl = text.lastIndexOf("\n", offset - 1);
  return nl + 1;
}

function plainJs(text: string): unknown {
  const doc = parseDocument(text, { prettyErrors: true });
  if (doc.errors.length) throw new ConfigError(`~/.secor/scopes.yaml: invalid YAML: ${doc.errors[0]!.message.split("\n")[0]}`);
  return doc.toJS({ maxAliasCount: 50 }) ?? null;
}

function textualInsert(text: string, name: string, entry: NewServerScope, comment: string): string | null {
  const doc = parseDocument(text);
  if (doc.errors.length) return null;
  const root = doc.contents;
  if (!isMap(root)) return null;
  const pair = root.items.find((p) => isScalar(p.key) && p.key.value === "servers");
  const entryText = scopeEntryYaml(name, entry);
  if (!pair) {
    const sep = text.length === 0 || text.endsWith("\n") ? "" : "\n";
    return `${text}${sep}servers:\n${indentLines(`# ${comment}\n${entryText}`, "  ")}`;
  }
  const servers = pair.value;
  // `servers:` with no value, or `servers: {}`: put the entry on the lines after the key, keeping any comment.
  const emptyNull = isScalar(servers) && servers.value === null;
  const emptyFlow = isMap(servers) && servers.flow === true && servers.items.length === 0;
  if ((emptyNull || emptyFlow) && isScalar(pair.key) && pair.key.range && servers?.range) {
    let base = text;
    if (emptyFlow) base = text.slice(0, servers.range[0]) + text.slice(servers.range[1]);
    const nl = base.indexOf("\n", pair.key.range[1]);
    const at = nl < 0 ? base.length : nl;
    const keyCol = pair.key.range[0] - lineStart(base, pair.key.range[0]);
    return `${base.slice(0, at)}\n${indentLines(`# ${comment}\n${entryText}`, " ".repeat(keyCol + 2)).replace(/\n$/, "")}${base.slice(at)}${nl < 0 ? "\n" : ""}`;
  }
  if (!isMap(servers) || servers.flow || servers.items.length === 0 || !servers.range) return null;
  const firstKey = servers.items[0]!.key;
  if (!isScalar(firstKey) || !firstKey.range) return null;
  const col = firstKey.range[0] - lineStart(text, firstKey.range[0]);
  const at = servers.range[1];
  const before = text.slice(0, at);
  const sep = before.endsWith("\n") ? "" : "\n";
  return `${before}${sep}${indentLines(`# ${comment}\n${entryText}`, " ".repeat(col))}${text.slice(at)}`;
}

function documentInsert(text: string, name: string, entry: NewServerScope, comment: string): string | null {
  const doc = parseDocument(text);
  if (doc.errors.length || !isMap(doc.contents)) return null;
  let servers = doc.get("servers", true);
  if (!isMap(servers)) {
    const node = doc.createNode({});
    node.flow = false;
    doc.set("servers", node);
    servers = doc.get("servers", true);
  }
  if (!isMap(servers)) throw new ConfigError("~/.secor/scopes.yaml: could not add the server entry");
  servers.flow = false;
  const entryDoc = parseDocument(scopeEntryYaml(name, entry));
  const entryMap = entryDoc.contents;
  if (!isMap(entryMap) || !entryMap.items[0]) throw new ConfigError("~/.secor/scopes.yaml: could not build the server entry");
  const item = entryMap.items[0];
  if (isScalar(item.key)) item.key.commentBefore = ` ${comment}`;
  servers.items.push(item);
  return doc.toString({ lineWidth: 0, flowCollectionPadding: false });
}

/**
 * New scopes.yaml text with `name` appended under `servers`. The result is checked to equal the original data plus
 * exactly the new entry, and to validate against the scopes schema.
 */
export function appendServerScope(text: string | null, name: string, entry: NewServerScope, date: string): string {
  let original = text ?? SCOPES_TEMPLATE;
  let parsed = plainJs(original);
  if (parsed === null) {
    // An empty or all-comment file: keep the human's text and start the document after it.
    original = `${original}${original === "" || original.endsWith("\n") ? "" : "\n"}version: 1\n`;
    parsed = plainJs(original);
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new ConfigError("~/.secor/scopes.yaml: expected a mapping at the top level");
  const before = parsed as Record<string, unknown>;
  const existing = before.servers;
  if (existing && typeof existing === "object" && Object.hasOwn(existing, name)) {
    throw new ConfigError(`~/.secor/scopes.yaml already has a scope for "${name}"; edit it there`);
  }
  const comment = `added by secor connect add on ${date}`;
  const expected = { ...before, servers: { ...((existing && typeof existing === "object" ? existing : {}) as Record<string, unknown>), [name]: JSON.parse(JSON.stringify(entry)) as unknown } };
  for (const attempt of [textualInsert, documentInsert]) {
    const out = attempt(original, name, entry, comment);
    if (out === null) continue;
    let after: unknown;
    try {
      after = plainJs(out);
    } catch {
      continue;
    }
    if (isDeepStrictEqual(after, expected)) {
      validate(ScopesFileSchema, after, "~/.secor/scopes.yaml");
      return out.endsWith("\n") ? out : `${out}\n`;
    }
  }
  throw new ConfigError("~/.secor/scopes.yaml: could not append the server entry without changing other content; add it by hand");
}

/** Append the scope to ~/.secor/scopes.yaml (backing the old file up first). Returns the backup path, if any. */
export function writeServerScope(name: string, entry: NewServerScope, now: Date, path = scopesPath()): string | null {
  const text = existsSync(path) ? readFileSync(path, "utf8") : null;
  const next = appendServerScope(text, name, entry, now.toISOString().slice(0, 10));
  const backup = text === null ? null : backupFile(path, now);
  writeFileAtomic(path, next, 0o600);
  return backup;
}
