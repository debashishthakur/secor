// mcp/tool-scope (spec section 8.5): a tool handler reads/writes files with a path from tool input and no
// containment check (high), starts a process with input-derived arguments and no allowlist (high), or
// interpolates tool input into a shell command string (critical).

import { posix } from "node:path";
import {
  anchorText,
  args,
  callee,
  calleeName,
  calleePath,
  callsIn,
  closest,
  elements,
  enclosingFunction,
  exportsOf,
  exprPath,
  importOf,
  isCall,
  isInside,
  kids,
  kwarg,
  line,
  params,
  paramPattern,
  positionalArgs,
  prop,
  pyParam,
  resolveLocal,
  stringValue,
  topLevel,
  unwrap,
  walk,
} from "../../ast.js";
import type { ProjectContext } from "../../context.js";
import { findingId } from "../../finding.js";
import type { HandlerRef, InventoryEntry } from "../../inventory-types.js";
import { type ParsedFile, type SyntaxNode, memo } from "../../parse.js";
import { renderTestTemplate } from "../../templates.js";
import type { Framework } from "../../../types.js";
import { SOURCES, defineRule } from "../types.js";
import {
  Taint,
  bindingsIn,
  calledFunction,
  isSanitized,
  isShellQuoted,
  objectPatternEntries,
  pyFlavor,
  recordAllowlists,
  safeSchemaKeysTs,
  safeTypedParamsPy,
} from "./common.js";

const RULE_ID = "mcp/tool-scope";
const WHY =
  "The client, or a model steered by injected text, chooses this tool's arguments. Without a containment check or an allowlist it can reach any file or command the server's account can.";
const FIX = "Resolve paths and check them against an allowed root; allow only a fixed set of commands, without a shell.";

// ---------------------------------------------------------------- sink tables

const FS_SOURCES = new Set(["fs", "node:fs", "fs/promises", "node:fs/promises", "fs-extra", "graceful-fs"]);
/** fs functions that only inspect metadata or resolve paths: not file access for this rule. */
const FS_NOT_ACCESS = new Set(["existsSync", "exists", "stat", "statSync", "lstat", "lstatSync", "access", "accessSync", "realpath", "realpathSync", "native", "constants", "watch", "watchFile", "unwatchFile", "pathExists", "pathExistsSync"]);
const FS_TWO_PATHS = new Set(["rename", "renameSync", "copyFile", "copyFileSync", "cp", "cpSync", "symlink", "symlinkSync", "link", "linkSync", "copy", "copySync", "move", "moveSync"]);
const CP_SOURCES = new Set(["child_process", "node:child_process"]);
const CP_FUNCS = new Set(["exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync", "fork"]);
const CP_SHELL_FUNCS = new Set(["exec", "execSync"]);

const PY_OS_FILE = new Set(["remove", "unlink", "rmdir", "removedirs", "listdir", "scandir", "makedirs", "mkdir", "rename", "renames", "replace", "walk", "chmod", "chown", "symlink", "link", "truncate", "open"]);
const PY_TWO_PATHS = new Set(["rename", "renames", "replace", "symlink", "link", "copy", "copy2", "copyfile", "copytree", "move", "copymode", "copystat"]);
const PY_SHUTIL_NOT_ACCESS = new Set(["which", "disk_usage", "get_terminal_size", "register_archive_format", "unregister_archive_format", "get_archive_formats", "get_unpack_formats", "register_unpack_format", "unregister_unpack_format"]);
const PY_PATH_METHODS = new Set(["read_text", "write_text", "read_bytes", "write_bytes", "open", "unlink", "rmdir", "touch", "iterdir", "mkdir", "glob", "rglob"]);
const PY_OPEN = /^(?:open|io\.open|os\.open|codecs\.open|aiofiles\.open|anyio\.open_file|trio\.open_file)$/;
const PY_SUBPROCESS = new Set(["run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"]);
/** Qualified names (imports are resolved by pyQualified: `from os import system` → os.system). */
const PY_ALWAYS_SHELL = /^(?:os\.system|os\.popen|subprocess\.getoutput|subprocess\.getstatusoutput|asyncio\.create_subprocess_shell)$/;
const PY_EXEC_ALL_ARGS = /^(?:asyncio\.create_subprocess_exec|os\.exec\w*|os\.spawn\w*|os\.posix_spawn\w*)$/;
const SHELL_BINARIES = /^(?:\/(?:usr\/)?bin\/)?(?:sh|bash|zsh|dash|ksh|fish|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh)$/;

/** Helper names that, called with the input, count as a path containment check (DECISIONS.md). */
const PATH_VALIDATOR =
  /^(?:validate|check|ensure|assert|verify|sanitize|sanitise|safe|secure)_?\w*(?:path|file|dir|directory|location)\w*$|^(?:is|ensure|assert|check)_?\w*(?:within|inside|allowed|contained|sandbox)\w*$|^safe_?(?:join|open|resolve)$/i;

// ---------------------------------------------------------------- sinks

interface Sink {
  pf: ParsedFile;
  call: SyntaxNode;
  kind: "file" | "process";
  severity: "critical" | "high";
  /** File sinks: the path argument that carries tool input. */
  input?: SyntaxNode;
}

interface JsAliases {
  /** local name → child_process function, for promisify(exec) style aliases. */
  cp: Map<string, string>;
}

function jsAliases(pf: ParsedFile): JsAliases {
  return memo(pf, "mcp/tool-scope:aliases", () => ({ cp: promisifiedProcessFns(pf) }));
}

function promisifiedProcessFns(pf: ParsedFile): Map<string, string> {
  const cp = new Map<string, string>();
  walk(pf.root, (n) => {
    if (n.type !== "variable_declarator") return true;
    const name = n.childForFieldName("name");
    const value = unwrap(n.childForFieldName("value"));
    if (name?.type !== "identifier" || !value || !isCall(value) || calleeName(value) !== "promisify") return true;
    const target = args(value)[0];
    const fn = target ? jsProcessFn(pf, target, new Map()) : null;
    if (fn) cp.set(name.text, fn);
    return true;
  });
  return cp;
}

/** child_process function referenced by a callee expression (`exec`, `cp.exec`, `require("child_process").exec`). */
function jsProcessFn(pf: ParsedFile, fnNode: SyntaxNode, aliases: Map<string, string>): string | null {
  const u = unwrap(fnNode);
  if (!u) return null;
  if (u.type === "identifier") {
    const alias = aliases.get(u.text);
    if (alias) return alias;
    const imp = importOf(pf, u.text);
    if (imp && CP_SOURCES.has(imp.source) && CP_FUNCS.has(imp.imported)) return imp.imported;
    return null;
  }
  if (u.type === "member_expression") {
    const prop = u.childForFieldName("property")?.text ?? "";
    if (!CP_FUNCS.has(prop)) return null;
    const obj = unwrap(u.childForFieldName("object"));
    if (!obj) return null;
    if (obj.type === "identifier") {
      const imp = importOf(pf, obj.text);
      if (imp ? CP_SOURCES.has(imp.source) : /^(?:child_process|childProcess|cp)$/.test(obj.text)) return prop;
    }
    if (isCall(obj) && calleePath(obj) === "require" && CP_SOURCES.has(stringValue(args(obj)[0] ?? null) ?? "")) return prop;
  }
  return null;
}

/** fs function called by `call` (`fs.readFile`, `fs.promises.readFile`, `readFile` imported from fs/promises). */
function jsFsFn(pf: ParsedFile, call: SyntaxNode): string | null {
  const fn = unwrap(callee(call));
  if (!fn) return null;
  if (fn.type === "identifier") {
    const imp = importOf(pf, fn.text);
    if (imp && FS_SOURCES.has(imp.source) && imp.imported !== "*" && imp.imported !== "default") return imp.imported;
    return null;
  }
  if (fn.type !== "member_expression") return null;
  const segs = exprPath(fn).split(".");
  const head = segs[0] ?? "";
  const imp = importOf(pf, head);
  const isFs = imp ? FS_SOURCES.has(imp.source) : /^(?:fs|fsp|fsPromises|fse|fsExtra)$/.test(head);
  if (!isFs) return null;
  if (segs.length === 2 || (segs.length === 3 && segs[1] === "promises")) return segs[segs.length - 1] ?? null;
  return null;
}

function shellOption(options: SyntaxNode | null | undefined): boolean {
  const o = unwrap(options ?? null);
  if (!o || o.type !== "object") return false;
  for (const c of kids(o)) {
    if (c.type === "pair" && c.childForFieldName("key")?.text === "shell") {
      const v = unwrap(c.childForFieldName("value"));
      return !!v && v.type !== "false" && v.text !== "undefined" && v.text !== "null";
    }
    if (c.type === "shorthand_property_identifier" && c.text === "shell") return true;
  }
  return false;
}

/** Does `n` build a command string that embeds tainted input (template literal, `+`, `.join`, f-string, `%`, `.format`)? */
function interpolates(pf: ParsedFile, n: SyntaxNode | null, t: Taint, depth = 0): boolean {
  const u = unwrap(n);
  if (!u || depth > 3) return false;
  const tainted = (x: SyntaxNode | null) => t.has(x, isShellQuoted);
  switch (u.type) {
    case "template_string":
      return kids(u).some((c) => c.type === "template_substitution" && tainted(c));
    case "string":
      return pf.lang === "python" && kids(u).some((c) => c.type === "interpolation" && tainted(c));
    case "binary_expression":
    case "binary_operator": {
      const op = u.childForFieldName("operator")?.text ?? "";
      if (op !== "+" && op !== "%") return false;
      return tainted(u.childForFieldName("left")) || tainted(u.childForFieldName("right"));
    }
    case "call_expression":
    case "call": {
      const name = calleeName(u);
      const fn = callee(u);
      const recv = fn ? unwrap(fn.childForFieldName("object")) : null;
      if (name === "join" && recv) return tainted(recv);
      if (name === "format" && recv && stringValue(recv) !== null) return args(u).some((a) => tainted(a));
      return false;
    }
    case "identifier": {
      const v = resolveLocal(pf, u.text, u);
      return !!v && v.id !== u.id && interpolates(pf, v, t, depth + 1);
    }
    default:
      return false;
  }
}

/** `["sh", "-c", cmd]`-style invocation: the command string after -c. */
function shellDashC(cmd: SyntaxNode | null, argv: SyntaxNode[]): SyntaxNode | null {
  const bin = stringValue(cmd);
  if (bin !== null && SHELL_BINARIES.test(bin)) {
    const i = argv.findIndex((a) => /^\/?-?c$|^\/c$|^-Command$/i.test(stringValue(a) ?? ""));
    return i >= 0 ? (argv[i + 1] ?? null) : null;
  }
  // subprocess.run(["sh", "-c", f"..."])
  const first = argv[0] ? stringValue(argv[0]) : null;
  if (first !== null && SHELL_BINARIES.test(first)) {
    const i = argv.findIndex((a, k) => k > 0 && /^-?c$|^\/c$|^-Command$/i.test(stringValue(a) ?? ""));
    return i >= 0 ? (argv[i + 1] ?? null) : null;
  }
  return null;
}

/**
 * Severity for a process start. `argvInShell`: with a shell, Node joins the argument array into the command
 * string (critical when it holds input); Python passes list items after the first to the shell as `$0 $1 ...`.
 */
function processSeverity(pf: ParsedFile, t: Taint, cmd: SyntaxNode | null, argv: SyntaxNode[], shell: boolean, argvInShell: boolean): Sink["severity"] | null {
  const dashC = shellDashC(cmd, argv);
  if (shell && interpolates(pf, cmd, t)) return "critical";
  if (shell && argvInShell && argv.some((a) => t.has(a, isShellQuoted))) return "critical";
  if (shell && !argvInShell && argv[0] && interpolates(pf, argv[0], t)) return "critical";
  if (dashC && interpolates(pf, dashC, t)) return "critical";
  if (t.has(cmd) || argv.some((a) => t.has(a))) return "high";
  return null;
}

function jsSink(pf: ParsedFile, call: SyntaxNode, t: Taint, contained: boolean, aliases: JsAliases): Sink | null {
  const a = args(call);
  const fsFn = jsFsFn(pf, call);
  if (fsFn) {
    if (FS_NOT_ACCESS.has(fsFn) || contained) return null;
    const paths = FS_TWO_PATHS.has(fsFn) ? a.slice(0, 2) : a.slice(0, 1);
    const input = paths.find((p) => t.has(p));
    return input ? { pf, call, kind: "file", severity: "high", input } : null;
  }
  const fnNode = callee(call);
  const cp = fnNode ? jsProcessFn(pf, fnNode, aliases.cp) : null;
  if (!cp) return null;
  const cmd = a[0] ?? null;
  let argv: SyntaxNode[] = [];
  let options: SyntaxNode | null = null;
  if (CP_SHELL_FUNCS.has(cp)) options = a[1] ?? null;
  else if (unwrap(a[1] ?? null)?.type === "array") {
    argv = elements(a[1]!);
    options = a[2] ?? null;
  } else options = a[1] ?? null;
  const shell = CP_SHELL_FUNCS.has(cp) || shellOption(options);
  const severity = processSeverity(pf, t, cmd, argv, shell, true);
  return severity ? { pf, call, kind: "process", severity } : null;
}

/** Python callee resolved through `from os import remove` style imports to a dotted name ("os.remove"). */
function pyQualified(pf: ParsedFile, call: SyntaxNode): string {
  const path = calleePath(call);
  const head = path.split(".")[0] ?? path;
  const imp = importOf(pf, head);
  if (imp && imp.imported !== "*" && path === head) return `${imp.source}.${imp.imported}`;
  return path;
}

function pySink(pf: ParsedFile, call: SyntaxNode, t: Taint, contained: boolean): Sink | null {
  const q = pyQualified(pf, call);
  const pos = positionalArgs(call);
  const segs = q.split(".");
  const name = segs[segs.length - 1] ?? "";
  // Files
  let paths: (SyntaxNode | null)[] | null = null;
  if (PY_OPEN.test(q) || q === "builtins.open") paths = [pos[0] ?? kwarg(call, "file")];
  else if (segs.length === 2 && segs[0] === "os" && PY_OS_FILE.has(name)) paths = PY_TWO_PATHS.has(name) ? [pos[0] ?? kwarg(call, "src"), pos[1] ?? kwarg(call, "dst")] : [pos[0] ?? kwarg(call, "path")];
  else if (segs.length === 2 && segs[0] === "shutil" && !PY_SHUTIL_NOT_ACCESS.has(name)) paths = [pos[0] ?? kwarg(call, "src") ?? kwarg(call, "path"), pos[1] ?? kwarg(call, "dst")];
  else {
    const fn = callee(call);
    if (fn?.type === "attribute" && PY_PATH_METHODS.has(fn.childForFieldName("attribute")?.text ?? "")) {
      const recv = fn.childForFieldName("object");
      // Only path objects: a tainted receiver that is not a module.
      if (recv && !(recv.type === "identifier" && importOf(pf, recv.text))) paths = [recv];
    }
  }
  if (paths) {
    if (contained) return null;
    const input = paths.find((p) => t.has(p));
    return input ? { pf, call, kind: "file", severity: "high", input } : null;
  }
  // Processes
  const isSubprocess = segs.length === 2 && segs[0] === "subprocess" && PY_SUBPROCESS.has(name);
  const alwaysShell = PY_ALWAYS_SHELL.test(q);
  const execAll = PY_EXEC_ALL_ARGS.test(q);
  if (!isSubprocess && !alwaysShell && !execAll) return null;
  const cmd = pos[0] ?? kwarg(call, "args") ?? kwarg(call, "cmd") ?? kwarg(call, "command");
  let argv: SyntaxNode[] = [];
  if (execAll) argv = pos.slice(1);
  else if (cmd && ["list", "tuple"].includes(unwrap(cmd)?.type ?? "")) argv = elements(cmd);
  const shellArg = kwarg(call, "shell");
  const shell = alwaysShell || (!!shellArg && shellArg.type !== "false" && shellArg.type !== "none");
  const cmdNode = argv.length && !execAll ? null : cmd;
  const severity = processSeverity(pf, t, cmdNode, argv, shell, false);
  return severity ? { pf, call, kind: "process", severity } : null;
}

// ---------------------------------------------------------------- containment

function isPathResolve(pf: ParsedFile, call: SyntaxNode): boolean {
  const path = calleePath(call);
  if (/realpath(?:Sync)?(?:\.native)?$/.test(path) || /(?:^|\.)realpath$/.test(path)) return true;
  if (pf.lang === "python") {
    if (/^(?:os\.path\.)?(?:realpath|abspath|normpath)$/.test(path)) return true;
    const fn = callee(call);
    return fn?.type === "attribute" && fn.childForFieldName("attribute")?.text === "resolve";
  }
  if (/^(?:path|posix|win32|path\.posix|path\.win32|nodePath)\.(?:resolve|normalize|relative)$/.test(path)) return true;
  if (/^(?:resolve|normalize|relative)$/.test(path)) return /^(?:node:)?path(?:\/posix)?$/.test(importOf(pf, path)?.source ?? "");
  return false;
}

function isRootCheck(call: SyntaxNode): boolean {
  return /^(?:startsWith|startswith|is_relative_to|relative_to|commonpath|commonprefix)$/.test(calleeName(call));
}

/**
 * A containment check for the handler: the path is resolved and compared with an allowed root in the handler, or in
 * project helpers it calls with the input (two levels deep: `writableNote(args.note)` → `writable(id)` → resolve +
 * startsWith), or the input goes through a helper named like a path validator (DECISIONS.md).
 */
function hasContainment(ctx: ProjectContext, pf: ParsedFile, fn: SyntaxNode, t: Taint): boolean {
  const calls = callsIn(fn);
  if (calls.some((c) => isPathResolve(pf, c)) && calls.some(isRootCheck)) return true;
  for (const c of calls) {
    if (!args(c).some((a) => t.has(a))) continue;
    if (PATH_VALIDATOR.test(calleeName(c))) return true;
    const target = calledFunction(ctx, pf, c);
    if (target && target.node.id !== fn.id && helperContains(ctx, target.pf, target.node, 1, new Set([fn.id, target.node.id]))) return true;
  }
  return false;
}

function helperContains(ctx: ProjectContext, pf: ParsedFile, fn: SyntaxNode, depth: number, seen: Set<number>): boolean {
  const calls = callsIn(fn);
  if (calls.some((c) => isPathResolve(pf, c)) && calls.some(isRootCheck)) return true;
  if (depth >= 2) return false;
  for (const c of calls) {
    if (PATH_VALIDATOR.test(calleeName(c))) return true;
    const target = calledFunction(ctx, pf, c);
    if (!target || seen.has(target.node.id)) continue;
    seen.add(target.node.id);
    if (helperContains(ctx, target.pf, target.node, depth + 1, seen)) return true;
  }
  return false;
}

// ---------------------------------------------------------------- handler analysis

interface Analysis {
  sinks: Sink[];
}

function newTaint(pf: ParsedFile, seeds: Iterable<string>): Taint {
  return new Taint({ seeds, isClean: (n) => isSanitized(pf, n) });
}

/** Analyse one function with its tainted parameters; `depth` 0 follows helper calls one level. */
function analyzeFunction(ctx: ProjectContext, pf: ParsedFile, fn: SyntaxNode, t: Taint, containedAbove: boolean, depth: number, out: Analysis): void {
  recordAllowlists(pf, fn, t);
  t.propagate(bindingsIn(fn, true));
  const contained = containedAbove || hasContainment(ctx, pf, fn, t);
  const aliases = pf.lang === "python" ? null : jsAliases(pf);
  for (const call of callsIn(fn)) {
    const sink = pf.lang === "python" ? pySink(pf, call, t, contained) : jsSink(pf, call, t, contained, aliases!);
    if (sink) {
      out.sinks.push(sink);
      continue;
    }
    if (depth > 0) continue;
    // One level into project helpers that receive tool input.
    const a = args(call);
    if (!a.some((x) => t.has(x))) continue;
    const target = calledFunction(ctx, pf, call);
    if (!target || target.node.id === fn.id) continue;
    const ps = params(target.node);
    const seeds: string[] = [];
    let i = 0;
    for (const arg of a) {
      if (arg.type === "keyword_argument") {
        if (t.has(arg.childForFieldName("value"))) seeds.push(arg.childForFieldName("name")?.text ?? "");
        continue;
      }
      const p = ps[i++];
      if (!p || !t.has(arg)) continue;
      const py = pyParam(p);
      if (py) seeds.push(py.name);
      else seeds.push(...bindingNames(p));
    }
    const inner = newTaint(target.pf, seeds.filter(Boolean));
    analyzeFunction(ctx, target.pf, target.node, inner, contained, depth + 1, out);
  }
}

function bindingNames(p: SyntaxNode): string[] {
  const pat = paramPattern(p);
  if (pat.type === "identifier") return [pat.text];
  if (pat.type === "object_pattern") return objectPatternEntries(pat).flatMap((e) => e.names);
  return [];
}

/** Destructured locals of the first parameter: key → local names (`({ path: p })` → path → [p]). */
function firstParamKeys(fn: SyntaxNode): Map<string, string[]> {
  const out = new Map<string, string[]>();
  const first = params(fn)[0];
  if (!first) return out;
  const pat = paramPattern(first);
  if (pat.type !== "object_pattern") return out;
  for (const e of objectPatternEntries(pat)) out.set(e.key, e.names);
  return out;
}

/**
 * Does a TS registration declare tool input? `tool(name, cb)`, `tool(name, "description", cb)` and
 * `registerTool(name, { description }, cb)` call `cb(extra)`: the first parameter is request metadata, not input.
 */
function tsToolTakesInput(registration: SyntaxNode, handler: SyntaxNode): boolean {
  const method = calleeName(registration);
  const rest = args(registration)
    .slice(1)
    .filter((a) => !(a.startIndex <= handler.startIndex && a.endIndex >= handler.endIndex));
  if (method === "registerTool") {
    const config = unwrap(rest[0] ?? null);
    return !config || config.type !== "object" || !!prop(config, "inputSchema");
  }
  if (method === "tool") {
    return rest.some((a) => {
      const u = unwrap(a);
      if (!u || stringValue(u) !== null) return false;
      if (u.type === "object") return kids(u).some((p) => p.type === "pair" && /^z\s*\./.test(p.childForFieldName("value")?.text ?? ""));
      return true;
    });
  }
  return true;
}

function analyzeHandler(ctx: ProjectContext, entry: InventoryEntry, h: HandlerRef): Sink[] {
  const pf = h.pf;
  const takesInput = pf.lang === "python" || tsToolTakesInput(entry.internal.registration.node, h.node);
  const t = newTaint(pf, takesInput ? entry.internal.inputNames : []);
  if (pf.lang === "python") {
    for (const n of safeTypedParamsPy(pf, h.node)) t.cleanNames.add(n);
  } else {
    const safe = safeSchemaKeysTs(entry.internal.registration.node, h.node);
    const keys = firstParamKeys(h.node);
    for (const k of safe) {
      t.cleanKeys.add(k);
      for (const local of keys.get(k) ?? []) t.cleanNames.add(local);
    }
  }
  const out: Analysis = { sinks: [] };
  analyzeFunction(ctx, pf, h.node, t, false, 0, out);
  return out.sinks;
}

// ---------------------------------------------------------------- tool selection for shared handlers

/** For a low-level handler serving several tools, the entry whose `case "name":` / `if name == "name"` holds the sink. */
function entryForSink(group: InventoryEntry[], handler: SyntaxNode, call: SyntaxNode): InventoryEntry {
  if (group.length > 1) {
    const names = new Map(group.map((e) => [e.name ?? "", e]));
    for (let n: SyntaxNode | null = call.parent; n && n.id !== handler.id; n = n.parent) {
      if (n.type === "switch_case") {
        const v = stringValue(n.childForFieldName("value"));
        if (v !== null && names.has(v)) return names.get(v)!;
      }
      if (n.type === "case_clause") {
        const v = stringValue(kids(n)[0]?.descendantsOfType("string")[0] ?? null);
        if (v !== null && names.has(v)) return names.get(v)!;
      }
      if (n.type === "if_statement" || n.type === "elif_clause") {
        const cond = n.childForFieldName("condition");
        const consequence = n.childForFieldName("consequence");
        if (cond && consequence && isInside(call, consequence)) {
          for (const s of [...cond.descendantsOfType("string")]) {
            const v = stringValue(s ?? null);
            if (v !== null && names.has(v)) return names.get(v)!;
          }
        }
      }
    }
  }
  return [...group].sort((a, b) => cmp(a.name ?? "", b.name ?? "") || cmp(a.id, b.id))[0]!;
}

function cmp(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

// ---------------------------------------------------------------- test template

/** Test template variables for a tool: the server's module and export, and the tool name. */
export function toolTemplateVars(ctx: ProjectContext, entry: InventoryEntry): { vars: { toolName?: string; importPath?: string; handlerExport?: string }; flags: Set<string> } {
  const reg = entry.internal.registration;
  const pf = reg.pf;
  const flags = new Set<string>();
  const vars: { toolName?: string; importPath?: string; handlerExport?: string } = {};
  if (entry.name && entry.name !== "*") vars.toolName = entry.name;
  if (pf.lang === "python") {
    vars.importPath = pyModulePath(ctx, entry.internal.unit.root, reg.file);
    const target = reg.node.type === "decorator" ? kids(reg.node)[0] : reg.node;
    const fn = target ? (isCall(target) ? callee(target) : target) : null;
    const head = exprPath(fn).split(".")[0] ?? "";
    const exported = pyServerExport(pf, head, reg.node);
    if (exported) vars.handlerExport = exported;
    const decl = head ? unwrap(resolveLocal(pf, head, reg.node)) : null;
    flags.add(decl && isCall(decl) && /^(?:FastMCP|MCPServer)$/.test(calleeName(decl)) ? pyFlavor(pf, decl) : "mcp1");
  } else {
    vars.importPath = tsImportPath(reg.file);
    const exported = tsServerExport(pf, reg.node);
    if (exported) vars.handlerExport = exported;
  }
  return { vars, flags };
}

function tsImportPath(file: string): string {
  const noExt = file.replace(/\.(?:ts|tsx|mts|cts)$/, "");
  const rel = posix.relative("tests/secor", noExt);
  return rel.startsWith(".") ? rel : `./${rel}`;
}

function pyModulePath(ctx: ProjectContext, unitRoot: string, file: string): string {
  let rel = unitRoot && file.startsWith(`${unitRoot}/`) ? file.slice(unitRoot.length + 1) : file;
  rel = rel.replace(/\.py$/, "");
  const srcInit = unitRoot ? `${unitRoot}/src/__init__.py` : "src/__init__.py";
  if (rel.startsWith("src/") && !ctx.hasFile(srcInit)) rel = rel.slice(4);
  return rel.split("/").join(".").replace(/\.__init__$/, "");
}

/** The export that gives the test the server: the registering variable, `export default`, or an enclosing factory. */
function tsServerExport(pf: ParsedFile, registration: SyntaxNode): string | null {
  const fn = callee(registration);
  const recv = fn?.type === "member_expression" ? unwrap(fn.childForFieldName("object")) : null;
  const name = recv?.type === "identifier" ? recv.text : null;
  const exp = exportsOf(pf);
  if (name && exp.has(name)) return name;
  if (name) {
    const decl = topLevel(pf).get(name);
    if (decl) for (const [k, v] of exp) if (v.id === decl.value.id) return k;
  }
  let top: SyntaxNode | null = null;
  for (let f = enclosingFunction(registration); f; f = enclosingFunction(f)) top = f;
  if (top) {
    const holder = closest(top, ["variable_declarator"]);
    for (const [k, v] of exp) if (v.id === top.id || (holder && v.id === holder.childForFieldName("value")?.id)) return k;
  }
  return name;
}

function pyServerExport(pf: ParsedFile, head: string, at: SyntaxNode): string | null {
  if (!head) return null;
  if (topLevel(pf).has(head)) return head;
  let top: SyntaxNode | null = null;
  for (let f = enclosingFunction(at); f; f = enclosingFunction(f)) top = f;
  const name = top?.childForFieldName("name")?.text;
  return name ?? head;
}

/**
 * The tool argument a path expression reads: `args.name`, `request.params.arguments?.file`, `arguments["path"]`,
 * a destructured parameter (`({ path: notePath })` → path), a Python parameter, or a local variable built from one.
 */
export function inputKey(pf: ParsedFile, node: SyntaxNode, handler: SyntaxNode, inputNames: readonly string[], depth = 0): string | null {
  if (depth > 3) return null;
  const inputs = new Set(inputNames);
  const destructured = new Map<string, string>();
  for (const [key, locals] of firstParamKeys(handler)) for (const local of locals) destructured.set(local, key);
  const isArgs = (n: SyntaxNode | null) => {
    const p = exprPath(unwrap(n));
    return inputs.has(p) || /(?:^|\.)arguments$/.test(p);
  };
  let found: string | null = null;
  walk(node, (c) => {
    if (found !== null) return false;
    if (c.type === "member_expression" && isArgs(c.childForFieldName("object"))) found = c.childForFieldName("property")?.text ?? null;
    else if (c.type === "subscript_expression" && isArgs(c.childForFieldName("object"))) found = stringValue(c.childForFieldName("index"));
    else if (c.type === "subscript" && isArgs(c.childForFieldName("value"))) found = stringValue(c.childForFieldName("subscript"));
    else if (c.type === "call" && calleeName(c) === "get") {
      const fn = callee(c);
      if (fn?.type === "attribute" && isArgs(fn.childForFieldName("object"))) found = stringValue(positionalArgs(c)[0] ?? null);
    } else if (c.type === "identifier" || c.type === "shorthand_property_identifier") {
      if (destructured.has(c.text)) found = destructured.get(c.text)!;
      else if (pf.lang === "python" && inputs.has(c.text)) found = c.text;
      else {
        const v = resolveLocal(pf, c.text, c);
        if (v && v.id !== c.id && isInside(v, handler)) found = inputKey(pf, v, handler, inputNames, depth + 1);
      }
    }
    return found === null;
  });
  return found;
}

/** Put the tool's real argument name into the rendered template (the template's default is `path`). */
export function withArgumentKey(rendered: string, framework: Framework, key: string): string {
  if (framework === "mcp-py") return rendered.replace('arguments = {"path": target}', `arguments = {${JSON.stringify(key)}: target}`);
  const prop = /^[A-Za-z_$][\w$]*$/.test(key) ? key : JSON.stringify(key);
  return rendered.replace("const toolArguments = { path: target };", `const toolArguments = { ${prop}: target };`);
}

// ---------------------------------------------------------------- the rule

function entryHandlersKey(h: HandlerRef): string {
  return `${h.file}#${h.node.startIndex}#${h.node.endIndex}`;
}

export const toolScopeRule = defineRule({
  id: RULE_ID,
  title: "Tool with unrestricted file or command access",
  pack: "mcp",
  // Promoted after validation (DECISIONS.md, "Validation and promotion").
  maturity: "stable",
  source: SOURCES.owaspMcp,
  appliesTo: (ctx) => ctx.hasUnit("mcp"),
  check(ctx, emit) {
    const tools = ctx.inventory.filter((e) => e.kind === "mcp_tool" && e.service === "mcp");
    const byHandler = new Map<string, { h: HandlerRef; group: InventoryEntry[] }>();
    for (const e of tools) {
      for (const h of e.internal.handlers) {
        const key = entryHandlersKey(h);
        const slot = byHandler.get(key) ?? { h, group: [] };
        slot.group.push(e);
        byHandler.set(key, slot);
      }
    }
    const reported = new Set<string>();
    for (const { h, group } of [...byHandler.values()].sort((a, b) => (a.h.file < b.h.file ? -1 : a.h.file > b.h.file ? 1 : a.h.node.startIndex - b.h.node.startIndex))) {
      const sinks = analyzeHandler(ctx, group[0]!, h);
      for (const s of sinks) {
        const key = `${s.pf.file}#${s.call.startIndex}`;
        if (reported.has(key)) continue;
        reported.add(key);
        const entry = entryForSink(group, h.node, s.call);
        const anchor = anchorText(s.call);
        let testTemplate: string | undefined;
        if (s.kind === "file") {
          const framework: Framework = entry.framework;
          const { vars, flags } = toolTemplateVars(ctx, entry);
          const rendered = renderTestTemplate(RULE_ID, framework, findingId(RULE_ID, s.pf.file, anchor), vars, flags);
          const key = s.input && s.pf.file === h.file ? inputKey(s.pf, s.input, h.node, entry.internal.inputNames) : null;
          testTemplate = rendered && key ? withArgumentKey(rendered, framework, key) : rendered;
        }
        emit({
          severity: s.severity,
          service: "mcp",
          file: s.pf.file,
          line: line(s.call),
          anchor,
          evidence: s.call.text,
          why: WHY,
          fix: { summary: FIX, ...(testTemplate ? { testTemplate } : {}) },
          entryPointId: entry.id,
        });
      }
    }
  },
});
