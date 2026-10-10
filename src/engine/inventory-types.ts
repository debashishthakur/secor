import type { EntryPoint } from "../types.js";
import type { UnitInfo } from "./detect.js";
import type { ParsedFile, SyntaxNode } from "./parse.js";

export interface HandlerRef {
  file: string;
  pf: ParsedFile;
  /** The handler function node (arrow function, function declaration, Python function_definition, ...). */
  node: SyntaxNode;
}

export interface MiddlewareRef {
  file: string;
  /** The middleware / dependency expression as written (identifier, call, member expression). */
  node: SyntaxNode;
  /** Name used for guard matching: identifier, callee name, or last member segment. */
  name: string;
}

/** An inventory entry: the serialisable EntryPoint plus internal AST references for rules. */
export interface InventoryEntry extends EntryPoint {
  internal: {
    unit: UnitInfo;
    /** Resolved handler functions; empty when the handler could not be resolved. */
    handlers: HandlerRef[];
    /** Route-level and inherited middleware / dependencies, in registration order. */
    middleware: MiddlewareRef[];
    /** The registration node: route call, decorator, export statement, or file root (file-based routes). */
    registration: { file: string; pf: ParsedFile; node: SyntaxNode };
    /** MCP tools: identifiers bound to tool input in the handler. HTTP: identifiers bound to request input. */
    inputNames: string[];
    /** FastAPI: handler parameters bound to guard dependencies (their `.id` is a user identity value). */
    guardParams: string[];
    /** Next.js: covered by middleware that calls a guard. */
    middlewareCovered: boolean;
    /** Rate limiting is present for this entry point (section 8.3). */
    rateLimited: boolean;
    /** Pages router API: the branch that handles this method (when the handler branches on req.method). */
    methodBranch?: SyntaxNode;
  };
}

export function toEntryPoint(e: InventoryEntry): EntryPoint {
  const out: EntryPoint = {
    id: e.id,
    kind: e.kind,
    service: e.service,
    framework: e.framework,
    file: e.file,
    line: e.line,
    auth: { guarded: e.auth.guarded, via: e.auth.via, ...(e.auth.guard ? { guard: e.auth.guard } : {}) },
    declaredPublic: e.declaredPublic,
    callsPaidApi: e.callsPaidApi,
    writesDb: e.writesDb,
  };
  if (e.method !== undefined) out.method = e.method;
  if (e.path !== undefined) out.path = e.path;
  if (e.name !== undefined) out.name = e.name;
  // Keep the normative key order of section 7.
  return {
    id: out.id,
    kind: out.kind,
    service: out.service,
    framework: out.framework,
    ...(out.method !== undefined ? { method: out.method } : {}),
    ...(out.path !== undefined ? { path: out.path } : {}),
    ...(out.name !== undefined ? { name: out.name } : {}),
    file: out.file,
    line: out.line,
    auth: out.auth,
    declaredPublic: out.declaredPublic,
    callsPaidApi: out.callsPaidApi,
    writesDb: out.writesDb,
  };
}
