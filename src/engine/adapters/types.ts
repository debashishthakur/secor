import type { EntryPoint, EntryPointKind, Framework, ServiceKind } from "../../types.js";
import type { GuardMatcher } from "../auth-guards.js";
import type { ProjectContext } from "../context.js";
import type { UnitInfo } from "../detect.js";
import type { HandlerRef, MiddlewareRef } from "../inventory-types.js";
import type { ParsedFile, SyntaxNode } from "../parse.js";

export interface AdapterContext {
  ctx: ProjectContext;
  unit: UnitInfo;
  guards: GuardMatcher;
}

/** What an adapter emits; the inventory layer adds the ID, auth (unless given), and the derived flags. */
export interface RawEntry {
  kind: EntryPointKind;
  service: ServiceKind;
  framework: Framework;
  method?: string;
  path?: string;
  name?: string;
  file: string;
  line: number;
  handlers: HandlerRef[];
  middleware: MiddlewareRef[];
  /** Per middleware entry: the `auth.via` value to report if that middleware is a guard. */
  middlewareLevels?: ("middleware" | "router" | "dependency" | "server")[];
  /** Names of functions wrapping the handler, e.g. withAuth(handler). */
  wrappers?: string[];
  registration: { file: string; pf: ParsedFile; node: SyntaxNode };
  /** Adapter-decided auth (FastAPI dependencies, Next.js middleware, MCP server-level auth). */
  auth?: EntryPoint["auth"];
  inputNames?: string[];
  guardParams?: string[];
  middlewareCovered?: boolean;
  rateLimited?: boolean;
  methodBranch?: SyntaxNode;
}

export type Adapter = (a: AdapterContext) => RawEntry[];
