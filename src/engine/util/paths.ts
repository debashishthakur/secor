import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

/** The user's home directory. Tests point HOME at a temporary directory. */
export function home(): string {
  return process.env.HOME || homedir();
}

/** ~/.secor, or $SECOR_HOME when set (tests and isolated demos). */
export function secorHome(): string {
  return process.env.SECOR_HOME ? resolve(process.env.SECOR_HOME) : join(home(), ".secor");
}

export function expandHome(p: string): string {
  if (p === "~") return home();
  if (p.startsWith("~/")) return join(home(), p.slice(2));
  return p;
}

/** Project-relative path with "/" separators. */
export function toPosix(p: string): string {
  return sep === "/" ? p : p.split(sep).join("/");
}

let packageRootCache: string | null = null;

/** Directory that holds SECOR's package.json (works from src/ under vitest and from dist/ when bundled). */
export function packageRoot(): string {
  if (packageRootCache) return packageRootCache;
  let dir = dirname(fileURLToPath(import.meta.url));
  for (;;) {
    if (existsSync(join(dir, "package.json")) && existsSync(join(dir, "grammars"))) {
      packageRootCache = dir;
      return dir;
    }
    const parent = dirname(dir);
    if (parent === dir) throw new Error("SECOR package root not found");
    dir = parent;
  }
}
