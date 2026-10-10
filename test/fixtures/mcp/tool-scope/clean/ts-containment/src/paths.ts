import fs from "node:fs";
import path from "node:path";

/** Resolve `name` under `root` and refuse anything that escapes it (symlinks included). */
export function resolveInside(root: string, name: string): string {
  const target = path.resolve(root, name);
  const real = fs.existsSync(target) ? fs.realpathSync(target) : target;
  if (!real.startsWith(root + path.sep)) throw new Error("path outside the allowed root");
  return real;
}
