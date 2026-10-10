import { readFileSync } from "node:fs";
import { join } from "node:path";
import { packageRoot } from "../engine/util/paths.js";

let cached: string | null = null;

export function secorVersion(): string {
  if (!cached) {
    try {
      cached = (JSON.parse(readFileSync(join(packageRoot(), "package.json"), "utf8")) as { version: string }).version;
    } catch {
      cached = "0.0.0";
    }
  }
  return cached;
}
