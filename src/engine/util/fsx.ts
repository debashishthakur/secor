import { appendFileSync, chmodSync, closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes } from "node:crypto";

export function ensureDir(dir: string, mode = 0o700): void {
  mkdirSync(dir, { recursive: true, mode });
}

/** Write via a temp file and rename, so readers never see a half-written file. */
export function writeFileAtomic(path: string, data: string, mode = 0o600): void {
  ensureDir(dirname(path));
  const tmp = `${path}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, "w", mode);
  try {
    writeSync(fd, data);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
  chmodSync(path, mode);
}

export function appendLine(path: string, line: string, mode = 0o600): void {
  ensureDir(dirname(path));
  appendFileSync(path, line.endsWith("\n") ? line : `${line}\n`, { mode });
}

export function readJsonFile<T>(path: string): T | null {
  if (!existsSync(path)) return null;
  return JSON.parse(readFileSync(path, "utf8")) as T;
}

export function readTextIfExists(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}

export function mtimeMs(path: string): number | null {
  try {
    return statSync(path).mtimeMs;
  } catch {
    return null;
  }
}

/** Read JSON lines, skipping lines that do not parse (a crashed writer can leave a partial last line). */
export function readJsonLines<T>(path: string): T[] {
  const text = readTextIfExists(path);
  if (!text) return [];
  const out: T[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line) as T);
    } catch {
      // ignore partial line
    }
  }
  return out;
}
