// Backups before SECOR edits a file it does not own outright (invariant 3): ~/.secor/backups/<timestamp>-<file>.

import { chmodSync, constants, copyFileSync, existsSync } from "node:fs";
import { basename, join } from "node:path";
import { ensureDir } from "../engine/util/fsx.js";
import { secorHome } from "../engine/util/paths.js";

export function backupsDir(): string {
  return join(secorHome(), "backups");
}

/** UTC timestamp YYYYMMDDTHHMMSSZ (the runId format). */
export function compactTimestamp(d: Date): string {
  return d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
}

/** Copy `path` to ~/.secor/backups/<timestamp>-<basename> (mode 0600, never overwriting). Returns the backup path. */
export function backupFile(path: string, now = new Date()): string {
  const dir = backupsDir();
  ensureDir(dir);
  const base = `${compactTimestamp(now)}-${basename(path)}`;
  let target = join(dir, base);
  for (let n = 2; existsSync(target); n++) target = join(dir, `${base}-${n}`);
  copyFileSync(path, target, constants.COPYFILE_EXCL);
  chmodSync(target, 0o600);
  return target;
}
