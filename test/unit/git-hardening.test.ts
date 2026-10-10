// Scanning a repository must never execute anything that repository configures (core.fsmonitor, diff drivers).

import { existsSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { gitAvailable, listFiles, resetGitCache } from "../../src/engine/files.js";
import { runShip } from "../../src/ship/run.js";
import { GIT, git } from "../helpers/fixtures.js";

describe("git hardening", () => {
  it("a malicious core.fsmonitor in the scanned repo is not executed", async () => {
    process.env.PATH = `${GIT.replace(/\/git$/, "")}:${process.env.PATH}`;
    resetGitCache();
    if (!gitAvailable()) return;
    const root = mkdtempSync(join(tmpdir(), "secor-fsmon-"));
    const marker = join(root, "PWNED");
    writeFileSync(join(root, "a.ts"), "export const a = 1;\n");
    git(root, "init", "-q");
    git(root, "add", "-A");
    git(root, "commit", "-q", "-m", "x");
    git(root, "config", "core.fsmonitor", `touch ${marker}; false`);
    git(root, "config", "diff.external", `touch ${marker}`);
    const listing = listFiles(root, []);
    expect(listing.git.isRepo).toBe(true);
    expect(listing.files).toContain("a.ts");
    await runShip({ root, write: false, offline: true });
    expect(existsSync(marker)).toBe(false);
  });
});
