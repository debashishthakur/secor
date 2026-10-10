// Bundle the CLI into .test-dist/<name>/ (inside the repo, so packageRoot() finds grammars/). Used by CLI tests.

import { rmSync } from "node:fs";
import { join } from "node:path";
import { build } from "esbuild";

export async function buildCli(name = "cli"): Promise<string> {
  const root = join(import.meta.dirname, "..", "..");
  const outdir = join(root, ".test-dist", name);
  rmSync(outdir, { recursive: true, force: true });
  await build({
    entryPoints: { cli: join(root, "src/cli/index.ts"), probe: join(root, "src/probe/index.ts") },
    outdir,
    bundle: true,
    splitting: true,
    format: "esm",
    platform: "node",
    target: "node20",
    packages: "external",
    logLevel: "error",
  });
  return join(outdir, "cli.js");
}
