// Build a ProjectContext with detection done (for adapter-level tests).

import { defaultConfig } from "../../src/engine/config.js";
import { ProjectContext } from "../../src/engine/context.js";
import { detectUnits } from "../../src/engine/detect.js";
import { listFiles } from "../../src/engine/files.js";
import { mockNet } from "./fixtures.js";
import { initParsers } from "../../src/engine/parse.js";

export async function buildTestContext(root: string): Promise<ProjectContext> {
  await initParsers();
  const config = defaultConfig();
  const listing = listFiles(root, []);
  const ctx = new ProjectContext({ root, name: "t", config, files: listing.files, git: listing.git, packs: new Set(["core", "api", "mcp", "web"]), network: false, net: mockNet({}), runStartedAt: new Date(0) });
  ctx.detection = detectUnits({ files: ctx.files, read: (f) => ctx.read(f), mcpDeployment: "auto" });
  ctx.units = ctx.detection.units;
  return ctx;
}
