import { defineConfig } from "tsup";

export default defineConfig({
  entry: { cli: "src/cli/index.ts", probe: "src/probe/index.ts" },
  format: ["esm"],
  target: "node20",
  platform: "node",
  splitting: true,
  sourcemap: false,
  clean: true,
  dts: false,
  banner: { js: "#!/usr/bin/env node" },
});
