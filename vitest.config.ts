import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    exclude: ["test/fixtures/**", "node_modules/**"],
    testTimeout: 30_000,
    hookTimeout: 60_000,
    pool: "forks",
  },
});
