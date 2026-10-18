import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    // The suite opens a real database; the default 10s hook budget is tight
    // on a cold Windows box.
    hookTimeout: 30_000,
    testTimeout: 30_000,
    fileParallelism: false
  }
});
