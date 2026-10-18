import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    setupFiles: ["./tests/setup.ts"],
    // Integration hooks open a database pool and a real MCP upstream; the
    // default 10s is tight when the whole file suite runs in parallel.
    hookTimeout: 30_000,
    // A hung-upstream case legitimately waits for the SDK's bounded retry.
    testTimeout: 30_000,
    // Files share one database; setup.ts wipes it per file, so they must not
    // run at the same time.
    fileParallelism: false
  },
  resolve: {
    alias: {
      "@traceguard/schemas": fileURLToPath(
        new URL("../../packages/schemas/src/index.ts", import.meta.url)
      )
    }
  }
});
