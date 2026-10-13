import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
  test: { include: ["tests/**/*.test.ts"] },
  resolve: {
    alias: {
      "@traceguard/schemas": fileURLToPath(
        new URL("../../packages/schemas/src/index.ts", import.meta.url)
      )
    }
  }
});
