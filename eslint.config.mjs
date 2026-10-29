// Root lint config. Plain recommended rules for TS/TSX plus Node script
// files; type-aware linting stays off so lint runs without a build.
import js from "@eslint/js";
import globals from "globals";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    ignores: [
      "**/dist/**",
      "**/node_modules/**",
      "**/test-results/**",
      "**/playwright-report/**",
      ".hermes/**",
      "apps/api/migrations/**"
    ]
  },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ["**/*.{js,mjs,cjs}"],
    languageOptions: { globals: { ...globals.node } }
  },
  {
    files: ["prototype/**/*.{js,mjs}"],
    languageOptions: { globals: { ...globals.browser } }
  },
  {
    rules: {
      // A few `any`s survive at adapter boundaries; keep them visible
      // without failing the build.
      "@typescript-eslint/no-explicit-any": "warn"
    }
  }
);
