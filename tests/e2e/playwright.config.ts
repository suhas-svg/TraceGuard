import { defineConfig } from "@playwright/test";
import {
  API_KEY, APPROVAL_ARGS_KEY, APPROVER_KEY, API_DATABASE_URL, GATEWAY_DATABASE_URL, GATEWAY_STATE_DIR,
  RETENTION_DATABASE_URL
} from "./env";

// End-to-end run against the real stack: API, gateway, mock MCP upstream and
// the built dashboard, each started as its own process. One worker on purpose:
// the scenarios share one database and one upstream hit counter.
export default defineConfig({
  testDir: ".",
  fullyParallel: false,
  workers: 1,
  timeout: 120_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  use: {
    baseURL: "http://localhost:5173",
    trace: "retain-on-failure"
  },
  webServer: [
    {
      // The probe chain guarantees the database exists before the api binds:
      // Playwright starts webServers before globalSetup, so it cannot wait on
      // /readyz until setup-db.mjs has reset and migrated the e2e database.
      command: "node tests/e2e/setup-db.mjs && node apps/api/dist/index.js",
      cwd: "../..",
      url: "http://localhost:8090/readyz",
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      env: {
        PORT: "8090",
        DATABASE_URL: API_DATABASE_URL,
        DATABASE_URL_RETENTION: RETENTION_DATABASE_URL,
        API_KEY,
        APPROVER_KEY,
        APPROVAL_ARGS_KEY,
        ALLOW_PRIVATE_UPSTREAMS: "true"
      }
    },
    {
      command: "node apps/api/dist/gateway.js",
      cwd: "../..",
      url: "http://localhost:8091/healthz",
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      env: {
        GATEWAY_PORT: "8091",
        DATABASE_URL: GATEWAY_DATABASE_URL,
        API_KEY,
        APPROVER_KEY,
        APPROVAL_ARGS_KEY,
        ALLOW_PRIVATE_UPSTREAMS: "true",
        // The accepted-policy-version anchor for this run; helpers.ts wipes it
        // alongside the recreated database.
        GATEWAY_STATE_DIR
      }
    },
    {
      command: "node examples/mock-tools/server.mjs",
      cwd: "../..",
      url: "http://localhost:8092/hits",
      reuseExistingServer: !process.env.CI,
      timeout: 30_000,
      env: { MOCK_TOOLS_PORT: "8092" }
    },
    {
      command: "npm run preview --workspace apps/web -- --port 5173 --strictPort",
      cwd: "../..",
      url: "http://localhost:5173",
      reuseExistingServer: !process.env.CI,
      timeout: 60_000
    }
  ]
});
