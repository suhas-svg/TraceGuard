import { defineConfig } from "@playwright/test";
import {
  API_KEY, APPROVAL_ARGS_KEY, APPROVER_KEY, API_DATABASE_URL, GATEWAY_DATABASE_URL, GATEWAY_STATE_DIR,
  RETENTION_DATABASE_URL
} from "./env";

// Ports default to the documented dev ports. Overriding them lets the suite run
// next to an existing local stack instead of stopping it; env.ts supplies the
// matching URLs and helpers.setKeys stores all three (api, gateway, gateway
// control) in the dashboard's localStorage before each page loads.
const port = (name: string, fallback: number) => Number(process.env[name] ?? fallback);
const apiPort = port("E2E_API_PORT", 8090);
const gatewayPort = port("E2E_GATEWAY_PORT", 8091);
const gatewayControlPort = port("E2E_GATEWAY_CONTROL_PORT", 8093);
const gatewayInternalPort = port("E2E_GATEWAY_INTERNAL_PORT", 8094);
const mockToolsPort = port("E2E_MOCK_TOOLS_PORT", 8092);
const webPort = port("E2E_WEB_PORT", 5173);

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
    baseURL: `http://localhost:${webPort}`,
    trace: "retain-on-failure"
  },
  webServer: [
    {
      // The probe chain guarantees the database exists before the api binds:
      // Playwright starts webServers before globalSetup, so it cannot wait on
      // /readyz until setup-db.mjs has reset and migrated the e2e database.
      command: "node tests/e2e/setup-db.mjs && node apps/api/dist/index.js",
      cwd: "../..",
      url: `http://localhost:${apiPort}/readyz`,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      env: {
        PORT: String(apiPort),
        DATABASE_URL: API_DATABASE_URL,
        DATABASE_URL_RETENTION: RETENTION_DATABASE_URL,
        API_KEY,
        APPROVER_KEY,
        APPROVAL_ARGS_KEY,
        ALLOW_PRIVATE_UPSTREAMS: "true",
        // ADR-0010: discovery is delegated to the gateway's internal listener.
        GATEWAY_INTERNAL_URL: `http://127.0.0.1:${gatewayInternalPort}`,
        GATEWAY_INTERNAL_TOKEN: "test_internal_token",
        DASHBOARD_ORIGIN: `http://localhost:${webPort}`
      }
    },
    {
      command: "node apps/api/dist/gateway.js",
      cwd: "../..",
      url: `http://localhost:${gatewayPort}/healthz`,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000,
      env: {
        GATEWAY_PORT: String(gatewayPort),
        GATEWAY_CONTROL_PORT: String(gatewayControlPort),
        // ADR-0010: the api delegates discovery here. The port is not
        // published by compose; this is the host-side e2e run.
        GATEWAY_INTERNAL_PORT: String(gatewayInternalPort),
        GATEWAY_INTERNAL_TOKEN: "test_internal_token",
        DASHBOARD_ORIGIN: `http://localhost:${webPort}`,
        // Telemetry forwarding target; compose sets this to the api service.
        CONTROL_API_URL: `http://127.0.0.1:${apiPort}`,
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
      url: `http://localhost:${mockToolsPort}/hits`,
      reuseExistingServer: !process.env.CI,
      timeout: 30_000,
      env: { MOCK_TOOLS_PORT: String(mockToolsPort) }
    },
    {
      command: `pnpm --filter @traceguard/web preview --port ${webPort} --strictPort`,
      cwd: "../..",
      url: `http://localhost:${webPort}`,
      reuseExistingServer: !process.env.CI,
      timeout: 60_000
    }
  ]
});
