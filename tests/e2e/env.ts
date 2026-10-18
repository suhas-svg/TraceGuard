// E2E configuration. Everything is overridable so CI can point the suite at
// its own Postgres service without touching the dev-box defaults.
export const DATABASE_URL =
  process.env.E2E_DATABASE_URL ??
  "postgres://traceguard:traceguard_dev_only@localhost:5432/traceguard_e2e";
export const API_URL = process.env.E2E_API_URL ?? "http://localhost:8090";
export const GATEWAY_URL = process.env.E2E_GATEWAY_URL ?? "http://localhost:8091";
export const WEB_URL = process.env.E2E_WEB_URL ?? "http://localhost:5173";
export const MOCK_TOOLS_URL = process.env.E2E_MOCK_TOOLS_URL ?? "http://localhost:8092";
export const API_KEY = "test_key";
export const APPROVER_KEY = "test_approver";
export const APPROVAL_ARGS_KEY = "ab".repeat(32);
// The gateway's accepted-policy-version anchor. Defaults under test-results so
// an e2e run cannot collide with a developer's own ./gateway-state.
export const GATEWAY_STATE_DIR =
  process.env.E2E_GATEWAY_STATE_DIR ?? "test-results/e2e-gateway-state";
