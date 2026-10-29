// E2E configuration. Everything is overridable so CI can point the suite at
// its own Postgres service without touching the dev-box defaults.
export const DATABASE_URL =
  process.env.E2E_DATABASE_URL ??
  "postgres://traceguard:traceguard_dev_only@localhost:5432/traceguard_e2e";
export const API_URL = process.env.E2E_API_URL ?? "http://localhost:8090";
export const GATEWAY_URL = process.env.E2E_GATEWAY_URL ?? "http://localhost:8091";
export const GATEWAY_CONTROL_URL =
  process.env.E2E_GATEWAY_CONTROL_URL ?? "http://localhost:8093";
export const WEB_URL = process.env.E2E_WEB_URL ?? "http://localhost:5173";
export const MOCK_TOOLS_URL = process.env.E2E_MOCK_TOOLS_URL ?? "http://localhost:8092";
export const API_KEY = "test_key";
export const APPROVER_KEY = "test_approver";
export const APPROVAL_ARGS_KEY = "ab".repeat(32);
// The gateway's accepted-policy-version anchor. Defaults under test-results so
// an e2e run cannot collide with a developer's own ./gateway-state.
export const GATEWAY_STATE_DIR =
  process.env.E2E_GATEWAY_STATE_DIR ?? "test-results/e2e-gateway-state";

// §13.4: each process connects as its least-privilege role, so the e2e run
// proves the grants are sufficient for real operation, not just that the
// denials hold. The passwords are set by setup-db.mjs in the same run.
function asRole(role: string, password: string): string {
  const url = new URL(DATABASE_URL);
  url.username = role;
  url.password = password;
  return url.toString();
}
export const API_DATABASE_URL = process.env.E2E_API_DATABASE_URL ?? asRole("api_runtime", "e2e_api_pw");
export const GATEWAY_DATABASE_URL = process.env.E2E_GATEWAY_DATABASE_URL ?? asRole("gateway_runtime", "e2e_gateway_pw");
export const PUBLISHER_DATABASE_URL = process.env.E2E_PUBLISHER_DATABASE_URL ?? asRole("policy_publisher", "e2e_publisher_pw");
export const RETENTION_DATABASE_URL = process.env.E2E_RETENTION_DATABASE_URL ?? asRole("retention_job", "e2e_retention_pw");
