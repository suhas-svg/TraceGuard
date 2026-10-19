#!/usr/bin/env node
// NFR-007: boot both services against a Postgres that refuses connections and
// prove they fail closed. Health stays up (the process is alive); readiness
// reports not-ready; every write path errors instead of pretending to succeed.
// Run after `tsc -p apps/api/tsconfig.json`, from the repository root.
import { randomUUID } from "node:crypto";

const dead = "postgres://nobody:nobody@127.0.0.1:1/traceguard";
process.env.DATABASE_URL = dead;
process.env.DATABASE_URL_RETENTION = dead;
process.env.NODE_ENV = "test";
process.env.API_KEY = process.env.FAULT_API_KEY ?? "fault_key";
process.env.APPROVER_KEY = process.env.FAULT_APPROVER_KEY ?? "fault_approver";
process.env.APPROVAL_ARGS_KEY = process.env.APPROVAL_ARGS_KEY ?? "ab".repeat(32);

const apiModule = await import(new URL("../../apps/api/dist/index.js", import.meta.url).href);
const gatewayModule = await import(new URL("../../apps/api/dist/gateway.js", import.meta.url).href);

const key = { authorization: `Bearer ${process.env.API_KEY}`, "content-type": "application/json" };
let failures = 0;
const check = (name, ok, detail = "") => {
  console.log(`${ok ? "ok" : "FAIL"} ${name}${detail ? ` - ${detail}` : ""}`);
  if (!ok) failures += 1;
};

const api = apiModule.buildApp();
await api.listen({ host: "127.0.0.1", port: 0 });
const gw = gatewayModule.buildGateway();
await gw.listen({ host: "127.0.0.1", port: 0 });
const apiPort = api.server.address().port;
const gwPort = gw.server.address().port;

const request = (base, method, path, body) =>
  fetch(`${base}${path}`, {
    method,
    headers: key,
    body: body === undefined ? undefined : JSON.stringify(body)
  });

try {
  const health = await request(`http://127.0.0.1:${apiPort}`, "GET", "/healthz");
  check("api /healthz still answers", health.status === 200);

  const ready = await request(`http://127.0.0.1:${apiPort}`, "GET", "/readyz");
  check("api /readyz reports not ready", ready.status === 503);

  const ingest = await request(`http://127.0.0.1:${apiPort}`, "POST", "/v1/ingest/events", {
    events: [{
      schema_version: "1",
      event_id: `fault-${randomUUID()}`,
      agent_name: "fault-agent",
      run_id: randomUUID(),
      span_id: randomUUID(),
      parent_span_id: null,
      event_type: "run.started",
      timestamp: new Date().toISOString(),
      status: "success",
      attributes: {}
    }]
  });
  check("api ingest refuses without the database", ingest.status >= 500, `HTTP ${ingest.status}`);

  const gwHealth = await request(`http://127.0.0.1:${gwPort}`, "GET", "/healthz");
  check("gateway /healthz still answers", gwHealth.status === 200);

  const call = await request(`http://127.0.0.1:${gwPort}`, "POST", "/v1/gateway/tools/call", {
    server_id: "00000000-0000-0000-0000-000000000000",
    tool: "echo",
    arguments: {},
    caller: "fault"
  });
  const body = await call.text();
  check(
    "gateway tool call fails closed",
    call.status >= 500 && !body.includes('"result"'),
    `HTTP ${call.status}`
  );
} finally {
  await api.close();
  await gw.close();
}

if (failures > 0) {
  console.error(`fault injection: ${failures} failure(s)`);
  process.exit(1);
}
console.log("fault injection: fail-closed semantics hold with the database down");
process.exit(0);
