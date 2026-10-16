import { afterAll, describe, expect, it } from "vitest";
import { buildApp } from "../src/index.js";
import { buildGateway } from "../src/gateway.js";
import { pool } from "../src/db.js";

// The dashboard sends JSON PUT/DELETE requests. Without an allow-methods header
// the browser rejects the preflight and every edit/delete action surfaces as
// "Failed to fetch" while creates (POST, a safelisted method) keep working.
describe("dashboard CORS preflight", () => {
  const apps = [
    { name: "api", app: buildApp() },
    { name: "gateway", app: buildGateway() }
  ];

  afterAll(async () => {
    for (const { app } of apps) await app.close();
    await pool.end();
  });

  for (const { name, app } of apps) {
    it(`${name} lets the dashboard origin preflight PUT and DELETE`, async () => {
      for (const method of ["PUT", "DELETE"]) {
        const res = await app.inject({
          method: "OPTIONS",
          url: "/v1/policies/some-id",
          headers: {
            origin: "http://localhost:5173",
            "access-control-request-method": method,
            "access-control-request-headers": "content-type,authorization"
          }
        });
        expect(res.statusCode).toBe(204);
        expect(res.headers["access-control-allow-origin"]).toBe("http://localhost:5173");
        expect(String(res.headers["access-control-allow-methods"] ?? "")).toContain(method);
      }
    });
  }
});
