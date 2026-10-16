import { randomUUID } from "node:crypto";
import { expect, test, type Page } from "@playwright/test";
import {
  apiGet, apiPost, event, gwCall, gwPost, ingest, seedRun, setKeys, upstreamHits
} from "./helpers";

// Scenarios A-F from the specification, run against the real stack. The
// describe is serial and shares one database and one upstream hit counter;
// every denial asserts both the client error and the absence of an upstream
// side effect.
test.describe.configure({ mode: "serial" });

const tag = Date.now().toString(36);
let serverId = "";

test.beforeAll(async ({ request }) => {
  const reg = await gwPost(request, "/v1/servers", {
    name: `e2e-tools-${tag}`,
    base_url: "http://127.0.0.1:8092/mcp"
  });
  expect(reg.status()).toBe(201);
  serverId = (await reg.json()).id;

  const disc = await gwPost(request, `/v1/servers/${serverId}/discover`, {});
  expect(disc.status()).toBe(200);
  const tools = (await disc.json()).tools.map((t: { tool_name: string }) => t.tool_name);
  expect(tools).toContain("read_file");
  expect(tools).toContain("wipe_disk");

  const policies = [
    { name: `e2e-allow-${tag}`, server_id: serverId, tool_name: "read_file", effect: "allow" },
    { name: `e2e-deny-${tag}`, priority: 100, server_id: serverId, tool_name: "wipe_disk", effect: "deny" },
    {
      name: `e2e-appr-${tag}`, priority: 50, server_id: serverId, tool_name: "read_file",
      effect: "require_approval",
      conditions: { arguments: { path: { enum: ["/approval-needed.txt"] } } }
    }
  ];
  for (const policy of policies) {
    const res = await gwPost(request, "/v1/policies", policy);
    expect(res.status()).toBe(201);
  }
});

async function openTab(page: Page, label: string) {
  await page.getByRole("navigation", { name: "Primary" }).getByRole("button", { name: label, exact: true }).click();
}

test("scenario A: a successful run is visible end to end", async ({ page, request }) => {
  const agent = `e2e-ok-${tag}`;
  const runId = await seedRun(request, { agent_name: agent, tool: "read_file" });

  await setKeys(page);
  await page.goto("/");
  await expect(page.getByText("Total runs")).toBeVisible();

  await openTab(page, "Runs");
  // The Agent filter also renders the name as a hidden <option>; scope to
  // the table body so only the visible row counts.
  await expect(page.getByRole("table").getByText(agent).first()).toBeVisible();

  await page.goto(`/#/runs/${runId}`);
  await expect(page.getByText("model.request").first()).toBeVisible();
  await page.getByText("model.request").first().click();
  await expect(page.getByText("Usage source")).toBeVisible();
  await expect(page.getByText("provider_reported").first()).toBeVisible();
});

test("scenario B: a failed run surfaces its error", async ({ page, request }) => {
  const agent = `e2e-fail-${tag}`;
  // Distinct error strings: the run fails with "boom" while the tool span
  // carries "tool exploded", so the detail panel must show the tool's own
  // error rather than the run's.
  const runId = await seedRun(request, {
    agent_name: agent, ok: false, tool: "read_file"
  });

  await setKeys(page);
  await page.goto(`/#/runs/${runId}`);
  await expect(page.getByText("failed").first()).toBeVisible();
  await expect(page.getByText("boom").first()).toBeVisible();
  await page.getByText("tool.invocation").first().click();
  await expect(page.getByText("tool exploded").first()).toBeVisible();
});

test("scenario C: an exhausted budget blocks the call before the upstream", async ({ page, request }) => {
  const runId = randomUUID();
  const ing = await ingest(request, [event({ run_id: runId, event_type: "run.started" })]);
  expect(ing.status()).toBe(200);

  const budget = await apiPost(request, "/v1/budgets", {
    scope: "run", ref_id: runId, limit_micro: 1_000_000, effect: "block"
  });
  expect([200, 201]).toContain(budget.status());
  const budgetId = (await budget.json()).id;
  // Hold the whole limit: the next managed call is over.
  const reserve = await apiPost(request, "/v1/budgets/check", {
    budget_id: budgetId, max_cost_micro: 1_000_000
  });
  expect(reserve.status()).toBe(200);

  const before = await upstreamHits(request);
  const denied = await gwCall(request, {
    server_id: serverId, tool: "read_file", arguments: { path: "/notes.txt" },
    caller: "e2e", run_id: runId
  });
  expect(denied.status()).toBe(403);
  expect((await denied.json()).error).toBe("budget_exceeded");
  expect(await upstreamHits(request)).toBe(before);

  await setKeys(page);
  await page.goto(`/#/runs/${runId}`);
  await expect(page.getByText("denied").first()).toBeVisible();
  await page.getByText("tool.invocation").first().click();
  await expect(page.getByText(/budget exhausted/).first()).toBeVisible();
});

test("scenario D: an approval-protected call waits for a human, then executes", async ({ page, request }) => {
  const before = await upstreamHits(request);
  const held = await gwCall(request, {
    server_id: serverId, tool: "read_file", arguments: { path: "/approval-needed.txt" },
    caller: "e2e", request_id: `e2e-appr-${tag}`
  });
  expect(held.status()).toBe(202);
  // Nothing executes before the human decision.
  expect(await upstreamHits(request)).toBe(before);

  await setKeys(page);
  await page.goto("/");
  await openTab(page, "Approvals");
  await expect(page.getByText("/approval-needed.txt").first()).toBeVisible();
  await page.getByRole("button", { name: "Approve", exact: true }).click();

  await page.getByRole("group", { name: "Filter approvals" })
    .getByRole("button", { name: "Approved", exact: true }).click();
  await page.getByRole("button", { name: "Run now", exact: true }).click();

  // Running consumes the approval, so the card drops out of the Approved
  // filter and its transient result text unmounts with it. Confirm the
  // execution reached the upstream once, then find the row where it now
  // lives: under the Consumed filter. (Its args are cleared on consume, so
  // only the status badge and metadata remain.)
  await expect.poll(() => upstreamHits(request), { timeout: 45_000 }).toBe(before + 1);
  await page.getByRole("group", { name: "Filter approvals" })
    .getByRole("button", { name: "Consumed", exact: true }).click();
  await expect(page.getByText("consumed").first()).toBeVisible();
  await expect(page.getByText("read_file").first()).toBeVisible();
  await expect(page.getByText("from e2e").first()).toBeVisible();
});

test("scenario E: a denied call never reaches the upstream", async ({ page, request }) => {
  const runId = randomUUID();
  const ing = await ingest(request, [event({ run_id: runId, event_type: "run.started" })]);
  expect(ing.status()).toBe(200);

  const before = await upstreamHits(request);
  const denied = await gwCall(request, {
    server_id: serverId, tool: "wipe_disk", arguments: { target: "/dev/sda" },
    caller: "e2e", run_id: runId
  });
  expect(denied.status()).toBe(403);
  const body = await denied.json();
  expect(body.error).toBe("tool_blocked");
  expect(body.reason).toContain(`e2e-deny-${tag}`);
  expect(await upstreamHits(request)).toBe(before);

  await setKeys(page);
  await page.goto(`/#/runs/${runId}`);
  await page.getByText("tool.invocation").first().click();
  await expect(page.getByText(new RegExp(`e2e-deny-${tag}`)).first()).toBeVisible();
});

test("scenario F: two evaluation versions compare side by side", async ({ page, request }) => {
  const suite = await apiPost(request, "/v1/evaluations/suites", { name: `e2e-suite-${tag}` });
  expect(suite.status()).toBe(201);
  const suiteId = (await suite.json()).id;
  const kase = await apiPost(request, `/v1/evaluations/suites/${suiteId}/cases`, {
    name: "greeting",
    assertions: [{ type: "contains", value: "hello" }],
    exec_config: { output: "hello world", latency_ms: 5, input_tokens: 10, output_tokens: 5 }
  });
  expect(kase.status()).toBe(201);

  const runA = await apiPost(request, `/v1/evaluations/suites/${suiteId}/runs`, {
    agent_name: `e2e-eval-${tag}`, config_fingerprint: "good"
  });
  expect(runA.status()).toBe(201);
  const runB = await apiPost(request, `/v1/evaluations/suites/${suiteId}/runs`, {
    agent_name: `e2e-eval-${tag}`, config_fingerprint: "bad",
    exec_overrides: { greeting: { output: "goodbye" } }
  });
  expect(runB.status()).toBe(201);
  const aId = (await runA.json()).eval_run.id;
  const bId = (await runB.json()).eval_run.id;

  const cmp = await apiGet(request, `/v1/evaluations/runs/compare?ids=${aId},${bId}`);
  expect(cmp.status()).toBe(200);
  const [a, b] = (await cmp.json()).runs;
  expect(a.pass_rate).toBe(1);
  expect(b.pass_rate).toBe(0);

  await setKeys(page);
  await page.goto("/");
  await openTab(page, "Evaluations");
  await expect(page.getByText(`e2e-suite-${tag}`).first()).toBeVisible();
  await expect(page.getByText("locked").first()).toBeVisible();

  await page.getByPlaceholder("evaluation run id").fill(aId);
  await page.getByRole("button", { name: "Open", exact: true }).click();
  await expect(page.getByText("1/1").first()).toBeVisible();

  await page.getByPlaceholder("run-id-1, run-id-2").fill(`${aId}, ${bId}`);
  await page.getByRole("button", { name: "Compare", exact: true }).click();
  await expect(page.getByText("100%").first()).toBeVisible();
  await expect(page.getByText("0%").first()).toBeVisible();
});
