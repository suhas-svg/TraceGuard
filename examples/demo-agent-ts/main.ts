import { BudgetExceeded, BudgetGuard, TraceGuardClient } from "@traceguard/sdk";

const BASE = process.env.TRACEGUARD_URL ?? "http://localhost:8090";
const KEY = process.env.TRACEGUARD_API_KEY ?? "dev_key_change_me";
const BUDGET = process.env.TRACEGUARD_BUDGET ?? "";

const client = new TraceGuardClient(BASE, KEY, "ts-agent");
const runId = client.startRun();
console.log("run:", runId);

if (BUDGET) {
  const guard = new BudgetGuard(BASE, KEY, BUDGET);
  const r1 = await guard.reserve(5480);
  console.log("call1 reserved:", String(r1).slice(0, 8));
  await guard.settle(r1, 5480);
  console.log("call1 settled at 5480 micro");
  try {
    await guard.reserve(5480);
    console.log("CALL2 UNEXPECTEDLY ALLOWED");
  } catch (e) {
    if (e instanceof BudgetExceeded) console.log("call2 blocked:", e.message);
    else throw e;
  }
}

client.modelEvent(runId, { provider: "demo", model: "demo-1", inputTokens: 1200, outputTokens: 240 });
client.endRun(runId, true);
await client.flush();
console.log("done");
