import { createHmac } from "node:crypto";
import { pool } from "./db.js";

// Outward webhooks: policy denials, approvals, budget breaches, and finished
// evaluations POST to operator URLs. Best-effort by design: delivery never
// blocks or fails the decision it reports, and every attempt lands in the
// deliveries table for inspection and retry.
export type WebhookEvent =
  | "tool.denied"
  | "approval.requested"
  | "approval.decided"
  | "budget.exceeded"
  | "eval.completed";

export function sign(secret: string, body: string): string {
  return createHmac("sha256", secret).update(body).digest("hex");
}

async function attempt(
  sub: { id: string; url: string; secret: string },
  event: string,
  body: string
): Promise<{ status: string; lastError: string | null }> {
  try {
    const res = await fetch(sub.url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-traceguard-event": event,
        "x-traceguard-signature": sign(sub.secret ?? "", body)
      },
      body,
      signal: AbortSignal.timeout(5000)
    });
    if (!res.ok) return { status: "failed", lastError: `http ${res.status}` };
    return { status: "delivered", lastError: null };
  } catch (err) {
    return { status: "failed", lastError: err instanceof Error ? err.message : "delivery failed" };
  }
}

export async function redeliver(deliveryId: string): Promise<{ status: string; lastError: string | null }> {
  const rows = await pool.query(
    `SELECT d.*, s.url, s.secret FROM webhook_deliveries d
     JOIN webhook_subscriptions s ON s.id = d.subscription_id WHERE d.id = $1`,
    [deliveryId]
  );
  if (!rows.rows[0]) throw new Error("delivery_not_found");
  const d = rows.rows[0];
  const body = typeof d.payload === "string" ? d.payload : JSON.stringify(d.payload);
  const out = await attempt(d, d.event_type, body);
  await pool.query(
    "UPDATE webhook_deliveries SET status = $2, attempts = attempts + 1, last_error = $3 WHERE id = $1",
    [deliveryId, out.status, out.lastError]
  );
  return out;
}

export async function notify(
  workspaceId: string,
  event: WebhookEvent,
  payload: Record<string, unknown>
): Promise<void> {
  let subs;
  try {
    subs = await pool.query(
      "SELECT * FROM webhook_subscriptions WHERE workspace_id = $1 AND enabled = true",
      [workspaceId]
    );
  } catch {
    return; // tables may predate this feature on old databases; never break calls
  }
  const body = JSON.stringify({ event, ...payload });
  for (const sub of subs.rows) {
    const events = (sub.events ?? []) as string[];
    if (!events.includes(event) && !events.includes("*")) continue;
    const out = await attempt(sub, event, body);
    try {
      await pool.query(
        `INSERT INTO webhook_deliveries
           (subscription_id, event_type, payload, status, attempts, last_error)
         VALUES ($1,$2,$3::jsonb,$4,1,$5)`,
        [sub.id, event, body, out.status, out.lastError]
      );
    } catch {
      // The audit of the alert must not break the call either.
    }
  }
}
