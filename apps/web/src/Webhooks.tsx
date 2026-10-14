import { useEffect, useState } from "react";
import { opsApi, type Delivery, type Webhook } from "./api";

const EVENTS = ["tool.denied", "approval.requested", "approval.decided", "budget.exceeded", "eval.completed"];

export default function WebhooksView() {
  const [hooks, setHooks] = useState<Webhook[]>([]);
  const [deliveries, setDeliveries] = useState<Delivery[]>([]);
  const [form, setForm] = useState({ name: "", url: "", secret: "", events: ["tool.denied"] as string[] });
  const [error, setError] = useState("");

  const reload = () =>
    Promise.all([opsApi.webhooks(), opsApi.deliveries()])
      .then(([h, d]) => {
        setHooks(h.items);
        setDeliveries(d.items);
      })
      .catch((e) => setError(e instanceof Error ? e.message : "load failed"));

  useEffect(() => {
    reload();
  }, []);

  const toggleEvent = (ev: string) =>
    setForm((f) => ({
      ...f,
      events: f.events.includes(ev) ? f.events.filter((e) => e !== ev) : [...f.events, ev]
    }));

  return (
    <div className="p-4">
      <h2 className="mb-3 text-lg font-semibold">Webhooks</h2>
      {error && <p className="mb-2 text-sm text-red-700">{error}</p>}
      <form
        className="mb-4 grid max-w-2xl gap-2 rounded border p-3 text-sm"
        onSubmit={async (e) => {
          e.preventDefault();
          setError("");
          try {
            await opsApi.createWebhook({ ...form });
            setForm({ name: "", url: "", secret: "", events: ["tool.denied"] });
            reload();
          } catch (err) {
            setError(err instanceof Error ? err.message : "save failed");
          }
        }}
      >
        <div className="flex gap-2">
          <input aria-label="Webhook name" className="w-44 rounded border px-2 py-1" placeholder="name"
            value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          <input aria-label="Webhook URL" className="flex-1 rounded border px-2 py-1 font-mono" placeholder="https://…"
            value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} required />
        </div>
        <input aria-label="Webhook secret" className="rounded border px-2 py-1" placeholder="HMAC secret (optional)"
          value={form.secret} onChange={(e) => setForm({ ...form, secret: e.target.value })} />
        <div className="flex flex-wrap gap-2">
          {EVENTS.map((ev) => (
            <label key={ev} className="flex items-center gap-1 font-mono text-xs">
              <input type="checkbox" checked={form.events.includes(ev)} onChange={() => toggleEvent(ev)} />
              {ev}
            </label>
          ))}
        </div>
        <div>
          <button className="rounded bg-gray-800 px-3 py-1 text-white" type="submit">
            Add subscription
          </button>
        </div>
      </form>
      {hooks.map((h) => (
        <div key={h.id} className="mb-1 flex items-center gap-2 text-sm">
          <span className="font-medium">{h.name}</span>
          <span className="font-mono text-gray-500">{h.url}</span>
          <span className="text-gray-500">{h.events.join(", ")}</span>
          <button
            className="text-red-700 underline"
            onClick={() => opsApi.deleteWebhook(h.id).then(reload).catch((e) => setError(String(e)))}
          >
            Delete
          </button>
        </div>
      ))}
      <h3 className="mb-1 mt-4 text-sm font-semibold text-gray-600">Deliveries</h3>
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="border-b text-left text-gray-500">
            <th className="py-1 pr-2">Subscription</th>
            <th className="py-1 pr-2">Event</th>
            <th className="py-1 pr-2">Status</th>
            <th className="py-1 pr-2">Tries</th>
            <th className="py-1 pr-2">Error</th>
            <th className="py-1 pr-2"></th>
          </tr>
        </thead>
        <tbody>
          {deliveries.map((d) => (
            <tr key={d.id} className="border-b">
              <td className="py-1 pr-2">{d.subscription}</td>
              <td className="py-1 pr-2 font-mono">{d.event_type}</td>
              <td className="py-1 pr-2">{d.status}</td>
              <td className="py-1 pr-2">{d.attempts}</td>
              <td className="py-1 pr-2 text-gray-600">{d.last_error ?? ""}</td>
              <td className="py-1 pr-2">
                {d.status === "failed" && (
                  <button className="text-blue-700 underline"
                    onClick={() => opsApi.retryDelivery(d.id).then(reload).catch((e) => setError(String(e)))}>
                    Retry
                  </button>
                )}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
