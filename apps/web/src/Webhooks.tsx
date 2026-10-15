import { useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { opsApi } from "./api";
import {
  Alert, Button, Card, Empty, Field, Input, Page,
  StatusBadge, Table, Td, Th
} from "./components";

const EVENTS = ["tool.denied", "approval.requested", "approval.decided", "budget.exceeded", "eval.completed"];

export default function WebhooksView() {
  const [form, setForm] = useState({ name: "", url: "", secret: "", events: ["tool.denied"] as string[] });
  const [error, setError] = useState("");
  const queryClient = useQueryClient();
  const hooksQuery = useQuery({ queryKey: ["webhooks"], queryFn: () => opsApi.webhooks() });
  const deliveriesQuery = useQuery({ queryKey: ["webhook-deliveries"], queryFn: () => opsApi.deliveries() });
  const hooks = hooksQuery.data?.items ?? [];
  const deliveries = deliveriesQuery.data?.items ?? [];
  const loadError = hooksQuery.error ?? deliveriesQuery.error;
  const loadFailed = loadError ? (loadError instanceof Error ? loadError.message : "load failed") : "";

  const reload = () => queryClient.invalidateQueries();

  const toggleEvent = (ev: string) =>
    setForm((f) => ({
      ...f,
      events: f.events.includes(ev) ? f.events.filter((e) => e !== ev) : [...f.events, ev]
    }));

  return (
    <Page
      title="Webhooks"
      sub="HMAC-signed event delivery. Secrets are write-only; reads never return them."
    >
      {(error || loadFailed) && <Alert>{error || loadFailed}</Alert>}
      <Card className="mb-5 max-w-2xl p-4">
        <form
          className="grid gap-3 text-sm"
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
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Name">
              <Input aria-label="Webhook name" placeholder="alerts" value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </Field>
            <Field label="HMAC secret (optional)">
              <Input aria-label="Webhook secret" placeholder="shared secret" value={form.secret}
                onChange={(e) => setForm({ ...form, secret: e.target.value })} />
            </Field>
          </div>
          <Field label="URL">
            <Input aria-label="Webhook URL" placeholder="https://…" className="font-mono"
              value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })} required />
          </Field>
          <div className="flex flex-wrap gap-2">
            {EVENTS.map((ev) => (
              <label key={ev}
                className={`cursor-pointer rounded-full border px-2.5 py-1 font-mono text-xs transition-colors ${
                  form.events.includes(ev)
                    ? "border-brand-600 bg-brand-50 text-brand-700"
                    : "border-ink-200 text-ink-500 hover:border-ink-300"
                }`}>
                <input type="checkbox" className="sr-only" checked={form.events.includes(ev)}
                  onChange={() => toggleEvent(ev)} />
                {ev}
              </label>
            ))}
          </div>
          <div>
            <Button variant="primary" type="submit">Add subscription</Button>
          </div>
        </form>
      </Card>
      <h3 className="mb-2 text-sm font-semibold text-ink-700">Subscriptions</h3>
      {hooks.length === 0 ? (
        <Empty hint="No subscriptions yet." />
      ) : (
        <Card className="mb-5 divide-y divide-ink-100">
          {hooks.map((h) => (
            <div key={h.id} className="flex flex-wrap items-center gap-2 px-4 py-2.5 text-sm">
              <span className="font-medium text-ink-900">{h.name}</span>
              <span className="truncate font-mono text-xs text-ink-400">{h.url}</span>
              <span className="text-xs text-ink-500">{h.events.join(", ")}</span>
              <span className="ml-auto">
                <Button size="sm" variant="ghost" className="text-bad-700 hover:bg-bad-100"
                  onClick={() => opsApi.deleteWebhook(h.id).then(reload).catch((e) => setError(String(e)))}>
                  Delete
                </Button>
              </span>
            </div>
          ))}
        </Card>
      )}
      <h3 className="mb-2 text-sm font-semibold text-ink-700">Deliveries</h3>
      {deliveries.length === 0 ? (
        <Empty hint="No deliveries yet. Trigger a denial or approval to see one." />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Subscription</Th>
              <Th>Event</Th>
              <Th>Status</Th>
              <Th>Tries</Th>
              <Th>Error</Th>
              <Th><span className="sr-only">Actions</span></Th>
            </tr>
          </thead>
          <tbody>
            {deliveries.map((d) => (
              <tr key={d.id} className="transition-colors hover:bg-ink-50/70">
                <Td>{d.subscription}</Td>
                <Td className="font-mono text-[13px]">{d.event_type}</Td>
                <Td><StatusBadge status={d.status} /></Td>
                <Td>{d.attempts}</Td>
                <Td className="max-w-xs truncate text-ink-500">{d.last_error ?? ""}</Td>
                <Td>
                  {d.status === "failed" && (
                    <Button size="sm" variant="ghost"
                      onClick={() => opsApi.retryDelivery(d.id).then(reload).catch((e) => setError(String(e)))}>
                      Retry
                    </Button>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Page>
  );
}
