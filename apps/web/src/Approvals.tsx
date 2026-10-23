import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { gwApi, type Approval } from "./api";
import {
  Alert, Button, Card, Empty, Input, LinkButton, ListSkeleton, Page,
  Segmented, StatusBadge
} from "./components";

function ApprovalCard({
  a,
  onChanged,
  onOpenRun,
  highlighted = false
}: {
  a: Approval;
  onChanged: () => void;
  onOpenRun?: (runId: string) => void;
  highlighted?: boolean;
}) {
  const [reason, setReason] = useState("");
  const [error, setError] = useState("");

  const decide = async (approved: boolean) => {
    setError("");
    try {
      await gwApi.decide(a.id, approved, reason);
      onChanged();
    } catch (e) {
      setError(e instanceof Error ? e.message : "decision failed");
    }
  };

  return (
    <Card className={`mb-3 p-4 text-sm${highlighted ? " ring-2 ring-brand-500/60" : ""}`}>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono font-semibold text-ink-900">{a.tool_name}</span>
        <StatusBadge status={a.status} />
        <span className="text-ink-500">from {a.caller}</span>
        {a.run_id && onOpenRun && (
          <LinkButton onClick={() => onOpenRun(a.run_id!)}>run {a.run_id.slice(0, 8)}</LinkButton>
        )}
        <span className="ml-auto text-xs text-ink-500">expires {new Date(a.expires_at).toLocaleString()}</span>
      </div>
      <pre className="mt-2 max-h-48 overflow-auto rounded-lg bg-[#0b0e16] p-3 font-mono text-xs text-slate-100">
        {JSON.stringify(a.args, null, 2)}
      </pre>
      {a.decision_reason && <p className="mt-2 text-ink-500">Reason: {a.decision_reason}</p>}
      {a.status === "outcome_unknown" && (
        <p className="mt-2 text-sm text-ink-800">
          <strong>The upstream action may have executed.</strong> Inspect the upstream
          system before taking further action. This approval cannot be retried.
        </p>
      )}
      {a.status === "policy_invalidated" && (
        <p className="mt-2 text-sm text-ink-500">
          A policy change invalidated this approval before execution. It was never sent upstream.
        </p>
      )}
      {a.status === "tool_quarantined" && (
        <p className="mt-2 text-sm text-ink-500">
          The tool definition changed and was quarantined after this approval was issued.
        </p>
      )}
      {a.status === "response_received" && a.response_is_error && (
        <p className="mt-2 text-sm text-ink-500">
          The tool returned an error; that is not proof it caused no side effect.
        </p>
      )}
      {error && <div className="mt-2"><Alert>{error}</Alert></div>}
      {a.status === "pending" && (
        <div className="mt-3 flex flex-wrap items-center gap-2">
          <Input aria-label="Decision reason" className="w-64"
            placeholder="reason (optional)" value={reason} onChange={(e) => setReason(e.target.value)} />
          <Button variant="primary" onClick={() => decide(true)}>Approve</Button>
          <Button variant="danger" onClick={() => decide(false)}>Deny</Button>
        </div>
      )}
      {a.status === "approved" && (
        <p className="mt-3 text-sm text-ink-500">
          Approved. The calling agent retries the original request with the same
          logical request id; the dashboard cannot dispatch it.
        </p>
      )}
    </Card>
  );
}

export default function ApprovalsView({
  focusId = null,
  onOpenRun
}: {
  focusId?: string | null;
  onOpenRun?: (runId: string) => void;
}) {
  // A deep link from a run's decision panel opens the All filter so the
  // referenced hold is present even when it is no longer pending.
  const [filter, setFilter] = useState(focusId ? "" : "pending");
  const approvalsQuery = useQuery({
    queryKey: ["approvals", filter],
    queryFn: () => gwApi.approvals(filter || undefined),
    refetchInterval: 10_000
  });
  const items = approvalsQuery.data?.items ?? [];
  const error = approvalsQuery.error instanceof Error ? approvalsQuery.error.message : "";
  const queryClient = useQueryClient();
  // Invalidate every approvals query, not just the filtered one: the sidebar
  // badge reads its own key, so deciding a hold left the count stale for up to
  // its 30s interval and the badge contradicted the list on screen.
  const reload = () => queryClient.invalidateQueries({ queryKey: ["approvals"] });

  // FR-021: bring the deep-linked approval into view and mark it.
  const focusRef = useRef<HTMLDivElement | null>(null);
  useEffect(() => {
    if (focusId && focusRef.current) {
      focusRef.current.scrollIntoView({ block: "center", behavior: "smooth" });
    }
  }, [focusId, items.length]);
  const ordered = focusId
    ? [...items].sort((x, y) => Number(y.id === focusId) - Number(x.id === focusId))
    : items;

  return (
    <Page
      title="Approvals"
      sub="Held tool calls wait here. Nothing executes until a human decides."
      actions={
        <>
          <Segmented
            label="Filter approvals"
            value={filter}
            onChange={(v) => setFilter(v)}
            options={[
              { value: "pending", label: "Pending" },
              { value: "", label: "All" },
              { value: "approved", label: "Approved" },
              { value: "rejected", label: "Rejected" },
              { value: "expired", label: "Expired" },
              { value: "executing", label: "Executing" },
              { value: "response_received", label: "Executed" },
              { value: "outcome_unknown", label: "Outcome unknown" },
              { value: "policy_invalidated", label: "Invalidated" }
            ]}
          />
          <Button onClick={reload}>Refresh</Button>
        </>
      }
    >
      {error && <Alert>{error}</Alert>}
      {approvalsQuery.isPending ? (
        <ListSkeleton rows={3} label="Loading approvals..." />
      ) : items.length === 0 ? (
        <Empty hint="Nothing here. Held calls appear under the pending filter." />
      ) : null}
      {ordered.map((a) => (
        <div key={a.id} ref={a.id === focusId ? focusRef : undefined}>
          <ApprovalCard
            a={a}
            onChanged={reload}
            onOpenRun={onOpenRun}
            highlighted={a.id === focusId}
          />
        </div>
      ))}
    </Page>
  );
}
