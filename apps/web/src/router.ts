import { useEffect, useState } from "react";

// URL is the single source of truth for "where am I": back/forward, refresh,
// and shared links all land on the right screen.

export type Tab = "overview" | "runs" | "evals" | "policy" | "approvals" | "webhooks" | "retention" | "costs" | "users";

export type Route = { tab: Tab; runId: string | null; approvalId: string | null };

const TABS: readonly string[] = ["overview", "runs", "evals", "policy", "approvals", "webhooks", "retention", "costs", "users"];

export function parseRoute(hash: string): Route {
  const parts = hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  const tab = (TABS.includes(parts[0] ?? "") ? parts[0] : "runs") as Tab;
  return {
    tab,
    runId: tab === "runs" && parts[1] ? decodeURIComponent(parts[1]) : null,
    // FR-021: a decision in the trace view deep-links to its approval.
    approvalId: tab === "approvals" && parts[1] ? decodeURIComponent(parts[1]) : null
  };
}

export function formatRoute(route: Route): string {
  if (route.runId) return `#/runs/${route.runId}`;
  if (route.approvalId) return `#/approvals/${route.approvalId}`;
  return `#/${route.tab}`;
}

export function useHashRoute(): [Route, (route: Route) => void] {
  const [route, setRoute] = useState<Route>(() =>
    typeof window === "undefined" ? { tab: "runs", runId: null, approvalId: null } : parseRoute(window.location.hash)
  );
  useEffect(() => {
    const onChange = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  const navigate = (next: Route) => {
    window.location.hash = formatRoute(next);
  };
  return [route, navigate];
}
