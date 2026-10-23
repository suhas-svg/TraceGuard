import { useEffect, useMemo, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { connectSession, getOverview, settings } from "./api";
import { useHashRoute, type Tab } from "./router";
import type { PaletteItem } from "./palette";
import { Palette } from "./CommandPalette";
import OverviewView from "./Overview";
import RunsView from "./Runs";
import TraceView from "./Trace";
import EvalsView from "./Evals";
import PoliciesView from "./Policies";
import ApprovalsView from "./Approvals";
import WebhooksView from "./Webhooks";
import RetentionView from "./Retention";
import CostsView from "./Costs";
import UsersView from "./Users";
import { Button, Field, Input, NavIcon } from "./components";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "runs", label: "Runs" },
  { id: "evals", label: "Evaluations" },
  { id: "policy", label: "Policy" },
  { id: "approvals", label: "Approvals" },
  { id: "webhooks", label: "Webhooks" },
  { id: "retention", label: "Retention" },
  { id: "costs", label: "Costs" },
  { id: "users", label: "Users" }
];

const NAV_GROUPS: { label: string; tabs: Tab[] }[] = [
  { label: "Monitor", tabs: ["overview", "runs"] },
  { label: "Control", tabs: ["policy", "approvals"] },
  { label: "Analyze", tabs: ["evals", "costs"] },
  { label: "Configure", tabs: ["webhooks", "retention", "users"] }
];

function short(id: string) {
  return id.slice(0, 8);
}

function tabLabel(id: Tab) {
  return TABS.find((t) => t.id === id)?.label ?? id;
}

function theme(): "light" | "dark" {
  if (typeof document === "undefined") return "light";
  const saved = localStorage.getItem("tg-theme");
  if (saved === "dark" || saved === "light") return saved;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function ThemeToggle() {
  const [mode, setMode] = useState<"light" | "dark">("light");
  useEffect(() => {
    const t = theme();
    setMode(t);
    document.documentElement.classList.toggle("dark", t === "dark");
  }, []);
  return (
    <button
      onClick={() => {
        const next = mode === "dark" ? "light" : "dark";
        setMode(next);
        localStorage.setItem("tg-theme", next);
        document.documentElement.classList.toggle("dark", next === "dark");
      }}
      aria-label={mode === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      title={mode === "dark" ? "Switch to light mode" : "Switch to dark mode"}
      className="flex h-8 w-8 items-center justify-center rounded-lg text-ink-400 transition-colors hover:bg-ink-100 hover:text-ink-900"
    >
      {mode === "dark" ? (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
          strokeLinecap="round" className="h-4 w-4" aria-hidden="true">
          <circle cx="12" cy="12" r="4" />
          <path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4l1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" />
        </svg>
      ) : (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
          strokeLinecap="round" strokeLinejoin="round" className="h-4 w-4" aria-hidden="true">
          <path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z" />
        </svg>
      )}
    </button>
  );
}

function ConnectionDrawer({ open, onClose, onSaved }: {
  open: boolean;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [url, setUrl] = useState(settings.url);
  const [key, setKey] = useState("");
  const [gwUrl, setGwUrl] = useState(settings.gwUrl);
  const [approverKey, setApproverKey] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  return (
    <div
      className={`fixed inset-0 z-50 flex justify-end transition-[visibility] duration-200 ${open ? "visible" : "invisible"}`}
      role="dialog" aria-label="Connection settings" aria-hidden={!open}
    >
      <div
        className={`absolute inset-0 bg-black/50 transition-opacity duration-200 ${open ? "opacity-100" : "opacity-0"}`}
        onClick={onClose}
      />
      <form
        className={`relative flex w-80 flex-col gap-3 bg-surface p-5 shadow-xl transition-transform duration-200 ${open ? "translate-x-0" : "translate-x-full"}`}
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            await connectSession(url, key, gwUrl, approverKey);
            // The raw keys were used once to mint HttpOnly session cookies;
            // clearing them here keeps them out of React state after connect.
            setKey("");
            setApproverKey("");
            onSaved();
            onClose();
          } catch (err) {
            setError(err instanceof Error ? err.message : "connection failed");
          } finally {
            setBusy(false);
          }
        }}
      >
        <h2 className="text-base font-semibold text-ink-900">Connection</h2>
        <p className="text-xs text-ink-500">
          Keys are exchanged for short-lived server-side sessions. Only the URLs stay in this browser.
        </p>
        <Field label="API URL"><Input value={url} onChange={(e) => setUrl(e.target.value)} /></Field>
        <Field label="API key">
          <Input type="password" value={key} placeholder="admin key (exchanged once)"
            onChange={(e) => setKey(e.target.value)} />
        </Field>
        <Field label="Gateway URL"><Input value={gwUrl} onChange={(e) => setGwUrl(e.target.value)} /></Field>
        <Field label="Approver key">
          <Input type="password" value={approverKey} placeholder="approver key (exchanged once)"
            onChange={(e) => setApproverKey(e.target.value)} />
        </Field>
        {error && <p role="alert" className="text-xs text-red-600">{error}</p>}
        <div className="mt-1 flex gap-2">
          <Button variant="primary" type="submit" disabled={busy}>
            {busy ? "Connecting…" : "Connect"}
          </Button>
          <Button type="button" onClick={onClose} disabled={busy}>Cancel</Button>
        </div>
      </form>
    </div>
  );
}


export default function App() {
  const [{ tab, runId: openRun, approvalId }, navigate] = useHashRoute();
  const [drawer, setDrawer] = useState(false);
  const [mobileNav, setMobileNav] = useState(false);
  const queryClient = useQueryClient();
  const health = useQuery({
    queryKey: ["healthz"],
    queryFn: async () => (await fetch(`${settings.url}/healthz`)).ok,
    refetchInterval: 30_000
  });
  const connected = health.isError ? false : health.data ?? null;
  // Exact pending count from the overview. Reading the approvals list instead
  // capped at the API's default 50, so the badge read exactly 50 and the
  // surplus holds were invisible.
  const pendingApprovals = useQuery({
    queryKey: ["overview", "pending-approvals"],
    queryFn: getOverview,
    refetchInterval: 30_000,
    retry: false
  }).data?.pending_approvals ?? 0;

  const go = (t: Tab) => {
    setMobileNav(false);
    navigate({ tab: t, runId: null, approvalId: null });
  };

  useEffect(() => {
    if (!mobileNav) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setMobileNav(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mobileNav]);

  // Ctrl/Cmd+K opens the switcher; Escape closes it from inside.
  const [palette, setPalette] = useState(false);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);
  // Rebuilt while the palette is open so recent runs reflect the live cache.
  const paletteItems: PaletteItem[] = useMemo(() => {
    // Any loaded runs page works for "recent": the unfiltered list is
    // preferred, but a filtered one beats showing nothing.
    const cached = queryClient
      .getQueriesData<{ pages: { items: { id: string; agent_name: string }[] }[] }>({
        queryKey: ["runs"]
      })
      .map(([, data]) => data)
      .find((d) => d?.pages?.[0]?.items?.length);
    const recent = (cached?.pages[0]?.items ?? []).slice(0, 6).map((r) => ({
      id: `run-${r.id}`,
      label: `Open run ${r.id.slice(0, 8)}`,
      hint: r.agent_name,
      action: () => navigate({ tab: "runs", runId: r.id, approvalId: null })
    }));
    return [...TABS.map((t) => ({ id: `tab-${t.id}`, label: `Go to ${t.label}`, action: () => go(t.id) })), ...recent];
  }, [palette]);

  return (
    <div className="min-h-screen lg:flex">
      {mobileNav && (
        <button
          type="button"
          aria-label="Close navigation"
          onClick={() => setMobileNav(false)}
          className="fixed inset-0 z-40 bg-[#090b0f]/45 backdrop-blur-[2px] lg:hidden"
        />
      )}

      <aside
        className={`fixed inset-y-0 left-0 z-50 flex w-[248px] shrink-0 flex-col border-r border-ink-200 bg-surface-2 px-3.5 pb-3.5 pt-4 transition-transform duration-200 lg:sticky lg:top-0 lg:h-screen lg:translate-x-0 ${
          mobileNav ? "translate-x-0" : "-translate-x-full"
        }`}
      >
        <div className="flex items-center gap-2.5 px-2 pb-5">
          <span className="flex h-[34px] w-[34px] items-center justify-center rounded-[10px] bg-gradient-to-br from-brand-500 to-brand-700 font-mono text-[12px] font-bold text-white shadow-[0_4px_12px_rgba(79,70,229,0.28)]">
            TG
          </span>
          <div className="min-w-0">
            <div className="text-[15px] font-semibold tracking-[-0.025em] text-ink-900">TraceGuard</div>
            <div className="mt-px text-[11px] text-ink-400">agent control plane</div>
          </div>
        </div>

        <nav className="flex flex-col gap-[17px]" aria-label="Primary">
          {NAV_GROUPS.map((group) => (
            <div key={group.label}>
              <div className="px-2.5 pb-1 text-[10px] font-semibold uppercase tracking-[0.09em] text-ink-400">
                {group.label}
              </div>
              <div className="flex flex-col gap-0.5">
                {group.tabs.map((id) => {
                  const label = tabLabel(id);
                  const active = tab === id && !openRun;
                  return (
                    <button
                      key={id}
                      onClick={() => go(id)}
                      aria-current={active ? "page" : undefined}
                      className={`relative flex items-center gap-2.5 rounded-lg px-2.5 py-2 text-[13px] transition-colors ${
                        active
                          ? "bg-brand-50 font-semibold text-brand-700 dark:bg-brand-500/15 dark:text-brand-300"
                          : "text-ink-600 hover:bg-ink-100 hover:text-ink-900"
                      }`}
                    >
                      <NavIcon name={id} className="h-[17px] w-[17px]" />
                      {label}
                      {id === "approvals" && pendingApprovals > 0 && (
                        <span
                          className="tg-nums ml-auto rounded-full bg-bad-700 px-1.5 py-0.5 text-[10px] font-semibold leading-none text-white"
                          aria-label={`${pendingApprovals} pending`}
                        >
                          {pendingApprovals}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>

        <div className="mt-auto flex flex-col gap-2.5">
          <button
            onClick={() => setDrawer(true)}
            aria-label="Open connection settings"
            className="flex w-full items-center gap-2.5 rounded-lg border border-ink-200 bg-surface px-2.5 py-2 text-left text-[11.5px] text-ink-500 hover:border-ink-300"
          >
            <span
              className={`h-2 w-2 shrink-0 rounded-full ${
                connected === null ? "bg-ink-300" : connected ? "bg-ok-700" : "bg-bad-700"
              }`}
              aria-hidden="true"
            />
            <span className="min-w-0">
              <span className="block font-medium text-ink-700">
                {connected === null ? "Checking API" : connected ? "API connected" : "API unreachable"}
              </span>
              <span className="block truncate text-[10.5px] text-ink-400">{settings.url}</span>
            </span>
          </button>
          <div className="flex items-center gap-2 px-1.5 py-1">
            <span className="flex h-[29px] w-[29px] items-center justify-center rounded-full border border-ink-200 bg-ink-100 text-[10.5px] font-semibold text-ink-600">
              TG
            </span>
            <div className="min-w-0">
              <div className="text-[12px] font-semibold text-ink-700">Control plane</div>
              <div className="text-[10.5px] text-ink-400">self-hosted</div>
            </div>
          </div>
        </div>
      </aside>

      <div className="min-w-0 flex-1">
        <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-ink-200 bg-ink-50/85 px-4 backdrop-blur-md lg:px-7">
          <button
            type="button"
            onClick={() => setMobileNav(true)}
            aria-label="Open navigation"
            className="flex h-8 w-8 items-center justify-center rounded-lg text-ink-500 hover:bg-ink-100 hover:text-ink-900 lg:hidden"
          >
            <NavIcon name="menu" className="h-4 w-4" />
          </button>
          <span className="flex items-center gap-2 sm:hidden">
            <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-brand-400 to-brand-700 font-mono text-xs font-bold text-white shadow-sm shadow-brand-600/25">
              TG
            </span>
            <span className="text-[13px] font-semibold tracking-tight text-ink-900">TraceGuard</span>
          </span>
          <div className="hidden items-center gap-1.5 text-[12.5px] text-ink-400 sm:flex">
            <span>Workspace</span>
            <NavIcon name="chevronRight" className="h-3 w-3" />
            {openRun ? (
              <>
                <span>Runs</span>
                <NavIcon name="chevronRight" className="h-3 w-3" />
                <span className="font-mono font-semibold text-ink-800">{short(openRun)}</span>
              </>
            ) : (
              <strong className="font-semibold text-ink-800">{tabLabel(tab)}</strong>
            )}
          </div>
          <div className="flex-1" />
          <button
            type="button"
            onClick={() => setPalette(true)}
            aria-label="Open command palette"
            className="flex h-8 items-center gap-2 rounded-lg border border-ink-200 bg-surface px-2.5 text-[12px] text-ink-400 hover:border-ink-300 hover:text-ink-600"
          >
            <NavIcon name="search" className="h-4 w-4" />
            <span className="hidden md:inline">Search or jump to…</span>
            <kbd className="ml-2 hidden rounded border border-ink-200 bg-surface-3 px-1.5 py-0.5 font-mono text-[10px] text-ink-400 md:inline">
              Ctrl K
            </kbd>
          </button>
          <ThemeToggle />
        </header>

        <main>
          {tab === "overview" ? (
            <OverviewView
              onNavigate={go}
              onOpenRun={(id) => navigate({ tab: "runs", runId: id, approvalId: null })}
              onOpenApproval={(id) => navigate({ tab: "approvals", runId: null, approvalId: id })}
            />
          ) : tab === "evals" ? (
            <EvalsView onOpenRun={(id) => navigate({ tab: "runs", runId: id, approvalId: null })} />
          ) : tab === "policy" ? (
            <PoliciesView />
          ) : tab === "approvals" ? (
            <ApprovalsView
              focusId={approvalId}
              onOpenRun={(id) => navigate({ tab: "runs", runId: id, approvalId: null })}
            />
          ) : tab === "webhooks" ? (
            <WebhooksView />
          ) : tab === "retention" ? (
            <RetentionView />
          ) : tab === "costs" ? (
            <CostsView />
          ) : tab === "users" ? (
            <UsersView />
          ) : openRun ? (
            <TraceView
              runId={openRun}
              onBack={() => navigate({ tab: "runs", runId: null, approvalId: null })}
              onOpenApproval={(id) => navigate({ tab: "approvals", runId: null, approvalId: id })}
              onOpenPolicy={() => navigate({ tab: "policy", runId: null, approvalId: null })}
            />
          ) : (
            <RunsView onOpen={(id) => navigate({ tab: "runs", runId: id, approvalId: null })} />
          )}
        </main>
      </div>

      <Palette open={palette} onClose={() => setPalette(false)} items={paletteItems} />
      <ConnectionDrawer
        open={drawer}
        onClose={() => setDrawer(false)}
        onSaved={() => queryClient.invalidateQueries()}
      />
    </div>
  );
}
