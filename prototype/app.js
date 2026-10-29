/* TraceGuard redesign prototype — sample data + interactions.
   No framework, no network, no persistence beyond the theme choice. */

const ICONS = {
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  play: '<path d="M6 4.5v15l13-7.5-13-7.5z"/>',
  shield: '<path d="M12 3l7 3v5c0 5-3.5 8-7 10-3.5-2-7-5-7-10V6l7-3z"/>',
  check: '<path d="M20 6L9 17l-5-5"/>',
  checkSquare: '<rect x="3" y="3" width="18" height="18" rx="3"/><path d="M8 12l3 3 5-6"/>',
  flask: '<path d="M9 3h6M10 3v6l-5.5 9.5A2 2 0 006.2 21h11.6a2 2 0 001.7-2.5L14 9V3"/><path d="M8.5 14h7"/>',
  dollar: '<path d="M12 2v20M17 5H9.5a3.5 3.5 0 000 7h5a3.5 3.5 0 010 7H6"/>',
  link: '<path d="M10 13a5 5 0 007.5.5l2-2a5 5 0 00-7-7l-1.5 1.5"/><path d="M14 11a5 5 0 00-7.5-.5l-2 2a5 5 0 007 7L13 18"/>',
  archive: '<rect x="3" y="4" width="18" height="4" rx="1"/><path d="M5 8v11a1 1 0 001 1h12a1 1 0 001-1V8M10 12h4"/>',
  users: '<path d="M17 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2"/><circle cx="9.5" cy="7" r="4"/><path d="M22 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
  moon: '<path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"/>',
  bell: '<path d="M18 8a6 6 0 00-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M13.7 21a2 2 0 01-3.4 0"/>',
  arrowLeft: '<path d="M19 12H5M12 19l-7-7 7-7"/>',
  arrowRight: '<path d="M5 12h14M12 5l7 7-7 7"/>',
  refresh: '<path d="M20 11a8 8 0 10-2.3 5.7M20 4v7h-7"/>',
  chevronRight: '<path d="M9 18l6-6-6-6"/>',
  chevronDown: '<path d="M6 9l6 6 6-6"/>',
  filter: '<path d="M3 5h18M6 12h12M10 19h4"/>',
  download: '<path d="M12 3v12M7 10l5 5 5-5M5 21h14"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  alert: '<path d="M12 3l9.5 17H2.5L12 3z"/><path d="M12 9v4M12 17h.01"/>',
  x: '<path d="M18 6L6 18M6 6l12 12"/>',
  copy: '<rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15H4a1 1 0 01-1-1V4a1 1 0 011-1h10a1 1 0 011 1v1"/>',
  bot: '<rect x="4" y="8" width="16" height="12" rx="3"/><path d="M12 8V4M9 4h6"/><circle cx="9" cy="14" r="1"/><circle cx="15" cy="14" r="1"/>',
  tool: '<path d="M14.7 6.3a4 4 0 00-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 005.4-5.4l-2.5 2.5-3-3 2.5-2.5z"/>',
  zap: '<path d="M13 2L3 14h8l-1 8 10-12h-8l1-8z"/>',
  lock: '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 018 0v3"/>',
  activity: '<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  external: '<path d="M14 3h7v7M21 3l-9 9M18 14v6a1 1 0 01-1 1H4a1 1 0 01-1-1V7a1 1 0 011-1h6"/>',
  more: '<circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/>',
  settings: '<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 00.3 1.9l.1.1a2 2 0 11-2.8 2.8l-.1-.1a1.7 1.7 0 00-1.9-.3 1.7 1.7 0 00-1 1.6V21a2 2 0 11-4 0v-.1a1.7 1.7 0 00-1-1.6 1.7 1.7 0 00-1.9.3l-.1.1a2 2 0 11-2.8-2.8l.1-.1a1.7 1.7 0 00.3-1.9 1.7 1.7 0 00-1.6-1H3a2 2 0 110-4h.1a1.7 1.7 0 001.6-1 1.7 1.7 0 00-.3-1.9l-.1-.1a2 2 0 112.8-2.8l.1.1a1.7 1.7 0 001.9.3H10a1.7 1.7 0 001-1.6V3a2 2 0 114 0v.1a1.7 1.7 0 001 1.6 1.7 1.7 0 001.9-.3l.1-.1a2 2 0 112.8 2.8l-.1.1a1.7 1.7 0 00-.3 1.9V10a1.7 1.7 0 001.6 1H21a2 2 0 110 4h-.1a1.7 1.7 0 00-1.6 1z"/>',
  checkCircle: '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
  xCircle: '<circle cx="12" cy="12" r="9"/><path d="M9 9l6 6M15 9l-6 6"/>',
  menu: '<path d="M4 6h16M4 12h16M4 18h16"/>',
  terminal: '<path d="M4 17l6-5-6-5M12 19h8"/>',
  calendar: '<rect x="3" y="5" width="18" height="16" rx="2"/><path d="M16 3v4M8 3v4M3 11h18"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
  spark: '<path d="M12 3l1.8 5.2L19 10l-5.2 1.8L12 17l-1.8-5.2L5 10l5.2-1.8L12 3z"/>'
};

const icon = (name, cls = "") =>
  `<svg class="icon ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name] || ""}</svg>`;

const NAV = [
  { group: "Monitor", items: [
    { id: "overview", label: "Overview", icon: "grid" },
    { id: "runs", label: "Runs", icon: "play" }
  ]},
  { group: "Control", items: [
    { id: "policy", label: "Policy", icon: "shield" },
    { id: "approvals", label: "Approvals", icon: "checkSquare", badge: 2 }
  ]},
  { group: "Analyze", items: [
    { id: "evals", label: "Evaluations", icon: "flask" },
    { id: "costs", label: "Costs", icon: "dollar" }
  ]},
  { group: "Configure", items: [
    { id: "webhooks", label: "Webhooks", icon: "link" },
    { id: "retention", label: "Retention", icon: "archive" },
    { id: "users", label: "Users", icon: "users" }
  ]}
];

const SCREEN_LABELS = {
  overview: "Overview", runs: "Runs", policy: "Policy", approvals: "Approvals",
  evals: "Evaluations", costs: "Costs", webhooks: "Webhooks", retention: "Retention", users: "Users"
};

const RUNS = [
  { id: "r_9f2c4a1b", agent: "support-triage", status: "success", started: "2 min ago", duration: "1.42 s", spans: 12, tin: 1840, tout: 420, cost: "$0.0184", model: "gpt-4.1" },
  { id: "r_7d1e8c33", agent: "billing-copilot", status: "running", started: "just now", duration: "8.24 s", spans: 7, tin: 3120, tout: 84, cost: "$0.0121", model: "gpt-4.1-mini" },
  { id: "r_2a9b4f10", agent: "docs-agent", status: "failed", started: "4 min ago", duration: "3.18 s", spans: 9, tin: 920, tout: 210, cost: "$0.0063", model: "claude-3.7" },
  { id: "r_6c3d9a72", agent: "code-reviewer", status: "success", started: "7 min ago", duration: "2.04 s", spans: 15, tin: 4210, tout: 680, cost: "$0.0312", model: "gpt-4.1" },
  { id: "r_1f8e2b90", agent: "support-triage", status: "denied", started: "11 min ago", duration: "0.84 s", spans: 5, tin: 640, tout: 0, cost: "$0.0012", model: "gpt-4.1-mini" },
  { id: "r_5b7a1c44", agent: "data-pipeline", status: "success", started: "14 min ago", duration: "4.96 s", spans: 21, tin: 8840, tout: 1240, cost: "$0.0620", model: "claude-3.7" },
  { id: "r_8e4f6d21", agent: "billing-copilot", status: "success", started: "18 min ago", duration: "1.12 s", spans: 6, tin: 1500, tout: 360, cost: "$0.0148", model: "gpt-4.1-mini" },
  { id: "r_3d9c7e55", agent: "docs-agent", status: "running", started: "22 min ago", duration: "12.4 s", spans: 4, tin: 720, tout: 0, cost: "$0.0009", model: "claude-3.7" },
  { id: "r_0a2b8f16", agent: "support-triage", status: "failed", started: "31 min ago", duration: "2.76 s", spans: 8, tin: 1180, tout: 94, cost: "$0.0041", model: "gpt-4.1" },
  { id: "r_4c6e9d38", agent: "code-reviewer", status: "cancelled", started: "45 min ago", duration: "0.42 s", spans: 3, tin: 120, tout: 0, cost: "$0.0002", model: "gpt-4.1" },
  { id: "r_7f1a3b82", agent: "data-pipeline", status: "success", started: "1 hr ago", duration: "6.21 s", spans: 26, tin: 12040, tout: 2100, cost: "$0.0890", model: "claude-3.7" },
  { id: "r_2e8d5c47", agent: "docs-agent", status: "success", started: "1 hr ago", duration: "1.88 s", spans: 11, tin: 2100, tout: 480, cost: "$0.0210", model: "gpt-4.1" }
];

const TOTAL_MS = 1420;
const SPANS = [
  { id: "sp-1", name: "run.completed", type: "run", depth: 0, start: 0, duration: 1420, status: "success", provider: "internal", model: null, tin: 0, tout: 0, cost: "—", attrs: { "traceguard.run_id": "r_9f2c4a1b", "traceguard.agent": "support-triage", "traceguard.workspace": "acme-prod" } },
  { id: "sp-2", name: "agent.invoke", type: "agent", depth: 1, start: 12, duration: 1396, status: "success", provider: "internal", model: "support-triage", tin: 0, tout: 0, cost: "—", attrs: { "agent.name": "support-triage", "agent.framework": "langgraph", "agent.version": "0.4.2" } },
  { id: "sp-3", name: "memory.read", type: "internal", depth: 2, start: 24, duration: 8, status: "success", provider: "redis", model: null, tin: 0, tout: 0, cost: "—", attrs: { "store": "redis", "keys": 3, "hit_rate": 1.0 } },
  { id: "sp-4", name: "policy.evaluate", type: "policy", depth: 2, start: 32, duration: 14, status: "success", provider: "traceguard", model: null, tin: 0, tout: 0, cost: "—", decision: { effect: "allow", rule: "default-allow", policy: "v14", reason: "Call matched an allow rule and stayed within the run budget." }, attrs: { "policy.version": 14, "policy.rule": "default-allow", "policy.effect": "allow" } },
  { id: "sp-5", name: "model.request", type: "model", depth: 2, start: 58, duration: 612, status: "success", provider: "openai", model: "gpt-4.1", tin: 1204, tout: 318, cost: "$0.0094", attrs: { "gen_ai.provider.name": "openai", "gen_ai.request.model": "gpt-4.1", "gen_ai.usage.input_tokens": 1204, "gen_ai.usage.output_tokens": 318, "gen_ai.response.finish_reason": "tool_calls" } },
  { id: "sp-6", name: "tool.invocation", type: "tool", depth: 2, start: 690, duration: 186, status: "denied", provider: "mcp/filesystem", model: "read_file", tin: 0, tout: 0, cost: "—", decision: { effect: "deny", rule: "no-outside-data", policy: "v14", reason: "The gateway refused this call before any upstream request. The requested path resolves outside the allowed root." }, attrs: { "mcp.server": "filesystem", "tool.name": "read_file", "arguments.path": "/etc/secrets.env", "policy.rule": "no-outside-data", "policy.version": 14, "caller": "support-triage" } },
  { id: "sp-7", name: "policy.evaluate", type: "policy", depth: 3, start: 700, duration: 8, status: "denied", provider: "traceguard", model: null, tin: 0, tout: 0, cost: "—", decision: { effect: "deny", rule: "no-outside-data", policy: "v14", reason: "Path confinement failed: /etc/secrets.env is outside /data." }, attrs: { "policy.version": 14, "policy.rule": "no-outside-data", "policy.effect": "deny", "condition": "path_within /data" } },
  { id: "sp-8", name: "cache.read", type: "internal", depth: 3, start: 884, duration: 6, status: "success", provider: "redis", model: null, tin: 0, tout: 0, cost: "—", attrs: { "store": "redis", "key": "docs:refund-policy:2026", "hit": true } },
  { id: "sp-9", name: "tool.invocation", type: "tool", depth: 2, start: 892, duration: 242, status: "success", provider: "mcp/search", model: "search_docs", tin: 0, tout: 0, cost: "—", decision: { effect: "allow", rule: "docs-allow", policy: "v14", reason: "Read-only tool scoped to the public documentation index." }, attrs: { "mcp.server": "search", "tool.name": "search_docs", "arguments.query": "refund policy 2026", "results": 4, "policy.rule": "docs-allow" } },
  { id: "sp-10", name: "db.query", type: "internal", depth: 3, start: 1140, duration: 42, status: "success", provider: "postgres", model: null, tin: 0, tout: 0, cost: "—", attrs: { "db.system": "postgresql", "db.operation": "SELECT", "db.rows": 4, "db.statement": "SELECT id, title FROM docs WHERE tsv @@ query" } },
  { id: "sp-11", name: "model.request", type: "model", depth: 2, start: 1150, duration: 248, status: "success", provider: "openai", model: "gpt-4.1", tin: 636, tout: 102, cost: "$0.0027", attrs: { "gen_ai.provider.name": "openai", "gen_ai.request.model": "gpt-4.1", "gen_ai.usage.input_tokens": 636, "gen_ai.usage.output_tokens": 102, "gen_ai.response.finish_reason": "stop" } },
  { id: "sp-12", name: "usage.record", type: "internal", depth: 2, start: 1402, duration: 10, status: "success", provider: "traceguard", model: null, tin: 0, tout: 0, cost: "—", attrs: { "usage.input_tokens": 1840, "usage.output_tokens": 420, "cost.micro_usd": 18400, "pricing.version": 7 } }
];

const SPAN_COLORS = { run: "#5b6475", agent: "#818cf8", model: "#60a5fa", tool: "#2dd4bf", policy: "#fbbf24", internal: "#3f4a5c" };
const SPAN_ICONS = { run: "activity", agent: "bot", model: "spark", tool: "tool", policy: "shield", internal: "terminal" };

const AGENTS = [
  { name: "support-triage", runs: 842, success: 96 },
  { name: "docs-agent", runs: 611, success: 92 },
  { name: "billing-copilot", runs: 438, success: 88 },
  { name: "code-reviewer", runs: 297, success: 98 }
];

const POLICY_SLICES = [
  { label: "Allowed", value: 2084, color: "var(--ok)" },
  { label: "Approval", value: 137, color: "var(--warn)" },
  { label: "Denied", value: 67, color: "var(--bad)" }
];

const KPIS = [
  { label: "Total runs", value: "2,288", delta: "+12.4%", deltaClass: "up", meta: "vs. previous 24h", color: "var(--accent)", spark: [120, 132, 118, 145, 139, 158, 152, 176, 168, 190, 184, 204] },
  { label: "Success rate", value: "94.2%", delta: "+1.8%", deltaClass: "up", meta: "2,155 succeeded", color: "var(--ok)", spark: [90, 91, 90.5, 92, 91.8, 92.5, 93, 92.8, 93.5, 94, 93.8, 94.2] },
  { label: "Est. spend", value: "$54.12", delta: "68% of budget", deltaClass: "neutral", meta: "$25.88 remaining", color: "var(--warn)", spark: [22, 25, 24, 29, 27, 33, 31, 36, 34, 41, 44, 54] },
  { label: "p95 latency", value: "1.24s", delta: "-8.3%", deltaClass: "up", meta: "across 2,288 runs", color: "var(--info)", spark: [1.6, 1.55, 1.58, 1.5, 1.46, 1.48, 1.42, 1.4, 1.38, 1.32, 1.28, 1.24] }
];

const METRICS = {
  runs: { label: "Runs", unit: "runs", color: "var(--accent)", values: [42, 58, 51, 74, 68, 92, 81, 104, 88, 96, 120, 108, 132, 118, 144, 128, 152, 138, 164, 148, 172, 158, 184, 168], format: (v) => Math.round(v).toLocaleString() },
  tokens: { label: "Tokens", unit: "tokens", color: "var(--info)", values: [180, 240, 210, 320, 280, 410, 360, 480, 420, 510, 620, 580, 690, 640, 760, 700, 820, 760, 900, 840, 960, 900, 1040, 980], format: (v) => v >= 1000 ? `${(v / 1000).toFixed(1)}k` : `${Math.round(v)}` },
  cost: { label: "Cost", unit: "spend", color: "var(--ok)", values: [0.9, 1.2, 1.1, 1.6, 1.4, 2.1, 1.8, 2.4, 2.0, 2.6, 3.1, 2.9, 3.4, 3.2, 3.8, 3.5, 4.1, 3.8, 4.4, 4.1, 4.8, 4.5, 5.2, 4.9], format: (v) => `$${v.toFixed(1)}` }
};

const TRACE_DECISIONS = [
  { time: "58 ms", tool: "gpt-4.1", decision: "allow", reason: "Model call within the run budget", rule: "model-default", policy: "v14" },
  { time: "700 ms", tool: "read_file", decision: "deny", reason: "Path outside allowed root", rule: "no-outside-data", policy: "v14" },
  { time: "892 ms", tool: "search_docs", decision: "allow", reason: "Read-only tool, public index", rule: "docs-allow", policy: "v14" }
];

const PLACEHOLDERS = {
  policy: { title: "Tool policies", eyebrow: "Control", icon: "shield", desc: "Rules, upstream servers, signed policy versions, and the audit chain — split into focused sub-views.", items: ["Condition builder with an advanced JSON escape hatch", "Signed-version timeline with key and rollback state", "Server registry with tool quarantine review", "Audit chain verification with checkpoint coverage"] },
  approvals: { title: "Approvals", eyebrow: "Control", icon: "checkSquare", desc: "A review inbox for held tool calls, with the context needed to decide safely.", items: ["Inbox and detail split view", "Expiry countdown and caller risk context", "Argument diffs against the pinned tool definition", "Bulk review for low-risk holds"] },
  evals: { title: "Evaluations", eyebrow: "Analyze", icon: "flask", desc: "Versioned suites, per-case results, and a comparison view built for deciding what shipped.", items: ["Suite library with locked datasets", "Case results with failure reasons", "Two-run comparison with pass rate and cost", "Links back to the underlying traces"] },
  costs: { title: "Costs", eyebrow: "Analyze", icon: "dollar", desc: "Spend exploration that separates what we estimate from what the provider actually billed.", items: ["Spend explorer grouped by model, agent, or project", "Budget utilization with block and warn states", "Estimate versus invoice variance", "Missing-pricing warnings that never read as zero"] },
  webhooks: { title: "Webhooks", eyebrow: "Configure", icon: "link", desc: "Subscription health and a delivery log that makes retries obvious.", items: ["Endpoint health and signature status", "Delivery log with response codes", "Manual retry with idempotency", "Event filters for denials, approvals, and budgets"] },
  retention: { title: "Retention", eyebrow: "Configure", icon: "archive", desc: "Age-out rules that protect the records which must never be deleted.", items: ["Rules for runs, terminal approvals, and delivery logs", "Run history with affected record counts", "Guardrails for policies, decisions, and money tables", "Dry-run preview before a rule is applied"] },
  users: { title: "Users", eyebrow: "Configure", icon: "users", desc: "Team, scoped keys, and workspace membership in one place.", items: ["Member and approver key scopes", "Workspace membership and role changes", "Last-used and rotation state for each key", "Bootstrap-admin and recovery guidance"] }
};

/* ---------- helpers ---------- */

const escapeHtml = (value) => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const initials = (name) => name.split(/[-_\s]+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
const statusLabel = (status) => ({ all: "All", success: "Success", running: "Running", failed: "Failed", denied: "Denied", cancelled: "Cancelled" }[status] || status);
const TIME_LABELS = { "24h": "Last 24 hours", "7d": "Last 7 days", "30d": "Last 30 days" };
const chip = (status) => `<span class="chip ${status}"><span class="chip-dot"></span>${statusLabel(status)}</span>`;

function sparkline(values, color) {
  const w = 128, h = 34, min = Math.min(...values), max = Math.max(...values), span = max - min || 1;
  const pts = values.map((v, i) => [3 + (i / (values.length - 1)) * (w - 6), h - 4 - ((v - min) / span) * (h - 8)]);
  const line = pts.map((p) => `${p[0].toFixed(1)},${p[1].toFixed(1)}`).join(" ");
  return `<svg class="kpi-spark" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" aria-hidden="true"><polygon points="3,${h} ${line} ${w - 3},${h}" fill="${color}" opacity=".08"/><polyline points="${line}" fill="none" stroke="${color}" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>`;
}

function smoothPath(points) {
  if (points.length < 2) return "";
  let d = `M ${points[0][0]},${points[0][1]}`;
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[i - 1] || points[i];
    const p1 = points[i];
    const p2 = points[i + 1];
    const p3 = points[i + 2] || p2;
    const cp1x = p1[0] + (p2[0] - p0[0]) / 6;
    const cp1y = p1[1] + (p2[1] - p0[1]) / 6;
    const cp2x = p2[0] - (p3[0] - p1[0]) / 6;
    const cp2y = p2[1] - (p3[1] - p1[1]) / 6;
    d += ` C ${cp1x},${cp1y} ${cp2x},${cp2y} ${p2[0]},${p2[1]}`;
  }
  return d;
}

function donut(slices, centerValue, centerLabel, size = 132, thickness = 12) {
  const total = slices.reduce((sum, s) => sum + s.value, 0) || 1;
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;
  const gap = 2;
  const arcs = slices.map((s) => {
    const len = (s.value / total) * c;
    const arc = `<circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="${s.color}" stroke-width="${thickness}" stroke-dasharray="${Math.max(0, len - gap)} ${c - len + gap}" stroke-dashoffset="${-offset}"/>`;
    offset += len;
    return arc;
  }).join("");
  return `<div class="donut" style="width:${size}px;height:${size}px">
    <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" style="transform:rotate(-90deg)" aria-hidden="true">
      <circle cx="${size / 2}" cy="${size / 2}" r="${r}" fill="none" stroke="var(--surface-3)" stroke-width="${thickness}"/>
      ${arcs}
    </svg>
    <div class="donut-center"><strong>${centerValue}</strong><span>${centerLabel}</span></div>
  </div>`;
}

function activityChart() {
  const metric = METRICS[state.chartMetric];
  const values = metric.values;
  const max = Math.max(...values) * 1.18;
  const mobile = window.matchMedia("(max-width: 760px)").matches;
  const W = mobile ? 360 : 820, H = mobile ? 260 : 420, L = mobile ? 34 : 42, R = 12, T = 12, B = mobile ? 30 : 28;
  const x = (i) => L + (i / (values.length - 1)) * (W - L - R);
  const y = (v) => T + (1 - v / max) * (H - T - B);
  const points = values.map((v, i) => [x(i), y(v)]);
  const line = smoothPath(points);
  const area = `${line} L ${x(values.length - 1)},${H - B} L ${x(0)},${H - B} Z`;
  const ticks = [0, max / 3, (max / 3) * 2, max];
  const grid = ticks.map((t) => `<line x1="${L}" x2="${W - R}" y1="${y(t)}" y2="${y(t)}" class="grid-line"/><text x="${L - 8}" y="${y(t) + 3}" text-anchor="end" class="axis-label">${metric.format(t)}</text>`).join("");
  const labels = ["00:00", "04:00", "08:00", "12:00", "16:00", "20:00", "now"];
  const labelIndexes = [0, 4, 8, 12, 16, 20, 23];
  const xLabels = labels.map((label, i) => `<text x="${x(labelIndexes[i])}" y="${H - 7}" text-anchor="${i === 0 ? "start" : i === labels.length - 1 ? "end" : "middle"}" class="axis-label">${label}</text>`).join("");
  const last = points[points.length - 1];
  return `<svg class="chart-svg" viewBox="0 0 ${W} ${H}" role="img" aria-label="${metric.label} over the last 24 hours">
    <defs><linearGradient id="areaGrad" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="${metric.color}" stop-opacity=".22"/><stop offset="100%" stop-color="${metric.color}" stop-opacity="0"/></linearGradient></defs>
    ${grid}
    <path d="${area}" fill="url(#areaGrad)"/>
    <path d="${line}" fill="none" stroke="${metric.color}" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>
    <line x1="${last[0]}" y1="${T}" x2="${last[0]}" y2="${H - B}" stroke="${metric.color}" stroke-width="1" stroke-dasharray="3 4" opacity=".28"/>
    <circle cx="${last[0]}" cy="${last[1]}" r="4" fill="${metric.color}" stroke="var(--surface)" stroke-width="2"/>
    ${xLabels}
  </svg>`;
}

/* ---------- app state ---------- */

const state = {
  theme: readTheme(),
  status: "all",
  agent: "all",
  time: "24h",
  query: "",
  chartMetric: "runs",
  selectedSpan: "sp-6",
  inspectorTab: "overview",
  paletteOpen: false,
  paletteQuery: "",
  paletteIndex: 0
};

function readTheme() {
  try {
    const saved = localStorage.getItem("tg-theme");
    if (saved === "dark" || saved === "light") return saved;
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  } catch { return "light"; }
}

function applyTheme() {
  document.documentElement.dataset.theme = state.theme;
  const btn = document.getElementById("themeToggle");
  if (btn) {
    btn.innerHTML = icon(state.theme === "dark" ? "sun" : "moon");
    btn.setAttribute("aria-label", state.theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
  }
  try { localStorage.setItem("tg-theme", state.theme); } catch { /* private mode */ }
}

function toggleTheme() {
  state.theme = state.theme === "dark" ? "light" : "dark";
  applyTheme();
}

/* ---------- nav + chrome ---------- */

function navHtml() {
  return NAV.map((group) => `<div class="nav-group">
    <div class="nav-label">${group.group}</div>
    ${group.items.map((item) => `<a class="nav-item" data-nav="${item.id}" href="#/${item.id}">${icon(item.icon)}<span>${item.label}</span>${item.badge ? `<span class="nav-badge">${item.badge}</span>` : ""}</a>`).join("")}
  </div>`).join("");
}

function updateChrome(screen, id) {
  document.querySelectorAll(".nav-item").forEach((link) => {
    const active = link.dataset.nav === screen;
    link.classList.toggle("active", active);
    if (active) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  const crumb = document.getElementById("breadcrumb");
  let html = `<span>Workspace</span>${icon("chevronRight")}`;
  if (screen === "runs" && id) {
    html += `<a href="#/runs">Runs</a>${icon("chevronRight")}<strong>${escapeHtml(id)}</strong>`;
  } else {
    html += `<strong>${SCREEN_LABELS[screen] || "Overview"}</strong>`;
  }
  crumb.innerHTML = html;
  document.title = `${SCREEN_LABELS[screen] || "Overview"} · TraceGuard`;
}

/* ---------- overview ---------- */

function renderAttention() {
  return `<div class="attention" aria-label="Needs attention">
    <a class="attention-item" href="#/approvals">
      <span class="attention-icon warn">${icon("clock")}</span>
      <span class="attention-copy"><span class="attention-title">2 approvals waiting</span><span class="attention-desc">Held tool calls are blocked until reviewed.</span></span>
      <span class="attention-link">${icon("chevronRight")}</span>
    </a>
    <a class="attention-item" href="#/costs">
      <span class="attention-icon warn">${icon("dollar")}</span>
      <span class="attention-copy"><span class="attention-title">Budget at 92%</span><span class="attention-desc">support-triage is $4.12 from its daily cap.</span></span>
      <span class="attention-link">${icon("chevronRight")}</span>
    </a>
    <a class="attention-item" href="#/runs" data-attention-failed>
      <span class="attention-icon bad">${icon("alert")}</span>
      <span class="attention-copy"><span class="attention-title">3 failed runs</span><span class="attention-desc">All failed in the last hour.</span></span>
      <span class="attention-link">${icon("chevronRight")}</span>
    </a>
  </div>`;
}

function renderKpis() {
  return `<div class="kpi-grid">${KPIS.map((kpi) => `<div class="card kpi">
    <div class="kpi-head"><span class="kpi-label">${kpi.label}</span><span class="delta ${kpi.deltaClass}">${kpi.delta}</span></div>
    <div class="kpi-value">${kpi.value}</div>
    <div class="kpi-meta">${kpi.meta}</div>
    ${sparkline(kpi.spark, kpi.color)}
  </div>`).join("")}</div>`;
}

function renderPolicyPosture() {
  const total = POLICY_SLICES.reduce((sum, s) => sum + s.value, 0);
  return `<div class="card">
    <div class="card-header">
      <div><div class="card-title">Policy posture</div><div class="card-sub">${total.toLocaleString()} decisions in the last 24 hours</div></div>
      <span class="chip success"><span class="chip-dot"></span>Healthy</span>
    </div>
    <div class="donut-wrap">
      ${donut(POLICY_SLICES, "91%", "allowed")}
      <div class="legend">${POLICY_SLICES.map((slice) => `<div class="legend-row">
        <span class="legend-dot" style="background:${slice.color}"></span>
        <span class="legend-label">${slice.label}</span>
        <span class="legend-value">${slice.value.toLocaleString()}</span>
        <span class="legend-pct">${Math.round((slice.value / total) * 100)}%</span>
      </div>`).join("")}</div>
    </div>
  </div>`;
}

function renderTopAgents() {
  const max = Math.max(...AGENTS.map((a) => a.runs));
  return `<div class="card">
    <div class="card-header"><div><div class="card-title">Top agents</div><div class="card-sub">By run volume in this window</div></div></div>
    <div class="agent-list">${AGENTS.map((agent) => `<div>
      <div class="agent-row-head"><span class="agent-name">${agent.name}</span><span class="agent-meta">${agent.runs} runs · ${agent.success}%</span></div>
      <div class="agent-bar"><span class="agent-fill" style="width:${(agent.runs / max) * 100}%"></span></div>
    </div>`).join("")}</div>
  </div>`;
}

function renderRecentRuns() {
  return `<div class="card table-card">
    <div class="card-header">
      <div><div class="card-title">Recent runs</div><div class="card-sub">Newest executions across all agents</div></div>
      <a class="link-btn" href="#/runs">View all runs →</a>
    </div>
    <div class="table-wrap" style="margin-top:12px">
      <table>
        <thead><tr><th>Run</th><th>Agent</th><th>Status</th><th class="num">Duration</th><th class="num">Cost</th></tr></thead>
        <tbody>${RUNS.slice(0, 5).map((run) => `<tr class="clickable" data-run-id="${run.id}" tabindex="0">
          <td><span class="run-id">${run.id}</span></td>
          <td><span class="agent-cell"><span class="agent-avatar">${initials(run.agent)}</span>${run.agent}</span></td>
          <td>${chip(run.status)}</td>
          <td class="num">${run.duration}</td>
          <td class="num">${run.cost}</td>
        </tr>`).join("")}</tbody>
      </table>
    </div>
  </div>`;
}

function renderApprovalsPreview() {
  const approvals = [
    { tool: "read_file", caller: "support-triage", expires: "12 min", risk: "Path /data/contracts" },
    { tool: "send_email", caller: "billing-copilot", expires: "4 min", risk: "External recipient" }
  ];
  return `<div class="card">
    <div class="card-header">
      <div><div class="card-title">Pending approvals <span class="title-count">2</span></div><div class="card-sub">Nothing executes until a human decides</div></div>
      <a class="link-btn" href="#/approvals">Open queue →</a>
    </div>
    <div class="approval-list">${approvals.map((approval) => `<div class="approval-row">
      <span class="approval-icon">${icon("tool")}</span>
      <div class="approval-copy">
        <div class="approval-tool">${approval.tool} <span class="muted">from ${approval.caller}</span></div>
        <div class="approval-meta">${approval.risk} · expires in ${approval.expires}</div>
      </div>
      <a class="btn sm" href="#/approvals">Review</a>
    </div>`).join("")}</div>
  </div>`;
}

function renderOverview() {
  const metric = METRICS[state.chartMetric];
  return `<div class="page">
    <div class="page-header">
      <div>
        <div class="eyebrow">Workspace · Acme Production</div>
        <h1>Overview</h1>
        <p class="page-sub">Runs, spend, and policy posture at a glance. Last 24 hours.</p>
      </div>
      <div class="page-actions">
        <button class="btn">${icon("calendar")} Last 24 hours ${icon("chevronDown")}</button>
        <button class="btn" data-action="refresh">${icon("refresh")} Refresh</button>
        <button class="btn primary">${icon("download")} Export</button>
      </div>
    </div>
    ${renderAttention()}
    ${renderKpis()}
    <div class="dash-grid">
      <div class="card chart-card">
        <div class="card-header">
          <div><div class="card-title">Run activity</div><div class="card-sub">Hourly volume across the last 24 hours</div></div>
          <div class="chart-toolbar">
            <div class="chart-tabs" role="group" aria-label="Chart metric">
              ${Object.entries(METRICS).map(([key, value]) => `<button class="chart-tab ${state.chartMetric === key ? "active" : ""}" data-metric="${key}">${value.label}</button>`).join("")}
            </div>
          </div>
        </div>
        <div class="chart-wrap" id="chartArea">${activityChart()}</div>
        <div class="chart-foot">
          <span class="chart-highlight" id="chartHighlight"><span class="dot" style="background:${metric.color}"></span>${metric.format(metric.values[metric.values.length - 1])} ${metric.unit} in the last hour</span>
          <span class="chart-legend"><span class="legend-dot" style="background:${metric.color}"></span>${metric.label}</span>
        </div>
      </div>
      <div class="right-stack">
        ${renderPolicyPosture()}
        ${renderTopAgents()}
      </div>
    </div>
    <div class="bottom-grid">
      ${renderRecentRuns()}
      ${renderApprovalsPreview()}
    </div>
    <p class="page-footnote">Estimates resolve against the pricing version in force when each span ran. Unpriced usage is flagged, never billed as zero. Refreshes every 15 s.</p>
  </div>`;
}

/* ---------- runs ---------- */

function filteredRuns() {
  const query = state.query.trim().toLowerCase();
  return RUNS.filter((run) => {
    const matchesStatus = state.status === "all" || run.status === state.status;
    const matchesAgent = state.agent === "all" || run.agent === state.agent;
    const matchesQuery = !query || `${run.id} ${run.agent} ${run.model}`.toLowerCase().includes(query);
    return matchesStatus && matchesAgent && matchesQuery;
  });
}

function activeFilterCount() {
  return (state.agent !== "all" ? 1 : 0) + (state.status !== "all" ? 1 : 0) + (state.query.trim() ? 1 : 0);
}

function renderActiveFilters() {
  const chips = [];
  if (state.agent !== "all") chips.push(`<span class="filter-chip">Agent: ${state.agent}<button aria-label="Remove agent filter" data-clear="agent">${icon("x")}</button></span>`);
  if (state.status !== "all") chips.push(`<span class="filter-chip">Status: ${statusLabel(state.status)}<button aria-label="Remove status filter" data-clear="status">${icon("x")}</button></span>`);
  if (state.query.trim()) chips.push(`<span class="filter-chip">Search: “${escapeHtml(state.query.trim())}”<button aria-label="Remove search filter" data-clear="query">${icon("x")}</button></span>`);
  chips.push(`<span class="filter-chip">${TIME_LABELS[state.time]}</span>`);
  return `<div class="active-filters" id="activeFilters">${chips.join("")}${activeFilterCount() ? `<button class="link-btn" data-clear="all">Clear all</button>` : ""}</div>`;
}

function tokenCell(run) {
  const total = run.tin + run.tout || 1;
  const inputPct = Math.round((run.tin / total) * 100);
  return `<div class="token-cell"><span class="token-nums"><b>${run.tin.toLocaleString()}</b> / ${run.tout.toLocaleString()}</span><span class="token-bar"><span style="width:${inputPct}%"></span><span style="width:${100 - inputPct}%"></span></span></div>`;
}

function runRow(run) {
  return `<tr class="clickable" data-run-id="${run.id}" tabindex="0">
    <td><span class="run-id">${run.id}</span></td>
    <td><span class="agent-cell"><span class="agent-avatar">${initials(run.agent)}</span>${run.agent}</span></td>
    <td>${chip(run.status)}</td>
    <td><span class="muted">${run.started}</span></td>
    <td class="num">${run.duration}</td>
    <td class="num">${run.spans}</td>
    <td>${tokenCell(run)}</td>
    <td class="num">${run.cost}</td>
    <td class="row-chevron">${icon("chevronRight")}</td>
  </tr>`;
}

function runsTableBody() {
  const rows = filteredRuns();
  if (rows.length === 0) return `<tr><td colspan="9"><div class="empty-inline">No runs match these filters.</div></td></tr>`;
  return rows.map(runRow).join("");
}

function runsCountText() {
  const rows = filteredRuns();
  if (rows.length === 0) return "No matching runs";
  return `Showing ${rows.length} of 2,288 runs`;
}

function renderRuns() {
  return `<div class="page">
    <div class="page-header">
      <div>
        <div class="eyebrow">Monitor</div>
        <h1>Runs <span class="title-count">2,288</span></h1>
        <p class="page-sub">Every agent execution, newest first. Open a run for its full trace.</p>
      </div>
      <div class="page-actions">
        <button class="btn">${icon("download")} Export</button>
        <button class="btn primary" data-action="refresh">${icon("refresh")} Refresh</button>
      </div>
    </div>
    <div class="card runs-toolbar">
      <div class="toolbar">
        <label class="searchbox">${icon("search")}<input id="runSearch" aria-label="Search runs" placeholder="Search run id, agent, or model..." value="${escapeHtml(state.query)}"></label>
        <div class="segmented" role="group" aria-label="Filter by status">
          ${["all", "success", "running", "failed", "denied"].map((status) => `<button data-status="${status}" class="${state.status === status ? "active" : ""}">${statusLabel(status)}</button>`).join("")}
        </div>
        <select class="select" id="agentFilter" aria-label="Filter by agent">
          <option value="all" ${state.agent === "all" ? "selected" : ""}>All agents</option>
          <option value="support-triage" ${state.agent === "support-triage" ? "selected" : ""}>support-triage</option>
          <option value="docs-agent" ${state.agent === "docs-agent" ? "selected" : ""}>docs-agent</option>
          <option value="billing-copilot" ${state.agent === "billing-copilot" ? "selected" : ""}>billing-copilot</option>
          <option value="code-reviewer" ${state.agent === "code-reviewer" ? "selected" : ""}>code-reviewer</option>
          <option value="data-pipeline" ${state.agent === "data-pipeline" ? "selected" : ""}>data-pipeline</option>
        </select>
        <select class="select" id="timeFilter" aria-label="Time range">
          ${Object.entries(TIME_LABELS).map(([value, label]) => `<option value="${value}" ${state.time === value ? "selected" : ""}>${label}</option>`).join("")}
        </select>
        <button class="btn">${icon("filter")} Filters <span class="filter-count" id="filterCount" ${activeFilterCount() ? "" : "hidden"}>${activeFilterCount()}</span></button>
        <span class="toolbar-spacer"></span>
        <span class="live-pill"><span class="live-dot"></span>Live</span>
      </div>
      ${renderActiveFilters()}
    </div>
    <div class="card table-card">
      <div class="card-header table-head">
        <div><div class="card-title">All runs</div><div class="card-sub" id="runsCount">${runsCountText()}</div></div>
        <div class="page-actions">
          <button class="btn sm">${icon("settings")} Columns</button>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Run</th><th>Agent</th><th>Status</th><th>Started</th><th class="num">Duration</th><th class="num">Spans</th><th>Tokens in / out</th><th class="num">Cost</th><th></th></tr></thead>
          <tbody id="runsTbody">${runsTableBody()}</tbody>
        </table>
      </div>
      <div class="pagination">
        <span id="paginationSummary">${paginationText()}</span>
        <div class="pagination-actions"><button class="btn sm" disabled>Previous</button><button class="btn sm">Next</button></div>
      </div>
    </div>
    <p class="page-footnote">Times are shown in your local timezone. Policy denials are separated from failures so a blocked call never reads as a crash.</p>
  </div>`;
}

function paginationText() {
  const count = filteredRuns().length;
  if (activeFilterCount() === 0) return "Showing 1–12 of 2,288 · auto-refreshes every 10 s";
  return `${count} matching ${count === 1 ? "run" : "runs"} · auto-refreshes every 10 s`;
}

function updateRunsTable() {
  const tbody = document.getElementById("runsTbody");
  if (tbody) tbody.innerHTML = runsTableBody();
  const count = document.getElementById("runsCount");
  if (count) count.textContent = runsCountText();
  const active = document.getElementById("activeFilters");
  if (active) active.outerHTML = renderActiveFilters();
  const filterCount = document.getElementById("filterCount");
  if (filterCount) {
    filterCount.textContent = activeFilterCount();
    filterCount.hidden = activeFilterCount() === 0;
  }
  const agent = document.getElementById("agentFilter");
  if (agent) agent.value = state.agent;
  const time = document.getElementById("timeFilter");
  if (time) time.value = state.time;
  const pagination = document.getElementById("paginationSummary");
  if (pagination) pagination.textContent = paginationText();
  document.querySelectorAll("[data-status]").forEach((button) => {
    button.classList.toggle("active", button.dataset.status === state.status);
  });
}

/* ---------- trace ---------- */

function traceStat(label, value) {
  return `<div class="trace-stat"><div class="trace-stat-label">${label}</div><div class="trace-stat-value">${value}</div></div>`;
}

function spanColor(span) {
  return span.status === "denied" ? "#f87171" : (SPAN_COLORS[span.type] || "#64748b");
}

function spanRow(span) {
  const left = (span.start / TOTAL_MS) * 100;
  const width = Math.max(0.55, (span.duration / TOTAL_MS) * 100);
  const selected = state.selectedSpan === span.id;
  return `<button class="span-row ${selected ? "selected" : ""}" data-span="${span.id}">
    <span class="span-label" style="padding-left:${span.depth * 13}px">
      ${icon(SPAN_ICONS[span.type], `span-type-icon ${span.type}`)}
      <span class="span-name">${span.name}</span>
      ${span.model ? `<span class="span-model">${span.model}</span>` : ""}
      ${span.status === "denied" ? `<span class="mini-badge bad">denied</span>` : ""}
    </span>
    <span class="span-track"><span class="span-bar" style="left:${left}%;width:${width}%;background:${spanColor(span)}"></span></span>
    <span class="span-duration">${span.duration} ms</span>
  </button>`;
}

function metaCell(label, value) {
  return `<div class="meta-cell"><div class="meta-k">${label}</div><div class="meta-v">${value}</div></div>`;
}

function policyCallout(span) {
  if (!span.decision) return "";
  const allowed = span.decision.effect === "allow";
  return `<div class="policy-callout ${allowed ? "ok" : ""}">
    <div class="callout-head">${icon(allowed ? "checkCircle" : "shield")} ${allowed ? "Allowed by policy" : "Denied by policy"} <span class="mini-badge ${allowed ? "ok" : "bad"}">${span.decision.policy}</span></div>
    <p>${escapeHtml(span.decision.reason)}</p>
    <div class="callout-meta"><span>Rule <code>${span.decision.rule}</code></span><span>Effect <code>${span.decision.effect}</code></span></div>
    <a href="#/policy">Open policy ${icon("arrowRight")}</a>
  </div>`;
}

function targetMeta(span) {
  if (span.type === "model") return ["Model", span.model || "—"];
  if (span.type === "tool") return ["Tool", span.model || "—"];
  if (span.type === "agent") return ["Agent", span.model || "—"];
  return ["Target", span.model || span.provider];
}

function renderInspector(span) {
  const tabs = [["overview", "Overview"], ["attributes", "Attributes"], ["decisions", "Decisions"]];
  const [targetKey, targetValue] = targetMeta(span);
  let body = "";
  if (state.inspectorTab === "overview") {
    body = `<div class="meta-grid">
      ${metaCell("Status", span.status)}
      ${metaCell("Duration", `${span.duration} ms`)}
      ${metaCell("Started", `+${span.start} ms`)}
      ${metaCell("Type", span.type)}
      ${metaCell("Provider", span.provider)}
      ${metaCell(targetKey, targetValue)}
    </div>
    ${span.tin || span.tout ? `<div class="inspector-section">
      <div class="inspector-section-title">Tokens & cost</div>
      <div class="token-strip three">
        <div class="token-box"><div class="token-box-label">Input</div><div class="token-box-value">${span.tin.toLocaleString()}</div></div>
        <div class="token-box"><div class="token-box-label">Output</div><div class="token-box-value">${span.tout.toLocaleString()}</div></div>
        <div class="token-box"><div class="token-box-label">Cost</div><div class="token-box-value">${span.cost}</div></div>
      </div>
    </div>` : ""}
    ${policyCallout(span)}`;
  } else if (state.inspectorTab === "attributes") {
    body = `<div class="json-block">${escapeHtml(JSON.stringify(span.attributes, null, 2))}</div>`;
  } else {
    body = span.decision
      ? `<div class="decision-mini">
          <div class="decision-mini-row"><span class="decision-badge ${span.decision.effect}">${span.decision.effect}</span><span>${span.decision.rule}</span><span class="time">${span.decision.policy}</span></div>
          <div class="decision-mini-row"><span class="muted">Reason</span><span>${escapeHtml(span.decision.reason)}</span></div>
          <div class="decision-mini-row"><span class="muted">Span</span><span class="run-id">${span.id}</span><span class="time">+${span.start} ms</span></div>
        </div>`
      : `<p class="muted" style="font-size:11px">No policy decision was recorded for this span.</p>`;
  }
  return `<div class="inspector-head">
      ${icon(SPAN_ICONS[span.type], `span-type-icon ${span.type}`)}
      <div><div class="inspector-title">${span.name}</div><div class="inspector-sub">${span.type} span · ${span.status}</div></div>
    </div>
    <div class="inspector-tabs" role="tablist" aria-label="Span detail">
      ${tabs.map(([key, label]) => `<button class="inspector-tab ${state.inspectorTab === key ? "active" : ""}" data-itab="${key}" role="tab" aria-selected="${state.inspectorTab === key}">${label}</button>`).join("")}
    </div>
    ${body}`;
}

function renderTrace(runId) {
  const run = RUNS.find((item) => item.id === runId) || RUNS[0];
  const selected = SPANS.find((span) => span.id === state.selectedSpan) || SPANS[5];
  const decisions = TRACE_DECISIONS.map((decision) => `<tr>
    <td class="run-id">${decision.time}</td>
    <td class="run-id">${decision.tool}</td>
    <td><span class="decision-badge ${decision.decision}">${decision.decision}</span></td>
    <td>${decision.reason}</td>
    <td><code>${decision.rule}</code></td>
    <td>${decision.policy}</td>
  </tr>`).join("");
  return `<div class="page trace-page">
    <div class="trace-shell">
      <div class="trace-top">
        <a class="trace-back" href="#/runs">${icon("arrowLeft")} Back to runs</a>
        <div class="trace-title-row">
          <div>
            <div class="trace-eyebrow">${chip(run.status)}<span class="trace-focus-pill">${icon("eye")} Focus mode</span></div>
            <h1>${run.id}</h1>
            <div class="trace-sub">${run.agent} · ${run.model} · started ${run.started} · ${run.duration}</div>
          </div>
          <div class="trace-actions">
            <button class="btn dark" data-copy>${icon("copy")} Copy link</button>
            <a class="btn dark" href="#/runs">${icon("play")} All runs</a>
            <button class="icon-btn" aria-label="More run actions">${icon("more")}</button>
          </div>
        </div>
        <div class="trace-stats">
          ${traceStat("Duration", run.duration)}
          ${traceStat("Spans", SPANS.length)}
          ${traceStat("Tokens", "2,260")}
          ${traceStat("Est. cost", run.cost)}
          ${traceStat("Policy", "v14")}
          ${traceStat("Decisions", String(TRACE_DECISIONS.length))}
        </div>
      </div>
      <div class="trace-grid">
        <div class="waterfall">
          <div class="wf-head">
            <div><div class="wf-title">Trace timeline</div><div class="wf-sub">12 spans · 1 policy denial · 2 model calls</div></div>
            <div class="wf-tools">
              <button class="wf-tool" aria-label="Zoom in">${icon("search")}</button>
              <button class="wf-tool" aria-label="Expand all">${icon("chevronDown")}</button>
              <button class="wf-tool" aria-label="More trace actions">${icon("more")}</button>
            </div>
          </div>
          <div class="wf-ruler"><span>Span</span><span class="ruler-track"><span>0 ms</span><span>355</span><span>710</span><span>1,065</span><span>1,420 ms</span></span><span></span></div>
          ${SPANS.map(spanRow).join("")}
          <div class="wf-foot"><span>Click a span to inspect it · ↑↓ moves through spans</span><span>12 spans</span></div>
        </div>
        <aside class="inspector" id="inspector" aria-label="Span inspector">${renderInspector(selected)}</aside>
      </div>
      <div class="decisions">
        <div class="decisions-head">
          <div><div class="decisions-title">Policy decisions</div><div class="decisions-sub">Gateway decisions correlated to this run, including blocked and gated calls.</div></div>
          <a class="btn dark sm" href="#/policy">${icon("shield")} Open policy</a>
        </div>
        <div class="table-wrap">
          <table>
            <thead><tr><th>Time</th><th>Target</th><th>Decision</th><th>Reason</th><th>Matched rule</th><th>Policy</th></tr></thead>
            <tbody>${decisions}</tbody>
          </table>
        </div>
      </div>
    </div>
  </div>`;
}

/* ---------- placeholders ---------- */

function renderPlaceholder(screen) {
  const meta = PLACEHOLDERS[screen] || PLACEHOLDERS.policy;
  return `<div class="page">
    <div class="page-header">
      <div>
        <div class="eyebrow">${meta.eyebrow}</div>
        <h1>${meta.title}</h1>
        <p class="page-sub">${meta.desc}</p>
      </div>
      <div class="page-actions"><span class="prototype-pill"><span></span>Next design pass</span></div>
    </div>
    <div class="card placeholder-card">
      <div class="placeholder-icon">${icon(meta.icon)}</div>
      <h2>${meta.title} is queued for the next pass</h2>
      <p>This prototype focuses on the three highest-value screens. The same system — grouped navigation, calm surfaces, and dense-but-readable data — extends here next.</p>
      <ul class="placeholder-list">${meta.items.map((item) => `<li>${icon("check")}${item}</li>`).join("")}</ul>
      <a class="btn primary" href="#/overview">${icon("arrowLeft")} Back to overview</a>
    </div>
  </div>`;
}

/* ---------- routing ---------- */

function currentRoute() {
  const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
  return { screen: parts[0] || "overview", id: parts[1] || null };
}

function render() {
  const { screen, id } = currentRoute();
  const view = document.getElementById("view");
  let html;
  if (screen === "overview") html = renderOverview();
  else if (screen === "runs") html = id ? renderTrace(id) : renderRuns();
  else html = renderPlaceholder(screen);
  view.innerHTML = html;
  updateChrome(screen, id);
  window.scrollTo({ top: 0 });
}

/* ---------- command palette ---------- */

function paletteGroups() {
  const query = state.paletteQuery.trim().toLowerCase();
  const views = NAV.flatMap((group) => group.items.map((item) => ({ label: item.label, hint: group.group, icon: item.icon, href: `#/${item.id}` })));
  const recent = RUNS.slice(0, 4).map((run) => ({ label: `Run ${run.id}`, hint: `${run.agent} · ${run.status}`, icon: "play", href: `#/runs/${run.id}` }));
  const actions = [
    { label: "Toggle theme", hint: "Appearance", icon: state.theme === "dark" ? "sun" : "moon", action: "theme" },
    { label: "Open connection settings", hint: "Settings", icon: "settings", action: "drawer" },
    { label: "Refresh data", hint: "Data", icon: "refresh", action: "refresh" }
  ];
  return [
    { label: "Navigate", items: views },
    { label: "Recent runs", items: recent },
    { label: "Actions", items: actions }
  ].map((group) => ({ ...group, items: group.items.filter((item) => `${item.label} ${item.hint || ""}`.toLowerCase().includes(query)) })).filter((group) => group.items.length);
}

function flatPaletteItems() {
  return paletteGroups().flatMap((group) => group.items);
}

function renderPalette() {
  const groups = paletteGroups();
  const flat = flatPaletteItems();
  state.paletteIndex = Math.max(0, Math.min(state.paletteIndex, flat.length - 1));
  let index = 0;
  const html = groups.length === 0
    ? `<div class="palette-empty">No matches for “${escapeHtml(state.paletteQuery)}”.</div>`
    : groups.map((group) => `<div class="palette-group">
        <div class="palette-group-label">${group.label}</div>
        ${group.items.map((item) => {
          const current = index++;
          return `<button class="palette-item ${current === state.paletteIndex ? "active" : ""}" data-command-index="${current}">
            <span class="palette-icon">${icon(item.icon)}</span>
            <span>${item.label}</span>
            <span class="palette-hint">${item.hint || ""}</span>
          </button>`;
        }).join("")}
      </div>`).join("");
  document.getElementById("paletteList").innerHTML = html;
}

function openPalette() {
  state.paletteOpen = true;
  state.paletteQuery = "";
  state.paletteIndex = 0;
  document.getElementById("paletteInput").value = "";
  document.getElementById("paletteScrim").hidden = false;
  renderPalette();
  setTimeout(() => document.getElementById("paletteInput").focus(), 0);
}

function closePalette() {
  state.paletteOpen = false;
  document.getElementById("paletteScrim").hidden = true;
}

function executeCommand(item) {
  if (!item) return;
  closePalette();
  if (item.href) { location.hash = item.href; return; }
  if (item.action === "theme") toggleTheme();
  else if (item.action === "drawer") openDrawer();
  else if (item.action === "refresh") { showToast("Data refreshed"); render(); }
}

/* ---------- drawer + toast ---------- */

function openDrawer() {
  document.getElementById("drawerScrim").hidden = false;
  setTimeout(() => document.getElementById("apiUrl").focus(), 40);
}

function closeDrawer() {
  document.getElementById("drawerScrim").hidden = true;
}

let toastTimer;
function showToast(message) {
  const toast = document.getElementById("toast");
  toast.innerHTML = `${icon("checkCircle")}<span>${escapeHtml(message)}</span>`;
  toast.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove("show"), 2400);
}

/* ---------- events ---------- */

function onViewClick(event) {
  const runRow = event.target.closest("[data-run-id]");
  if (runRow) { location.hash = `#/runs/${runRow.dataset.runId}`; return; }

  const statusButton = event.target.closest("[data-status]");
  if (statusButton) { state.status = statusButton.dataset.status; updateRunsTable(); return; }

  const metricButton = event.target.closest("[data-metric]");
  if (metricButton) {
    state.chartMetric = metricButton.dataset.metric;
    document.querySelectorAll("[data-metric]").forEach((button) => button.classList.toggle("active", button.dataset.metric === state.chartMetric));
    const chart = document.getElementById("chartArea");
    if (chart) chart.innerHTML = activityChart();
    const metric = METRICS[state.chartMetric];
    const highlight = document.getElementById("chartHighlight");
    if (highlight) highlight.innerHTML = `<span class="dot" style="background:${metric.color}"></span>${metric.format(metric.values[metric.values.length - 1])} ${metric.unit} in the last hour`;
    return;
  }

  const spanButton = event.target.closest("[data-span]");
  if (spanButton) {
    state.selectedSpan = spanButton.dataset.span;
    document.querySelectorAll("[data-span]").forEach((button) => button.classList.toggle("selected", button.dataset.span === state.selectedSpan));
    const span = SPANS.find((item) => item.id === state.selectedSpan);
    const inspector = document.getElementById("inspector");
    if (span && inspector) inspector.innerHTML = renderInspector(span);
    return;
  }

  const tabButton = event.target.closest("[data-itab]");
  if (tabButton) {
    state.inspectorTab = tabButton.dataset.itab;
    const span = SPANS.find((item) => item.id === state.selectedSpan);
    const inspector = document.getElementById("inspector");
    if (span && inspector) inspector.innerHTML = renderInspector(span);
    return;
  }

  const clearButton = event.target.closest("[data-clear]");
  if (clearButton) {
    const target = clearButton.dataset.clear;
    if (target === "agent" || target === "all") state.agent = "all";
    if (target === "status" || target === "all") state.status = "all";
    if (target === "query" || target === "all") {
      state.query = "";
      const input = document.getElementById("runSearch");
      if (input) input.value = "";
    }
    updateRunsTable();
    return;
  }

  if (event.target.closest("[data-attention-failed]")) {
    state.status = "failed";
    return;
  }

  if (event.target.closest("[data-copy]")) {
    const link = location.href;
    if (navigator.clipboard) navigator.clipboard.writeText(link).catch(() => {});
    showToast("Link copied to clipboard");
    return;
  }

  if (event.target.closest('[data-action="refresh"]')) {
    showToast("Data refreshed just now");
    return;
  }
}

function onViewInput(event) {
  if (event.target.id === "runSearch") {
    state.query = event.target.value;
    updateRunsTable();
  }
}

function onViewChange(event) {
  if (event.target.id === "agentFilter") {
    state.agent = event.target.value;
    updateRunsTable();
  } else if (event.target.id === "timeFilter") {
    state.time = event.target.value;
    updateRunsTable();
  }
}

function onViewKeydown(event) {
  if (event.key === "ArrowUp" || event.key === "ArrowDown") {
    const currentSpan = event.target.closest("[data-span]");
    if (!currentSpan) return;
    event.preventDefault();
    const spans = [...document.querySelectorAll(".span-row")];
    const next = spans[spans.indexOf(currentSpan) + (event.key === "ArrowDown" ? 1 : -1)];
    if (next) { next.focus(); next.click(); }
    return;
  }
  if (event.key !== "Enter" && event.key !== " ") return;
  const row = event.target.closest("[data-run-id]");
  if (row && event.target === row) {
    event.preventDefault();
    location.hash = `#/runs/${row.dataset.runId}`;
  }
}

function bindEvents() {
  document.getElementById("nav").innerHTML = navHtml();

  document.getElementById("view").addEventListener("click", onViewClick);
  document.getElementById("view").addEventListener("input", onViewInput);
  document.getElementById("view").addEventListener("change", onViewChange);
  document.getElementById("view").addEventListener("keydown", onViewKeydown);

  window.addEventListener("hashchange", render);

  let chartResizeTimer;
  window.addEventListener("resize", () => {
    clearTimeout(chartResizeTimer);
    chartResizeTimer = setTimeout(() => {
      const chart = document.getElementById("chartArea");
      if (chart) chart.innerHTML = activityChart();
    }, 150);
  });

  document.getElementById("themeToggle").addEventListener("click", toggleTheme);
  document.getElementById("menuBtn").addEventListener("click", () => document.body.classList.toggle("nav-open"));
  document.getElementById("navScrim").addEventListener("click", () => document.body.classList.remove("nav-open"));
  document.querySelectorAll(".nav-item").forEach((link) => link.addEventListener("click", () => document.body.classList.remove("nav-open")));

  document.getElementById("searchTrigger").addEventListener("click", openPalette);
  document.getElementById("paletteScrim").addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closePalette();
  });
  document.getElementById("paletteInput").addEventListener("input", (event) => {
    state.paletteQuery = event.target.value;
    state.paletteIndex = 0;
    renderPalette();
  });
  document.getElementById("paletteList").addEventListener("click", (event) => {
    const item = event.target.closest("[data-command-index]");
    if (item) executeCommand(flatPaletteItems()[Number(item.dataset.commandIndex)]);
  });

  document.getElementById("connectionBtn").addEventListener("click", openDrawer);
  document.getElementById("userBtn").addEventListener("click", openDrawer);
  document.getElementById("drawerScrim").addEventListener("click", (event) => {
    if (event.target === event.currentTarget) closeDrawer();
  });
  document.querySelectorAll("[data-close-drawer]").forEach((button) => button.addEventListener("click", closeDrawer));
  document.getElementById("connectionForm").addEventListener("submit", (event) => {
    event.preventDefault();
    showToast("Connection saved locally");
    closeDrawer();
  });
  document.getElementById("testConnection").addEventListener("click", () => {
    const result = document.getElementById("connectionResult");
    result.textContent = "Connected · 42 ms";
    result.classList.add("show");
  });

  document.getElementById("bellBtn").addEventListener("click", () => showToast("No new alerts"));
  document.getElementById("workspaceBtn").addEventListener("click", () => showToast("Workspace switcher is next"));

  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      if (state.paletteOpen) closePalette(); else openPalette();
      return;
    }
    if (event.key === "Escape") {
      if (state.paletteOpen) { event.preventDefault(); closePalette(); }
      else if (!document.getElementById("drawerScrim").hidden) { event.preventDefault(); closeDrawer(); }
      else if (document.body.classList.contains("nav-open")) { document.body.classList.remove("nav-open"); }
      return;
    }
    if (!state.paletteOpen) return;
    const flat = flatPaletteItems();
    if (event.key === "ArrowDown") {
      event.preventDefault();
      state.paletteIndex = Math.min(state.paletteIndex + 1, flat.length - 1);
      renderPalette();
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      state.paletteIndex = Math.max(state.paletteIndex - 1, 0);
      renderPalette();
    } else if (event.key === "Enter") {
      event.preventDefault();
      executeCommand(flat[state.paletteIndex]);
    }
  });
}

/* ---------- init ---------- */

applyTheme();
bindEvents();
if (!location.hash) history.replaceState(null, "", "#/overview");
render();
