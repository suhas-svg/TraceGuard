import type { ReactNode } from "react";

// One shared kit so every view speaks the same visual language. Brand color
// carries only for primary actions and the active nav item; status always
// uses the semantic palette so color keeps a single meaning.

// ---------- Buttons ----------

type ButtonProps = {
  variant?: "primary" | "secondary" | "danger" | "ghost";
  size?: "sm" | "md";
} & React.ButtonHTMLAttributes<HTMLButtonElement>;

export function Button({ variant = "secondary", size = "md", className = "", ...rest }: ButtonProps) {
  const variants: Record<string, string> = {
    primary: "bg-brand-600 text-white shadow-sm hover:bg-brand-700 disabled:bg-ink-300",
    secondary:
      "border border-ink-200 bg-surface text-ink-700 shadow-sm hover:border-ink-300 hover:bg-ink-50 disabled:text-ink-300",
    danger: "bg-bad-700 text-white shadow-sm hover:brightness-110",
    ghost: "text-ink-500 hover:bg-ink-100 hover:text-ink-800"
  };
  const sizes = { sm: "px-2.5 py-1 text-xs", md: "px-3 py-1.5 text-sm" };
  return (
    <button
      className={`inline-flex items-center gap-1.5 rounded-lg font-medium transition-colors disabled:cursor-not-allowed ${variants[variant]} ${sizes[size]} ${className}`}
      {...rest}
    />
  );
}

// ---------- Badges ----------

const badgeTones: Record<string, string> = {
  ok: "bg-ok-100 text-ok-800",
  warn: "bg-warn-100 text-warn-700",
  bad: "bg-bad-100 text-bad-700",
  info: "bg-info-100 text-info-700",
  mute: "bg-mute-100 text-mute-700"
};

export function Badge({ tone = "mute", children }: { tone?: keyof typeof badgeTones; children: ReactNode }) {
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${badgeTones[tone]}`}>
      {children}
    </span>
  );
}

export function StatusBadge({ status }: { status: string }) {
  const tone: Record<string, keyof typeof badgeTones> = {
    success: "ok",
    approved: "ok",
    pass: "ok",
    delivered: "ok",
    consumed: "mute",
    rejected: "bad",
    executing: "warn",
    claimed: "warn",
    response_received: "ok",
    outcome_unknown: "bad",
    policy_invalidated: "bad",
    tool_quarantined: "bad",
    running: "warn",
    pending: "warn",
    failed: "bad",
    denied: "bad",
    expired: "bad",
    cancelled: "mute"
  };
  return <Badge tone={tone[status] ?? "mute"}>{status}</Badge>;
}

// ---------- Forms ----------

const inputCls =
  "rounded-lg border border-ink-200 bg-surface px-2.5 py-1.5 text-sm text-ink-800 placeholder:text-ink-400 focus:border-brand-400 focus:outline-none focus:ring-2 focus:ring-brand-500/15";

export function Input(props: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`${inputCls} ${props.className ?? ""}`} />;
}

export function Select(props: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={`${inputCls} ${props.className ?? ""}`} />;
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-xs font-medium text-ink-500">{label}</span>
      {children}
    </label>
  );
}

// ---------- Layout ----------

export function Page({ title, sub, eyebrow, actions, children }: {
  title: ReactNode;
  sub?: string;
  eyebrow?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="mx-auto max-w-[1480px] px-6 py-7 lg:px-8 lg:py-9">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          {eyebrow && (
            <div className="mb-1.5 text-[10.5px] font-semibold uppercase tracking-[0.09em] text-ink-400">
              {eyebrow}
            </div>
          )}
          <h1 className="text-[30px] font-semibold leading-[1.12] tracking-[-0.035em] text-ink-900">{title}</h1>
          {sub && <p className="mt-1.5 max-w-2xl text-[13.5px] leading-5 text-ink-500">{sub}</p>}
        </div>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>
      {children}
    </div>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-ink-200 bg-surface shadow-[0_1px_2px_rgba(20,22,18,0.04)] ${className}`}>
      {children}
    </div>
  );
}

export function Alert({ children }: { children: ReactNode }) {
  return (
    <div role="alert" className="mb-3 rounded-md border border-bad-700/20 bg-bad-100/60 px-3 py-2 text-sm text-bad-700">
      {children}
    </div>
  );
}

export function Empty({ hint, action }: { hint: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center gap-2 rounded-xl border border-dashed border-ink-200 bg-surface px-6 py-10 text-center">
      <p className="text-sm text-ink-500">{hint}</p>
      {action}
    </div>
  );
}

export function Skeleton({ className = "" }: { className?: string }) {
  return <div aria-hidden="true" className={`animate-pulse rounded-md bg-ink-100 ${className}`} />;
}

export function TableSkeleton({ rows = 6, label = "Loading..." }: { rows?: number; label?: string }) {
  return (
    <Card className="p-3">
      <div className="space-y-2" role="status" aria-label={label}>
        {Array.from({ length: rows }).map((_, i) => (
          <Skeleton key={i} className="h-8" />
        ))}
      </div>
    </Card>
  );
}

// Card-shaped rows for the list views (approvals, policies).
export function ListSkeleton({ rows = 3, label = "Loading..." }: { rows?: number; label?: string }) {
  return (
    <Card className="p-3">
      <div className="space-y-2" role="status" aria-label={label}>
        {Array.from({ length: rows }).map((_, i) => (
          <Skeleton key={i} className="h-16" />
        ))}
      </div>
    </Card>
  );
}

const statTones: Record<string, string> = {
  default: "text-ink-900",
  ok: "text-ok-700",
  bad: "text-bad-700",
  warn: "text-warn-700"
};

// Overview number. Pass onClick and it becomes a filter button with a pressed
// state, so a KPI can drive the list beneath it.
export function Stat({ label, value, hint, tone = "default", active = false, onClick, children }: {
  label: string;
  value: ReactNode;
  hint?: string;
  tone?: keyof typeof statTones;
  active?: boolean;
  onClick?: () => void;
  children?: ReactNode;
}) {
  const body = (
    <>
      <div className="text-[11.5px] font-medium text-ink-500">{label}</div>
      <div className={`tg-nums mt-1.5 text-[27px] font-semibold leading-[1.1] tracking-[-0.04em] ${statTones[tone]}`}>{value}</div>
      {hint && <div className="mt-1 text-[11px] text-ink-500">{hint}</div>}
      {children && <div className="mt-auto pt-2">{children}</div>}
    </>
  );
  const base = "flex h-full flex-col rounded-xl border bg-surface px-4 py-4 text-left shadow-[0_1px_2px_rgba(20,22,18,0.04)]";
  if (!onClick) return <div className={`${base} border-ink-200`}>{body}</div>;
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`${base} transition-colors ${active ? "border-brand-400 bg-brand-50/50" : "border-ink-200 hover:border-ink-300 hover:bg-ink-50/60"}`}
    >
      {body}
    </button>
  );
}

// ---------- Tables ----------

export function Segmented<T extends string>({ options, value, onChange, label }: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  label: string;
}) {
  return (
    <div role="group" aria-label={label}
      className="inline-flex rounded-lg border border-ink-200 bg-surface-3 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          aria-pressed={value === o.value}
          className={`rounded-md px-3 py-1.5 text-xs font-medium transition-colors ${
            value === o.value ? "bg-surface text-ink-900 shadow-sm ring-1 ring-ink-200/70" : "text-ink-500 hover:text-ink-900"
          }`}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}
export function Table({ children }: { children: ReactNode }) {
  return (
    <Card className="overflow-hidden">
      {/* Own scroll region so the header row stays put while a long table scrolls. */}
      <div className="max-h-[72vh] overflow-auto overscroll-contain">
        <table className="tg-nums w-full border-collapse text-sm">{children}</table>
      </div>
    </Card>
  );
}

export function Th({ children, className = "", onSort, sorted }: {
  children?: ReactNode;
  className?: string;
  onSort?: () => void;
  sorted?: "asc" | "desc";
}) {
  return (
    <th
      aria-sort={onSort ? (sorted === "asc" ? "ascending" : sorted === "desc" ? "descending" : "none") : undefined}
      className={`sticky top-0 z-10 border-b border-ink-200 bg-surface-2 px-3 py-2 text-left text-[10.5px] font-semibold uppercase tracking-[0.07em] text-ink-500 ${className}`}
    >
      {onSort ? (
        <button
          onClick={onSort}
          className="inline-flex items-center gap-1 uppercase tracking-wide transition-colors hover:text-ink-800"
        >
          {children}
          <span aria-hidden="true" className="text-[10px] font-normal">
            {sorted === "asc" ? "▲" : sorted === "desc" ? "▼" : "↕"}
          </span>
        </button>
      ) : (
        children
      )}
    </th>
  );
}

export function Td({ children, className = "", title }: { children?: ReactNode; className?: string; title?: string }) {
  return <td title={title} className={`border-b border-ink-100 px-3 py-2.5 align-middle last:border-0 ${className}`}>{children}</td>;
}

export function LinkButton({ children, onClick }: { children: ReactNode; onClick: () => void }) {
  return (
    <button onClick={onClick} className="font-mono text-[13px] text-brand-600 hover:text-brand-700 hover:underline">
      {children}
    </button>
  );
}

// ---------- Nav icons (inline SVG, no dependency) ----------

const paths: Record<string, string> = {
  overview: "M4 13h6V4H4v9zm10 7h6v-9h-6v9zM4 20h6v-4H4v4zm10-11h6V4h-6v5z",
  runs: "M5 4.5l13 7.5-13 7.5v-15z",
  evals: "M4 20V10M10 20V4M16 20v-8M22 20H2",
  policy: "M12 3l7 3v5c0 5-3.5 8-7 10-3.5-2-7-5-7-10V6l7-3z",
  approvals: "M5 13l4 4L19 7",
  webhooks: "M10 14a5 5 0 007 0l3-3a5 5 0 00-7-7l-1.5 1.5M14 10a5 5 0 00-7 0l-3 3a5 5 0 007 7l1.5-1.5",
  retention: "M4 7h16M9 7V5h6v2m-8 0l1 13h8l1-13",
  costs: "M12 3v18M7 7h7a3 3 0 010 6H9a3 3 0 000 6h8",
  users: "M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2M9 11a4 4 0 100-8 4 4 0 000 8M22 21v-2a4 4 0 00-3-3.9M16 3.1a4 4 0 010 7.8",
  connect: "M9 17a4 4 0 010-8 6 6 0 0111.6 1.6A4 4 0 0118 17H9z",
  search: "M21 21l-4.3-4.3M11 18a7 7 0 100-14 7 7 0 000 14z",
  menu: "M4 6h16M4 12h16M4 18h16",
  close: "M18 6L6 18M6 6l12 12",
  chevronRight: "M9 18l6-6-6-6",
  chevronDown: "M6 9l6 6 6-6",
  clock: "M12 21a9 9 0 100-18 9 9 0 000 18zM12 7v5l3 2",
  alert: "M12 3l9.5 17H2.5L12 3zM12 9v4M12 17h.01",
  check: "M20 6L9 17l-5-5",
  bell: "M18 8a6 6 0 00-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M13.7 21a2 2 0 01-3.4 0",
  refresh: "M20 11a8 8 0 10-2.3 5.7M20 4v7h-7",
  download: "M12 3v12M7 10l5 5 5-5M5 21h14",
  filter: "M3 5h18M6 12h12M10 19h4",
  arrowRight: "M5 12h14M12 5l7 7-7 7",
  arrowLeft: "M19 12H5M12 19l-7-7 7-7",
  tool: "M14.7 6.3a4 4 0 00-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 005.4-5.4l-2.5 2.5-3-3 2.5-2.5z",
  calendar: "M3 5h18v16H3zM16 3v4M8 3v4M3 11h18",
  more: "M5 12h.01M12 12h.01M19 12h.01",
  eye: "M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12zM12 15a3 3 0 100-6 3 3 0 000 6z",
  copy: "M9 9h11v11H9zM5 15H4V4h11v1",
  model: "M12 3l8 4.5v9L12 21l-8-4.5v-9L12 3zM12 12l8-4.5M12 12v9M12 12L4 7.5"
};

export function NavIcon({ name, className = "h-4 w-4" }: { name: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d={paths[name] ?? paths.runs} />
    </svg>
  );
}
