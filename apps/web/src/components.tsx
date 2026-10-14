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
  "rounded-lg border border-ink-200 bg-surface px-2.5 py-1.5 text-sm text-ink-800 placeholder:text-ink-300 focus:border-brand-400";

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

export function Page({ title, sub, actions, children }: {
  title: string;
  sub?: string;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <div className="mx-auto max-w-6xl p-6">
      <div className="mb-5 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h2 className="text-xl font-semibold tracking-tight text-ink-900">{title}</h2>
          {sub && <p className="mt-0.5 text-sm text-ink-500">{sub}</p>}
        </div>
        {actions && <div className="flex items-center gap-2">{actions}</div>}
      </div>
      {children}
    </div>
  );
}

export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-ink-200 bg-surface shadow-[0_1px_2px_rgba(20,24,36,0.05)] ${className}`}>
      {children}
    </div>
  );
}

export function Alert({ children }: { children: ReactNode }) {
  return (
    <div role="alert" className="mb-3 rounded-lg border border-bad-700/20 bg-bad-100/60 px-3 py-2 text-sm text-bad-700">
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

export function Spinner({ label = "Loading..." }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-6 text-sm text-ink-500" role="status">
      <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-ink-200 border-t-brand-500" />
      {label}
    </div>
  );
}

export function Stat({ label, value, hint }: { label: string; value: ReactNode; hint?: string }) {
  return (
    <Card className="px-4 py-3">
      <div className="text-xs font-medium uppercase tracking-wide text-ink-400">{label}</div>
      <div className="tg-nums mt-1 text-xl font-semibold text-ink-900">{value}</div>
      {hint && <div className="mt-0.5 text-xs text-ink-500">{hint}</div>}
    </Card>
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
      className="inline-flex rounded-lg border border-ink-200 bg-surface p-0.5 shadow-sm">
      {options.map((o) => (
        <button
          key={o.value}
          onClick={() => onChange(o.value)}
          aria-pressed={value === o.value}
          className={`rounded-md px-2.5 py-1 text-xs font-medium transition-colors ${
            value === o.value ? "bg-ink-800 text-ink-50 shadow-sm" : "text-ink-500 hover:text-ink-800"
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
      <div className="overflow-x-auto">
        <table className="tg-nums w-full border-collapse text-sm">{children}</table>
      </div>
    </Card>
  );
}

export function Th({ children, className = "" }: { children?: ReactNode; className?: string }) {
  return (
    <th className={`border-b border-ink-100 bg-ink-50/60 px-3 py-2 text-left text-xs font-medium uppercase tracking-wide text-ink-400 ${className}`}>
      {children}
    </th>
  );
}

export function Td({ children, className = "" }: { children?: ReactNode; className?: string }) {
  return <td className={`border-b border-ink-100 px-3 py-2 align-top last:border-0 ${className}`}>{children}</td>;
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
  runs: "M3 12l9-8 9 8M5 10v10h5v-6h4v6h5V10",
  evals: "M4 20V10M10 20V4M16 20v-8M22 20H2",
  policy: "M12 3l7 3v5c0 5-3.5 8-7 10-3.5-2-7-5-7-10V6l7-3z",
  approvals: "M5 13l4 4L19 7",
  webhooks: "M10 14a5 5 0 007 0l3-3a5 5 0 00-7-7l-1.5 1.5M14 10a5 5 0 00-7 0l-3 3a5 5 0 007 7l1.5-1.5",
  retention: "M4 7h16M9 7V5h6v2m-8 0l1 13h8l1-13",
  costs: "M12 3v18M7 7h7a3 3 0 010 6H9a3 3 0 000 6h8",
  users: "M16 21v-2a4 4 0 00-4-4H6a4 4 0 00-4 4v2M9 11a4 4 0 100-8 4 4 0 000 8M22 21v-2a4 4 0 00-3-3.9M16 3.1a4 4 0 010 7.8",
  connect: "M9 17a4 4 0 010-8 6 6 0 0111.6 1.6A4 4 0 0118 17H9z"
};

export function NavIcon({ name, className = "h-4 w-4" }: { name: string; className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.8}
      strokeLinecap="round" strokeLinejoin="round" className={className} aria-hidden="true">
      <path d={paths[name] ?? paths.runs} />
    </svg>
  );
}
