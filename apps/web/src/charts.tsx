import type { ReactNode } from "react";
import { Card } from "./components";

// A tiny dependency-free chart kit. Everything here is decorative
// (aria-hidden): the numbers each chart shows always appear as text in the
// surrounding view, so screen readers lose nothing. Colors reference the
// theme tokens from index.css, so light and dark follow automatically.

// ---------- helpers (unit-tested in tests/charts.test.ts) ----------

// Scale values into points inside a width x height box, with padding.
export function scalePoints(
  values: number[],
  width: number,
  height: number,
  pad = 3
): { x: number; y: number }[] {
  if (values.length === 0) return [];
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  const inner = Math.max(1, height - pad * 2);
  return values.map((v, i) => ({
    x: values.length === 1 ? width / 2 : (i / (values.length - 1)) * width,
    // A flat series has no top or bottom; draw it through the middle.
    y: max === min ? height / 2 : pad + (1 - (v - min) / span) * inner
  }));
}

// Histogram bucket counts over the value range (max falls in the last bin).
export function binValues(values: number[], bins = 12): number[] {
  const counts = new Array<number>(bins).fill(0);
  if (values.length === 0 || bins <= 0) return counts;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const span = max - min || 1;
  for (const v of values) {
    const idx = Math.min(bins - 1, Math.max(0, Math.floor(((v - min) / span) * bins)));
    counts[idx]++;
  }
  return counts;
}

// ---------- colors ----------

export const STATUS_COLORS: Record<string, string> = {
  success: "var(--color-ok-700)",
  failed: "var(--color-bad-700)",
  running: "var(--color-warn-700)",
  cancelled: "var(--color-mute-700)",
  denied: "var(--color-info-700)"
};

export function statusColor(name: string): string {
  return STATUS_COLORS[name] ?? "var(--color-ink-400)";
}

// ---------- layout ----------

export function ChartCard({ title, sub, children, className = "" }: {
  title: string;
  sub?: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Card className={`p-4 ${className}`}>
      <div className="mb-3">
        <h3 className="text-sm font-semibold text-ink-900">{title}</h3>
        {sub && <p className="mt-0.5 text-xs text-ink-500">{sub}</p>}
      </div>
      {children}
    </Card>
  );
}

// ---------- sparkline ----------

export function Sparkline({ values, width = 160, height = 40, className = "", color = "var(--color-brand-500)" }: {
  values: number[];
  width?: number;
  height?: number;
  className?: string;
  color?: string;
}) {
  if (values.length === 0) return null;
  const pts = scalePoints(values, width, height);
  const line = pts.map((p) => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
  const area = `0,${height} ${line} ${width},${height}`;
  const last = pts[pts.length - 1];
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className={className} aria-hidden="true" preserveAspectRatio="none">
      <polygon points={area} fill={color} opacity="0.12" />
      <polyline points={line} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={last.x} cy={last.y} r="2.5" fill={color} />
    </svg>
  );
}

// ---------- donut ----------

export interface Slice {
  label: string;
  value: number;
  color: string;
}

export function Donut({ slices, size = 148, thickness = 14, children }: {
  slices: Slice[];
  size?: number;
  thickness?: number;
  children?: ReactNode;
}) {
  const total = slices.reduce((a, s) => a + s.value, 0);
  const r = (size - thickness) / 2;
  const c = 2 * Math.PI * r;
  let offset = 0;
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden="true" className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="var(--color-ink-100)" strokeWidth={thickness} />
        {total > 0 &&
          slices.filter((s) => s.value > 0).map((s) => {
            const len = (s.value / total) * c;
            const arc = (
              <circle
                key={s.label}
                cx={size / 2}
                cy={size / 2}
                r={r}
                fill="none"
                stroke={s.color}
                strokeWidth={thickness}
                strokeDasharray={`${len} ${c - len}`}
                strokeDashoffset={-offset}
              />
            );
            offset += len;
            return arc;
          })}
      </svg>
      {children && (
        <div className="absolute inset-0 flex flex-col items-center justify-center">{children}</div>
      )}
    </div>
  );
}

export function Legend({ slices }: { slices: Slice[] }) {
  const sum = slices.reduce((a, s) => a + s.value, 0);
  return (
    <ul className="space-y-1.5 text-xs">
      {slices.map((s) => (
        <li key={s.label} className="flex items-center gap-2">
          <span className="h-2.5 w-2.5 shrink-0 rounded-sm" style={{ background: s.color }} aria-hidden="true" />
          <span className="min-w-0 flex-1 truncate text-ink-600">{s.label}</span>
          <span className="tg-nums text-ink-800">{s.value}</span>
          <span className="tg-nums w-10 text-right text-ink-500">
            {sum > 0 ? `${Math.round((s.value / sum) * 100)}%` : "0%"}
          </span>
        </li>
      ))}
    </ul>
  );
}

// ---------- horizontal meter ----------

export function Meter({ label, value, max, color, valueText, hint }: {
  label: string;
  value: number;
  max: number;
  color?: string;
  valueText?: string;
  hint?: string;
}) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div className="text-xs">
      <div className="mb-1 flex items-center justify-between gap-2">
        <span className="min-w-0 truncate text-ink-600">{label}</span>
        <span className="tg-nums shrink-0 text-ink-800">{valueText ?? String(value)}</span>
      </div>
      <div className="tg-track h-2 w-full">
        <div
          className="tg-bar h-2 transition-[width] duration-500"
          style={{ width: `${pct}%`, background: color ?? "var(--color-brand-500)" }}
        />
      </div>
      {hint && <div className="mt-0.5 text-[11px] text-ink-500">{hint}</div>}
    </div>
  );
}

// ---------- histogram ----------

export function Histogram({ values, bins = 12, height = 64, className = "", color = "var(--color-brand-500)" }: {
  values: number[];
  bins?: number;
  height?: number;
  className?: string;
  color?: string;
}) {
  if (values.length === 0) return null;
  const counts = binValues(values, bins);
  const max = Math.max(...counts, 1);
  const width = bins * 14;
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className={className} aria-hidden="true" preserveAspectRatio="none">
      {counts.map((c, i) => {
        const h = Math.max(2, (c / max) * (height - 6));
        return (
          <rect key={i} x={i * 14 + 2} width={10} y={height - h} height={h} rx="2"
            fill={color} opacity={c === 0 ? 0.18 : 0.75} />
        );
      })}
    </svg>
  );
}
