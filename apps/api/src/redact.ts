// Privacy pipeline for everything the platform persists. Two layers:
//   1. Secret-pattern scrubbing: recognized credential shapes are ALWAYS
//      replaced before anything lands in the database, regardless of capture
//      settings. There is no configuration that turns this off.
//   2. Capture policy: raw prompt / response / tool-argument shaped keys are
//      only persisted when CAPTURE_RAW_ATTRIBUTES=true. Otherwise the value
//      is replaced with a marker. Secrets are redacted either way.
// Callers: ingest (/v1/ingest/events), OTLP mapping (/v1/traces), eval span
// writes, gateway denied spans, and approval argument summaries.

export const REDACTED = "[REDACTED]";
export const NOT_CAPTURED = "[NOT CAPTURED]";

// Ordered most-specific first; PEM blocks and prefixed keys are matched
// before the generic sk- pattern so partial matches cannot leak a fragment.
const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
  /\bsk-ant-[A-Za-z0-9_-]{16,}/g,
  /\bsk-[A-Za-z0-9_-]{16,}/g,
  /\bgh[pousr]_[A-Za-z0-9]{20,}/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}/g,
  // JWT: three base64url segments, first always starts eyJ.
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{16,}/g
];

export function redactSecrets(text: string): string {
  let out = text;
  for (const re of SECRET_PATTERNS) out = out.replace(re, REDACTED);
  return out;
}

// Keys that commonly carry raw model or tool content. Exact names plus
// dotted/suffixed conventions (gen_ai.prompt.0.content, *.messages, ...).
const CONTENT_KEYS = new Set([
  "prompt", "prompts", "response", "responses", "content", "messages",
  "completion", "completions", "arguments", "args", "tool_args",
  "input_text", "output_text", "raw_input", "raw_output"
]);
const CONTENT_SEGMENT = /(^|[._])(prompt|prompts|content|messages|completion|completions|arguments)$/;

export function isContentKey(key: string): boolean {
  const k = key.toLowerCase();
  if (CONTENT_KEYS.has(k)) return true;
  if (k.startsWith("gen_ai.prompt") || k.startsWith("gen_ai.completion")) return true;
  if (k.startsWith("gen_ai.input.") || k.startsWith("gen_ai.output.")) return true;
  return CONTENT_SEGMENT.test(k);
}

export interface CaptureOptions {
  captureRaw?: boolean;
}

// Reads the flag fresh on every call so tests and restarts see changes.
export function captureRawEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  return (env.CAPTURE_RAW_ATTRIBUTES ?? "").trim().toLowerCase() === "true";
}

// Recursive walk over attributes/args payloads. Strings are always scrubbed
// for secrets; content-keyed values are replaced wholesale unless raw
// capture is explicitly enabled (in which case only secrets are scrubbed).
export function redactDeep(value: unknown, opts: CaptureOptions = {}): unknown {
  if (typeof value === "string") return redactSecrets(value);
  if (value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, opts));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (!opts.captureRaw && isContentKey(k)) {
      out[k] = NOT_CAPTURED;
      continue;
    }
    out[k] = redactDeep(v, opts);
  }
  return out;
}

// Redacted residue kept when pending approval arguments are dropped after a
// terminal transition ("only a redacted summary and hash remain").
export function summarizeArgs(args: unknown, opts: CaptureOptions = {}, maxLength = 1000): string {
  let text: string;
  try {
    const redacted = redactDeep(args, opts);
    text = typeof redacted === "string" ? redacted : JSON.stringify(redacted);
  } catch {
    text = "[unserializable]";
  }
  if (typeof text !== "string") text = "[unserializable]";
  return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
}
