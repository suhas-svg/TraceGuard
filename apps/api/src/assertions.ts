// Deterministic checks only. No model judging in v1: every assertion is a
// pure function of the recorded output, tool sequence, and final status.
export interface AssertCtx {
  output: string;
  tools: string[];
  status: string;
}

export interface AssertOutcome {
  passed: boolean;
  message: string;
}

// Deterministic checks only. No model judging in v1: every assertion is a
// pure function of the recorded output, tool sequence, and final status.
export function runAssertion(a: Record<string, unknown>, ctx: AssertCtx): AssertOutcome {
  switch (a.type) {
    case "exact":
      return a.value === ctx.output
        ? { passed: true, message: "exact match" }
        : { passed: false, message: `expected exactly ${JSON.stringify(a.value)}` };
    case "contains":
      return typeof a.value === "string" && ctx.output.includes(a.value)
        ? { passed: true, message: `contains ${JSON.stringify(a.value)}` }
        : { passed: false, message: `missing ${JSON.stringify(a.value)}` };
    case "regex": {
      let re: RegExp;
      try {
        re = new RegExp(String(a.pattern));
      } catch {
        return { passed: false, message: "invalid regex in assertion" };
      }
      return re.test(ctx.output)
        ? { passed: true, message: `matches ${a.pattern}` }
        : { passed: false, message: `no match for ${a.pattern}` };
    }
    case "json_schema": {
      // Tiny subset: required fields plus per-field primitive types.
      let parsed: unknown;
      try {
        parsed = JSON.parse(ctx.output);
      } catch {
        return { passed: false, message: "output is not JSON" };
      }
      const schema = (a.schema ?? {}) as { required?: string[]; properties?: Record<string, string> };
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        return { passed: false, message: "output is not a JSON object" };
      }
      const obj = parsed as Record<string, unknown>;
      for (const k of schema.required ?? []) {
        if (obj[k] === undefined) return { passed: false, message: `missing field ${k}` };
      }
      for (const [k, t] of Object.entries(schema.properties ?? {})) {
        if (obj[k] !== undefined && typeof obj[k] !== t) {
          return { passed: false, message: `field ${k} is not ${t}` };
        }
      }
      return { passed: true, message: "schema satisfied" };
    }
    case "tools": {
      const want = (a.sequence ?? []) as string[];
      const same = want.length === ctx.tools.length && want.every((t, i) => t === ctx.tools[i]);
      return same
        ? { passed: true, message: `tool sequence [${want.join(", ")}]` }
        : { passed: false, message: `expected [${want.join(", ")}], got [${ctx.tools.join(", ")}]` };
    }
    case "status":
      return ctx.status === a.value
        ? { passed: true, message: `status ${a.value}` }
        : { passed: false, message: `expected status ${a.value}, got ${ctx.status}` };
    default:
      return { passed: false, message: `unknown assertion ${(a as { type: unknown }).type}` };
  }
}

