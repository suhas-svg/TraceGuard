import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { resolveSecretRef, SecretRefError, secretRefIssue } from "../src/secret-ref.js";

describe("upstream secret references", () => {
  const dir = mkdtempSync(join(tmpdir(), "traceguard-secret-ref-"));

  afterAll(() => {
    delete process.env.TRACEGUARD_SECRET_REF_TEST;
    rmSync(dir, { recursive: true, force: true });
  });

  it("accepts only environment and file references", () => {
    expect(secretRefIssue(null)).toBeNull();
    expect(secretRefIssue("")).toBeNull();
    expect(secretRefIssue("env:UPSTREAM_TOKEN")).toBeNull();
    expect(secretRefIssue(`file:${join(dir, "token")}`)).toBeNull();
    expect(secretRefIssue("bare-secret")).toMatch(/env:NAME or file:/);
    expect(secretRefIssue("vault:upstream")).toMatch(/env:NAME or file:/);
    expect(secretRefIssue("env:")).not.toBeNull();
    expect(secretRefIssue("env:1BAD")).not.toBeNull();
    expect(secretRefIssue("x".repeat(513))).toMatch(/too long/);
  });

  it("resolves an environment reference at call time", () => {
    process.env.TRACEGUARD_SECRET_REF_TEST = "from-env";
    expect(resolveSecretRef("env:TRACEGUARD_SECRET_REF_TEST")).toBe("from-env");
    delete process.env.TRACEGUARD_SECRET_REF_TEST;
    expect(() => resolveSecretRef("env:TRACEGUARD_SECRET_REF_TEST")).toThrow(SecretRefError);
  });

  it("reads a file reference and strips one trailing newline", () => {
    const path = join(dir, "token");
    writeFileSync(path, "from-file\n", "utf8");
    expect(resolveSecretRef(`file:${path}`)).toBe("from-file");
  });

  it("fails closed for missing, empty, or malformed references", () => {
    expect(() => resolveSecretRef(`file:${join(dir, "missing")}`)).toThrow(SecretRefError);
    const empty = join(dir, "empty");
    writeFileSync(empty, "  \n", "utf8");
    expect(() => resolveSecretRef(`file:${empty}`)).toThrow(SecretRefError);
    expect(() => resolveSecretRef("plain-value")).toThrow(SecretRefError);
  });
});
