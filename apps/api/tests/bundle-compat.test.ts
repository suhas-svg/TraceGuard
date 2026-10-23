import { describe, expect, it } from "vitest";
import {
  BUNDLE_VERSION,
  LEGACY_BUNDLE_VERSION,
  policyBundleSchema,
  PROTOCOL_PROFILE
} from "@traceguard/schemas";

const workspaceId = "11111111-1111-4111-8111-111111111111";
const projectId = "22222222-2222-4222-8222-222222222222";
const serverId = "33333333-3333-4333-8333-333333333333";
const pinId = "44444444-4444-4444-8444-444444444444";
const definitionHash = "a".repeat(64);

function bundle(version: number, pin: Record<string, unknown>) {
  return {
    bundle_version: version,
    protocol_profile: PROTOCOL_PROFILE,
    workspace_id: workspaceId,
    project_id: projectId,
    version: 1,
    previous_version_hash: null,
    rules: [],
    servers: [],
    pins: [pin]
  };
}

describe("signed bundle version compatibility", () => {
  it("still accepts a legacy v1 bundle whose pins have no pin identity", () => {
    const parsed = policyBundleSchema.parse(bundle(LEGACY_BUNDLE_VERSION, {
      server_id: serverId,
      tool_name: "read_file",
      definition_hash: definitionHash
    }));
    expect(parsed.bundle_version).toBe(LEGACY_BUNDLE_VERSION);
    expect(parsed.pins[0].pin_id).toBeUndefined();
    expect(parsed.pins[0].pin_version).toBeUndefined();
  });

  it("requires pin identity on every new v2 bundle", () => {
    const result = policyBundleSchema.safeParse(bundle(BUNDLE_VERSION, {
      server_id: serverId,
      tool_name: "read_file",
      definition_hash: definitionHash
    }));
    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error.issues.some((issue) => issue.message === "v2 bundles require pin_id and pin_version"))
        .toBe(true);
    }
  });

  it("rejects a half-specified pin identity in either bundle version", () => {
    for (const version of [LEGACY_BUNDLE_VERSION, BUNDLE_VERSION]) {
      const result = policyBundleSchema.safeParse(bundle(version, {
        server_id: serverId,
        tool_name: "read_file",
        pin_id: pinId,
        definition_hash: definitionHash
      }));
      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error.issues.some((issue) => issue.message === "pin_id and pin_version must be present together"))
          .toBe(true);
      }
    }
  });
});
