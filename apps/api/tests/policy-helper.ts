import type { Pool } from "pg";
import { generateSigningKey } from "@traceguard/policy-signing";
import { publish, resolveWorkspaceId, trustKey } from "../../../tools/policy-publisher/src/index.js";

// Test-only convenience: publish the current drafts as the active signed
// policy, exactly the way the operator CLI does. The suite therefore
// exercises the real signature path, not a bypass.
const key = generateSigningKey();
let trustedWorkspaces = new Set<string>();

export async function publishTestPolicy(pool: Pool, workspace = "default"): Promise<number> {
  const workspaceId = await resolveWorkspaceId(pool, workspace);
  if (!trustedWorkspaces.has(workspaceId)) {
    await trustKey(pool, { workspaceId, publicKeyPem: key.publicKeyPem, trustedBy: "test" });
    trustedWorkspaces.add(workspaceId);
  }
  const result = await publish(pool, {
    workspaceId,
    privateKeyPem: key.privateKeyPem,
    publishedBy: "test"
  });
  return result.version;
}
