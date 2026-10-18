import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { contentHashOf, keyIdFor, verifyPayload } from "@traceguard/policy-signing";
import { policyBundleSchema, type PolicyBundle } from "@traceguard/schemas";
import type { PolicyRule } from "./policy.js";

// §13.3: the gateway trusts only a signed bundle the operator's publisher
// produced. Everything here fails closed — an invalid signature, a rollback,
// a fork, or a missing key means no protected call, never an unsigned one.

export interface ActivePolicy {
  bundle: PolicyBundle;
  policy_version_id: string;
  version: number;
}

export type ActivePolicyResult =
  | { ok: true; policy: ActivePolicy }
  | { ok: false; reason: string };

// Structural so a pg Pool and a PoolClient both satisfy it.
export interface Queryable {
  query(text: string, values?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

// The gateway remembers the highest policy version it has accepted, in a file
// only the gateway writes (GATEWAY_STATE_DIR). Without it, a database owner
// could roll the active pointer back to an older signed bundle and no
// signature check would notice: the old bundle is genuine, it is just no
// longer current.
interface AcceptedState {
  [workspaceId: string]: { version: number; content_hash: string };
}

function stateFile(): string {
  return join(process.env.GATEWAY_STATE_DIR ?? "./gateway-state", "policy-state.json");
}

function readState(): AcceptedState {
  try {
    return JSON.parse(readFileSync(stateFile(), "utf8")) as AcceptedState;
  } catch {
    // No state = a fresh gateway. The first accepted version bootstraps the
    // anchor; from then on every load is checked against it.
    return {};
  }
}

function writeState(state: AcceptedState): void {
  const file = stateFile();
  mkdirSync(dirname(file), { recursive: true });
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, JSON.stringify(state, null, 2));
  renameSync(tmp, file);
}

// In-process memo of what was already persisted, so bursts do not rewrite the
// state file per call. The file remains the source of truth across restarts.
let persistedAnchors: Record<string, string> = {};

export function resetPolicyStateCache(): void {
  persistedAnchors = {};
}

const MAX_HISTORY_WALK = 500;

// Signed bundle rules become engine rules carrying the bundle's version, so
// decisions cite the signed edition rather than a mutable draft row.
export function rulesFromBundle(bundle: PolicyBundle): PolicyRule[] {
  return bundle.rules.map((r) => ({
    id: r.id,
    version: bundle.version,
    name: r.name,
    enabled: r.enabled,
    priority: r.priority,
    agent_id: r.agent_id,
    server_id: r.server_id,
    tool_name: r.tool_name,
    effect: r.effect,
    conditions: (r.conditions ?? {}) as PolicyRule["conditions"]
  }));
}

export async function loadActivePolicy(
  client: Queryable,
  workspaceId: string
): Promise<ActivePolicyResult> {
  const row = await client.query(
    `SELECT pv.id, pv.version, pv.bundle, pv.content_hash, pv.signature, pv.previous_version_hash,
            pk.key_id AS pinned_key_id, pk.public_key_pem, pk.retired_at
       FROM active_config ac
       JOIN policy_versions pv ON pv.id = ac.policy_version_id
       JOIN policy_signing_keys pk ON pk.id = pv.signing_key_id
      WHERE ac.workspace_id = $1`,
    [workspaceId]
  );
  const pv = row.rows[0];
  if (!pv) return { ok: false, reason: "no signed policy version is active" };
  if (pv.retired_at) {
    return { ok: false, reason: "the signing key of the active policy version is retired; re-publish" };
  }

  // 1. The bundle must hash to what was stored, or it was altered in place.
  const contentHash = contentHashOf(pv.bundle);
  if (contentHash !== pv.content_hash) {
    return { ok: false, reason: "policy bundle content hash mismatch" };
  }

  // 2. The signature must verify under the pinned key, and the key id is
  //    recomputed from the key material rather than trusted as stored.
  if (keyIdFor(String(pv.public_key_pem)) !== pv.pinned_key_id) {
    return { ok: false, reason: "signing key id does not match the pinned key" };
  }
  if (!verifyPayload(pv.bundle, String(pv.signature), String(pv.public_key_pem))) {
    return { ok: false, reason: "policy signature does not verify" };
  }

  // 3. Shape, then the fields that must agree with the row.
  const parsed = policyBundleSchema.safeParse(pv.bundle);
  if (!parsed.success) {
    return { ok: false, reason: "policy bundle does not match the schema" };
  }
  const bundle = parsed.data;
  if (bundle.workspace_id !== workspaceId) {
    return { ok: false, reason: "policy bundle belongs to another workspace" };
  }
  if (bundle.version !== Number(pv.version)) {
    return { ok: false, reason: "policy bundle version does not match its row" };
  }
  if ((bundle.previous_version_hash ?? null) !== (pv.previous_version_hash ?? null)) {
    return { ok: false, reason: "policy bundle history does not match its row" };
  }

  // 4. Rollback, fork, and history-gap checks against the last accepted state.
  const state = readState();
  const stored = state[workspaceId];
  if (stored) {
    if (Number(pv.version) < stored.version) {
      return { ok: false, reason: `policy rollback detected (active v${pv.version}, last accepted v${stored.version})` };
    }
    if (Number(pv.version) === stored.version && contentHash !== stored.content_hash) {
      return { ok: false, reason: "policy fork detected (same version, different content)" };
    }
    if (Number(pv.version) > stored.version) {
      // Walk the signed history down to the last accepted version: every link
      // must exist, and each newer bundle must cite its parent's content hash.
      let cursor = {
        version: Number(pv.version),
        previous: (pv.previous_version_hash as string | null) ?? null,
        content_hash: contentHash
      };
      let steps = 0;
      while (cursor.version > stored.version) {
        if (++steps > MAX_HISTORY_WALK) {
          return { ok: false, reason: "policy history is too long to verify" };
        }
        if (!cursor.previous) {
          return { ok: false, reason: `policy history gap before v${cursor.version}` };
        }
        const parent = await client.query(
          "SELECT version, content_hash, previous_version_hash FROM policy_versions WHERE workspace_id = $1 AND version = $2",
          [workspaceId, cursor.version - 1]
        );
        const p = parent.rows[0];
        if (!p || p.content_hash !== cursor.previous) {
          return { ok: false, reason: `policy history gap at v${cursor.version - 1}` };
        }
        cursor = {
          version: Number(p.version),
          previous: (p.previous_version_hash as string | null) ?? null,
          content_hash: String(p.content_hash)
        };
      }
      if (cursor.content_hash !== stored.content_hash) {
        return { ok: false, reason: "policy rollback to a different history detected" };
      }
    }
  }

  // Accepted: remember it. Persisted after every check, so a crash can never
  // mark an unverified version as accepted.
  const anchor = `${Number(pv.version)}:${contentHash}`;
  if (persistedAnchors[workspaceId] !== anchor) {
    state[workspaceId] = { version: Number(pv.version), content_hash: contentHash };
    writeState(state);
    persistedAnchors[workspaceId] = anchor;
  }

  return {
    ok: true,
    policy: { bundle, policy_version_id: String(pv.id), version: Number(pv.version) }
  };
}
