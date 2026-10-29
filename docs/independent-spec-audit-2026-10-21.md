# Independent conformance audit — TraceGuard vs. agent-boundary-control-plane spec v3.0

**Audit date:** 2026-10-21

**Audited tree:** `f36d122` plus uncommitted working-tree changes (no code changes made by this audit)

**Spec:** `agent-boundary-control-plane-spec-v3.md`, v3.0, 2026-10-17

**Auditor:** independent code/test review, not the repository's `docs/spec-conformance.md`

> **Status note (2026-10-29):** this is the frozen 2026-10-21 baseline at `f36d122` against spec v3.0. Remediation since then (042 immutable pins, 043 `secret_ref`, 041 sessions, PKCE/resource, `external_identity_required`) is recorded only in `docs/spec-conformance.md` (maintainer self-assessment, updated 2026-10-27). No second independent re-audit has ratified it. Do not read §7 as the current tree verdict.

## Verdict

**Not conformant with the v1.0 must-have set as it stands.**

The enforcement core is substantially stronger than a typical first implementation. The MCP surface, approval state machine, signed-policy verification, deny-overrides, path confinement, OTLP limits, and encrypted approval arguments are real and tested. The 228-test API suite passes against PostgreSQL, the build passes, and the secret scan is clean.

The release blockers are structural, not cosmetic:

1. The audit checkpoint trust boundary and pruning semantics are wrong.
2. The database privilege matrix grants trusted-config and approval writes to the wrong roles.
3. The data model has no Project, AgentPrincipal, or separate IngestApiKey.
4. Upstream credentials are stored as plaintext values rather than secret references.
5. The approval/quarantine lifecycle is not backed by immutable pin versions.
6. The dashboard and admin execution path bypass the certified shim and use browser-stored privileged bearer keys.
7. The shim has no Authorization Code + PKCE flow.

Three must-have requirements are clearly not met (§7 identity/model, §10 audit, §13.4 DB roles); five more are only partial. Several §14 REST paths are absent or renamed. The repository's self-audit claims “26/26 functional, 13/13 non-functional, no must-have gaps”; that claim is not supported by the code.

> **Remediation status (2026-10-22):** release blocker 1 (§10 audit integrity) has been addressed at the code/test level; release blocker 2 (§13.4 DB roles) has been substantially remediated through migrations 035–037; and release blocker 3 (§7 identity model) has been addressed at the code/test level through migration 038 and its runtime wiring. Migration 039 also closes the project-scope gaps recorded under §1.3: signed policy versions and active pointers are project-scoped, and audit events carry project attribution under v4 hashes. See the dated notes in §1.1, §1.2, and §1.3. The original verdict and findings are retained as the audit baseline. The remaining API role/user-minting path and the other findings below remain open, so the project is still not conformant. These notes are maintainer remediation records, not a new independent audit.

A quick scorecard:

| Must-have area | Verdict |
|---|---|
| 1. Workspace → project → agent principal; IdP roles | **Not met** |
| 2. MCP Streamable HTTP allowlist + OAuth | **Met** |
| 3. Network segmentation | **Met**; live bypass test passed against Compose |
| 4. Discovery, namespacing, immutable pins | **Partial** |
| 5. Signed policy, deny-overrides, safe constraints | **Met** |
| 6. Approval state machine / consume-time re-evaluation | **Met** |
| 7. Certified TS shim with ACPKCE | **Partial** |
| 8. Encrypted args, dedup, caps | **Partial** |
| 9. Hash-chained audit + external checkpoints | **Not met** |
| 10. Dashboard queue + quarantine UI | **Partial** |
| 11. OTLP/HTTP + trace UI | **Met** |
| 12. Least-privilege DB roles | **Not met** |
| 13. Compose, migrations, threat model, compat, security tests | **Partial** |

**Post-audit remediation (2026-10-22):** row 9 (audit integrity) is addressed by migrations 033/034 and the operator CLI; row 12 (DB roles) is substantially remediated by migrations 035–037, with the API user/role-minting path still open; row 1 (identity model) is addressed at the code/test level by migrations 038 and 039, which add the project/principal/ingest-key layer, project-scoped signed policy, and project-attributed audit. The remaining findings in this report are still open. The scorecard above records the original audit baseline.

## 1. Release-blocking findings

### 1.1 Audit checkpoints are signed inside the gateway and anchored at the wrong boundary

**Spec:** §10.2, §13.4, FR-019. The checkpoint key must be stored outside PostgreSQL and outside the API/gateway containers. A checkpoint must cover the **last event in the segment being pruned**, and a verifier must show sequence gaps and never call a partial chain fully verified.

**Evidence:**

- `apps/api/src/gateway.ts` (`POST /v1/audit/checkpoints`, around line 1419) reads `AUDIT_CHECKPOINT_KEY` from the gateway process environment.
- `docker-compose.yml` injects `AUDIT_CHECKPOINT_KEY` and `AUDIT_CHECKPOINT_PUBLIC_KEY` into the **gateway** service. A compromised gateway can therefore sign a forged checkpoint that appears externally anchored.
- The checkpoint is created over the **current global tip**: `SELECT ... ORDER BY timestamp DESC, id DESC LIMIT 1`, with `up_to_hash = head.hash`.
- Migration `029_audit_checkpoints.sql` (`prune_audit_events`) then deletes `WHERE (timestamp,id) < (checkpoint_timestamp, checkpoint_id)` and **keeps the checkpointed head row**. The checkpoint is therefore at the first retained event, not the last event of the pruned segment. This is precisely the “checkpoint at the current tip and then delete an earlier range while retaining events that precede that tip” pattern the spec forbids.
- `POST /v1/audit/prune` accepts any non-empty `external_ref` string. It verifies the signature but never verifies that the signed artifact was actually exported or stored outside PostgreSQL. A caller can satisfy the endpoint with a receipt string.
- `prune_audit_events` is granted to `gateway_runtime`, not `retention_job`. The spec assigns audit pruning to the retention role, with a valid signed checkpoint.
- `packages/audit-chain/src/index.ts` hashes `timestamp, workspace_id, actor_type, actor_id, action, resource_type, resource_id, result, policy_version_id, matched_rule_ids, metadata, previous_hash`. It **omits the event ID and per-workspace sequence** from the hash, even though §10.1 includes both in the event fields and hash input. `verifyAuditChain` never checks sequence continuity or event IDs, so deleted or renumbered events inside a workspace do not produce a gap report.
- The verifier can mark a broken first link as `anchored` after matching a checkpoint, and does not label a partial chain “fully verified”; that part is sound. But without sequence/gap checks it cannot meet §10.2's “missing ranges and checkpoint gaps” requirement.

> **Remediation note (2026-10-21, after this finding was recorded):** migration
> `033_audit_integrity.sql` and `scripts/audit-checkpoint.mts` now implement
> operator-only checkpoint creation/pruning with the private key outside the
> API/gateway, v3 hashes covering event ID and per-workspace sequence, exact
> cutoff pruning through the last deleted event, durable chain state, a
> retention-only prune function, a required external receipt, and a signed v3
> payload naming `up_to_event_id` plus workspace segment heads. The verifier
> reports sequence gaps and only anchors a pruned prefix from a valid
> checkpoint. The gateway receives only `AUDIT_CHECKPOINT_PUBLIC_KEY`; the
> checkpoint/prune routes are gone. Integration and audit-chain tests cover the
> new path. The original finding is retained as the audit baseline; the other
> release blockers below (DB roles, identity model, and the rest) remain open,
> and this note is not an independent re-audit.

**Impact:** The audit trail is tamper-evident against an attacker who cannot alter the gateway, but not against the gateway itself. The pruning story does not cryptographically bind the deleted segment at the required boundary. This is the single most important gap because the product's core differentiator is tamper-evident audit.

**Required fix:** move checkpoint signing to an operator-side tool with a key never present in API/gateway; checkpoint the exact contiguous segment before deletion, anchored at its last event; require the signed artifact to be exported and independently verified before the retention role prunes; add sequence/ID continuity and gap reporting to the verifier; test deletion of a middle segment and a renumbered sequence.

### 1.2 Database roles grant trusted-config and approval writes to the wrong services

**Spec:** §13.4, FR-018a, NFR-008. The API must not approve/claim/execute/finalize or mutate active config. The gateway may read signed bundles and pins, enforce, use narrow approval procedures, and append audit; it must not edit drafts, trusted config, signing keys, or audit rows. The publisher inserts signed versions only. The retention job deletes eligible traces and prunes audit only with a checkpoint.

**Evidence (`apps/api/migrations/023_db_roles.sql`, `024_role_fixes.sql`, `028_spec_conformance.sql`, `apps/api/tests/db-roles.test.ts`):**

- `gateway_runtime` has table-level `INSERT, UPDATE` on `approvals`, `server_tools`, `mcp_servers`, and `policies`, and can execute `prune_audit_events`. It is not restricted to narrow approval-transition procedures.
- `policy_publisher` can `UPDATE policy_signing_keys` and `UPDATE active_config`, not merely insert a new signed version.
- `retention_job` can `DELETE FROM approvals` (as well as spans/runs/webhook deliveries). Approval history is not a trace-retention target.
- `api_runtime` can insert/update `users`, `api_keys`, and `memberships`, and can insert/update policy drafts. In non-OAuth deployments the API can mint trusted roles. That conflicts with “roles authoritative from the configured issuer” and “User is external identity mapping only”.
- The DB-role test **asserts these grants as expected behavior**, so the suite passing does not demonstrate spec compliance.

**Impact:** A compromised gateway or API credential can alter trusted server definitions, pin candidates, policy drafts, approval rows, signing-key trust, or active config. The spec's core claim — enforcement configuration is outside the control API and only a signed bundle activates it — is weakened at the database boundary.

**Required fix:** replace table-wide approval updates with `SECURITY DEFINER` transition procedures granted to `gateway_runtime`; revoke `INSERT/UPDATE` on `mcp_servers`, `server_tools`, `policies`, `policy_signing_keys`, and `active_config` from the gateway; make the publisher insert-only; move audit pruning to `retention_job`; remove approval DELETE from retention; prevent API role/user mutation in production. Update the tests to assert denials, not grants.

> **Remediation note (2026-10-21, after this finding was recorded):** migrations
> `035_approval_procedures.sql`, `036_policy_publisher_procedures.sql`, and
> `037_admin_config_roles.sql` narrow the runtime matrix:
>
> - **Approvals (035).** `approval_owner` (NOLOGIN) owns
>   `approval_request`, `approval_decide`, and `approval_transition`; only
>   `gateway_runtime` may execute them. All gateway approval DML was replaced
>   with those procedures. `INSERT/UPDATE/DELETE` on `approvals` is revoked
>   from `gateway_runtime`, `api_runtime`, and `retention_job`; retention no
>   longer deletes approval history.
> - **Publisher trust (036).** `policy_owner` (NOLOGIN) owns
>   `policy_trust_key` and `policy_activate_version`; `policy_publisher` keeps
>   `INSERT` on `policy_versions` but loses `INSERT/UPDATE` on
>   `policy_signing_keys` and `active_config`. The consume-time
>   `lock_active_config_share` helper is re-owned so the gateway keeps the
>   serialization lock without write privilege.
> - **Admin configuration (037).** The server/pin/policy admin routes moved
>   from the gateway process to `apps/api/src/admin.ts`; `api_runtime` receives
>   the `mcp_servers`/`server_tools` writes and `gateway_runtime` loses them.
> - **Tests.** `db-roles.test.ts` now asserts the denials, procedure ownership,
>   and retention behaviour; gateway approval tests exercise the procedures;
>   publisher tests use the new trust/activation path.
>
> **Still open:** `api_runtime` retains `INSERT/UPDATE` on `users`, `api_keys`,
> and `memberships`, so a non-OAuth deployment can still mint trusted roles.
> The audit's “prevent API role/user mutation in production” fix is deferred to
> the identity-model workstream (§1.3), where users and principals are
> restructured. The DB-role finding is therefore **substantially remediated but
> not fully closed**. The original finding is retained as the audit baseline;
> this note is not an independent re-audit.

### 1.3 No Project, AgentPrincipal, or distinct IngestApiKey model

**Spec:** Must #1, §13.1, FR-001. One workspace contains projects; an AgentPrincipal is a non-human MCP caller scoped to a project with issuer/subject/scopes/status; IngestApiKey is OTLP-only, hashed, scoped, revocable, and never an MCP OAuth token.

**Evidence:**

- `apps/api/migrations/*.sql` has `workspaces`, but **no `projects` table**. `mcp_servers`, `policies`, `approvals`, `runs`, and `spans` are scoped by `workspace_id` only.
- **No `agent_principals` table.** The `agents` table is a trace-agent entity, not an authenticated MCP principal. `apps/api/src/auth.ts` maps an OAuth `sub` (or a static key) directly to `caller`; `apps/api/src/mcp.ts` takes `principal.workspaces[0]`. There is no project-scoped principal, allowed-scope list, status, or issuer binding.
- **No `ingest_api_keys` table.** `api_keys` carries scopes including both `ingest` and `gateway`; `ROLE_SCOPES.member = [read, ingest, gateway]` and `ADMIN_SCOPES = [admin, ingest, gateway, read]`. The same credential can ingest traces and call MCP.
- `apps/api/src/index.ts` and `gateway.ts` call `defaultWorkspaceId()` on many mutating routes, ignoring the authenticated caller's workspace. Cross-workspace isolation is therefore partial even at the workspace level.
- Approval caps and dedup are workspace/global: `approvals.request_id TEXT UNIQUE` is global, and the cap counts `workspace_id`, not `project_id`.
- `docs/spec-conformance.md` describes “project” as workspace in several places. That is a naming substitution, not the data model the spec requires.

**Impact:** FR-001 cannot be demonstrated. A project cannot have its own agent principals, ingest keys, approval caps, policy scope, or audit scope. Adding these later requires schema and query changes across every subsystem.

**Required fix:** add `projects` under `workspace`, `agent_principals` under `project`, and `ingest_api_keys` under `project`; migrate every `workspace_id`-scoped table that is actually project-scoped; make `AgentPrincipal` the caller identity for MCP; issue separate hashed ingest keys; add project ID to approvals, decisions, budgets, runs, and audit. Then add cross-project negative tests.

> **Remediation note (2026-10-21, after this finding was recorded):** migration
> `038_identity_model.sql` adds `projects`, `agent_principals`, and
> `ingest_api_keys`; backfills a `default` project per existing workspace and
> creates one by trigger for every new workspace. It adds `project_id` to
> `mcp_servers`, `policies`, `approvals`, `policy_decisions`, `runs`, and
> `budgets`, with fill triggers so older callers that omit the column still
> land in the workspace default. Approval deduplication is now keyed by
> `(project_id,caller,request_id)`, and the active-pending caps and creation
> rate limit are project-scoped (10 per caller/project, 100 per project, 5
> requests/caller/minute). `apps/api/src/projects.ts` exposes project CRUD,
> per-project ingest-key create/list/revoke, agent-principal management, and
> `/v1/whoami`. `apps/api/src/auth.ts` maps a validated OAuth subject to an
> active project-scoped `AgentPrincipal`, narrows multi-project tokens to the
> provisioned project, intersects token scopes with the principal's allowed
> scopes, and rejects unprovisioned production MCP callers with
> `agent_principal_required`. Ingest keys use a separate `tgi_` prefix, are
> hashed and revocable, and are refused on MCP, approval-control, and admin
> routes. Cross-project negative tests cover ingestion, project reads, MCP
> server lookup, and approval deduplication. Migration
> `039_project_policy_audit.sql` closes the remaining project-scope gaps:
> `policy_versions` and `active_config` now carry `project_id`, bundles may
> carry it, and `loadActivePolicy` rejects a mismatched project (legacy
> bundles without the field are accepted only for the workspace default).
> `audit_events` now has a `project_id` and v4 hashes cover it, while v1–v3
> hashes remain byte-identical; the checkpoint/export path carries the field.
> The API still has a local user/role-minting path. This note is a maintainer
> remediation record, not a new independent audit.

### 1.4 Upstream credentials are stored as plaintext values

**Spec:** §7.4. Registration carries a **secret reference, never the value**; the gateway owns upstream credentials.

**Evidence:**

- `apps/api/migrations/002_gateway.sql` defines `mcp_servers.auth_secret TEXT`.
- `apps/api/src/gateway.ts` `POST /v1/servers` accepts `auth_secret` in the request body (max 1024) and inserts the value directly.
- The signed bundle includes `auth_mode` but not a secret reference; the gateway reads the plaintext column at call time.
- The API's GET response omits the secret, but the value exists in the database, in request bodies, and in any backup.

**Impact:** Database read access, a backup leak, or an API/gateway compromise exposes upstream credentials. The spec's “credential sources” model is not implemented.

**Required fix:** replace `auth_secret` with `secret_ref` (file path, environment variable name, or secret-manager key). Resolve it only in the gateway at connection time. Reject inline values. Add a test that a database dump contains no upstream credential.

### 1.5 Pin re-approval does not create a new immutable pin version

**Spec:** §7.5, FR-017. Tool definitions are immutable pins. A changed definition is quarantined. Re-approval creates a new immutable pin version; no invocation until the new pin is active.

**Evidence:**

- `server_tools` is a mutable row with `definition`, `previous_definition`, `definition_hash`, `definition_version`, and `quarantined`. There is no `tool_definition_pins`, `tool_pin_candidates`, or equivalent version table.
- `POST /v1/servers/:id/discover` updates the row on change and sets `quarantined = true`; it does not create an immutable candidate.
- `PUT /v1/servers/:sid/tools/:tool/quarantine` toggles quarantine. Setting it to false for an **unchanged** definition immediately makes the tool callable again if the signed bundle already contains that hash. No new signed bundle or pin version is required.
- There are no `/v1/tool-pins/{id}/submit-review` or `/v1/tool-pin-candidates/{id}/approve-for-publication` routes. The UI “Re-approve” toggle calls the quarantine endpoint directly.
- The signed bundle does carry immutable pin hashes, and a changed definition will not match the old bundle, so drift is blocked. The failure is the lifecycle and the same-hash re-approval path, not the hash check itself.

**Impact:** The “reviewed definition” guarantee is weaker than specified. A definition can be quarantined and re-enabled by an admin without a new review artifact, and pin history depends on a mutable row plus bundle history.

**Required fix:** add immutable pin/candidate rows; make every re-approval produce a new pin version; require publisher signature and gateway activation before calls; remove the direct unquarantine shortcut; expose submit-review/approve-for-publication routes; test same-hash re-approval and changed-hash re-approval.

### 1.6 Dashboard credentials and admin “Run now” bypass the certified shim

**Spec:** §7.3, §9.3, FR-015, FR-016. The dashboard uses a session/CSRF model; only the bundled shim is certified for approval retries; the agent credential never calls an approval endpoint; admin and approver are separate roles.

**Evidence:**

- `apps/web/src/api.ts` stores the API key, gateway key, gateway control URL, and **approver key** in `localStorage` (`tg_key`, `tg_approver_key`). There is no session cookie and no CSRF token.
- `apps/web/src/Approvals.tsx` has a **“Run now”** action that calls `POST /v1/gateway/tools/call` with the admin API key (`settings.key`), not the shim, supplying `approval_id`, original arguments, `request_id`, and caller. The gateway still enforces the binding hash, but this is an uncertified dispatch path and lets an admin-scope browser trigger execution after approval.
- The control listener correctly requires `approve` scope and does not let an admin key shortcut. The dashboard approver key is long-lived and stored in the browser, which defeats much of that separation.
- The UI displays raw approval arguments to an authorized approver over TLS with `Cache-Control: no-store`; that part is acceptable. The storage model is not.

**Impact:** A stolen browser profile yields a long-lived approver credential and an admin credential. An admin can execute an approved action outside the shim contract. The spec's separation between human approval and execution is not cleanly enforced.

**Required fix:** server-side session cookies with CSRF, short-lived tokens, no privileged keys in localStorage; remove “Run now” or route it through the certified shim with an agent credential and the required `_meta` metadata; keep approver and admin sessions distinct; add a test that an admin cannot dispatch and that a missing shim profile returns `APPROVAL_CLIENT_REQUIRED`.

## 2. High-severity conformance gaps

### 2.1 No Authorization Code + PKCE in the shim; RFC 8707 resource claim is not checked

`packages/mcp-client-shim/src/index.ts` implements the retry/approval contract well: stable `logical_request_id`, fresh JSON-RPC `id` per attempt, `approval-client-profile: 1`, terminal-state handling, `OUTCOME_UNKNOWN` on post-dispatch ambiguity, and `APPROVAL_CLIENT_REQUIRED` mapping. That satisfies FR-015's retry semantics.

It does **not** implement Authorization Code + PKCE. `apps/api/src/oauth.ts` supports `client_credentials` only; `docs/compatibility.md` admits ACPKCE is not implemented. `verifyAccessToken` checks `iss` and `aud` but not an RFC 8707 `resource` claim. The shim also accepts a static bearer token as a first-class option.

This is a must-have gap for interactive user authorization. `client_credentials` is defensible for a headless agent principal, but the spec requires ACPKCE **where user auth is involved** and forbids a raw API-key shortcut in production. Add ACPKCE, validate `resource`, and gate static-token mode to an explicit dev profile.

### 2.2 Audit event taxonomy is incomplete

The chain has most events, but §10.3 requires distinct approval approved/rejected events, server disabled, policy signed/published, tool re-approved, and budget denied. The implementation collapses approval decisions into `approval.decide`, has no `server.disabled` route/event, and writes `policy.published` only in the publisher process. It also uses `budget.exceeded` rather than `budget.denied`.

This is not a chain-integrity failure by itself, but it makes the audit trail harder to query and does not match the required event set.

### 2.3 REST contract is broadly divergent from §14

The functionality is often present under a different name, but the specified contract is not:

- Present after remediation 038: `/v1/projects`, `/v1/projects/{id}`, `/v1/projects/{id}/ingest-keys`, `/v1/ingest-keys/{id}/revoke`, `/v1/whoami`.
- Renamed: `/v1/servers` for `/v1/mcp-servers`; `/v1/servers/{id}/discover` for `refresh-tools`; `/v1/policies` for `/v1/policy-drafts`; `/v1/decisions` for `/v1/policy-decisions`; `/v1/runs/{id}/trace` for `/v1/runs/{id}/spans`; `PUT` for `PATCH` on budgets.
- Missing: `/v1/mcp-server-drafts` and export, `/v1/mcp-servers/{id}/tools`, `/v1/tool-pins/{id}/submit-review`, `/v1/tool-pin-candidates/{id}/approve-for-publication`, `/v1/mcp-servers/{id}/disable`, `/v1/policy-drafts/{id}/export`.
- Missing: control API `GET /v1/approvals` (redacted queue) and gateway `GET /_control/v1/approvals/{id}`.
- Pagination: `/v1/audit-events` has no cursor pagination and no workspace filter.

This breaks clients built to the spec even when the underlying behavior exists. The project lifecycle routes are now present; the remaining renaming and the missing pin-review/mcp-server-draft routes still contribute to the FR-017 contract gap.

### 2.4 Approval dedup and caps used the wrong keys; TTL default was wrong in Compose

- `approvals.request_id TEXT UNIQUE` was global. The spec key is `(project_id, caller_id, logical_request_id)`. Two callers reusing a logical ID collided; a global unique constraint also made cross-project linkage harder. Migration 038 replaces it with a unique key on `(project_id, caller, request_id)` and the identity suite checks that the same logical ID is independent across projects.
- Active-pending caps counted `workspace_id`, not `project_id`; the spec requires per-caller and per-project caps. Migration 038 and `apps/api/src/gateway.ts` now count 10 active pending per caller/project, 100 per project, and 5 creation requests per caller/project per minute.
- The gateway default TTL is 900 seconds and the hard max is 3600, which matches the spec. `docker-compose.yml` previously overrode it to `300` seconds; Compose now defaults to `900`. `infra/k8s/configmap.yaml` still sets `300`, so the Kubernetes reference deployment retains that deviation.

### 2.5 Budget reservation is serialized but not the specified atomic conditional update

`apps/api/src/budgets.ts` does:

1. `SELECT * FROM budgets WHERE id = $1 FOR UPDATE`
2. compute `spent + reserved + amount > limit` in JavaScript
3. `UPDATE budgets SET reserved_micro = reserved_micro + $2`

The row lock prevents two callers from both passing the check for the same budget, so it is not a classic double-spend. But §12 requires a single conditional `UPDATE ... WHERE spent + reserved + amount <= limit RETURNING`; zero rows means denied. The implementation's application-level check and unconditional update are not the same invariant, and the `project` scope computes spend from spans while locking only the budget row, so concurrent ingestion can race.

`POST /v1/budgets/settle` also accepts a caller-supplied `actual_cost_micro` without capping it at the reserved amount. A caller can settle an arbitrary positive amount and overrun the budget. There is no managed model wrapper; the gateway's `enforceBudget` is an extra pre-call check, not the required enforcement point.

### 2.6 DB roles and audit docs contradict the threat model

`docs/threat-model.md` T18 says no endpoint can sign, activate, or roll back a version and that migration 023 makes denials database privileges. The actual grants allow `gateway_runtime` to update `mcp_servers`, `server_tools`, `policies`, and `approvals`; `policy_publisher` to update `policy_signing_keys` and `active_config`; and `retention_job` to delete approvals. T10 says the checkpoint key is external, but Compose injects it into the gateway. These are not documentation nits: they misstate the security boundary a reviewer would rely on.

## 3. What is genuinely conformant

This section matters because the failures above should not obscure the quality of the enforcement core.

- **MCP surface (§7.1–7.3).** `apps/api/src/mcp.ts` advertises protocol `2026-07-28`, requires `_meta.io.modelcontextprotocol/protocolVersion` and `clientCapabilities`, validates `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` against the body, and allows only `server/discover`, `tools/list`, and `tools/call`. `tools/list` returns only enabled, pinned, non-quarantined, namespaced `alias__tool` entries with `ttlMs`, `cacheScope`, and `resultType: "complete"`. MRTR/input-required/task-shaped results are rejected with `UNSUPPORTED_RESULT`, audited, and never forwarded. GET `/mcp` returns 405. Unknown methods are rejected.
- **Approval state machine (§9.2).** The gateway has durable `CLAIMED` and `EXECUTING` states, a CAS claim with lease, a separate execution-intent transaction under `lock_active_config_share`, full consume-time re-evaluation, and `OUTCOME_UNKNOWN` on ambiguous post-dispatch failure. It never auto-retries after ambiguity, and a late response does not reset a finalized unknown. This is the strongest part of the implementation.
- **Signed policy (§8, §13.3).** Ed25519 signatures, content hashes, previous-version linkage, rollback/fork/history checks, a gateway-only anchor, retired-key refusal, deny-overrides, and safe JSON Schema/regex/enum/max-length constraints are implemented. `path_within` requires a server- and tool-scoped rule plus a pinned executor attestation; the gateway and publisher both refuse unenforceable rules.
- **Approval argument protection (§9.4).** AES-256-GCM sealing, TTL clamping, ciphertext deletion on terminal states, redacted summaries, binding hashes over caller/server/tool/args/logical ID/pin hash, and `Cache-Control: no-store` are implemented.
- **OTLP ingestion (§11).** Protobuf and JSON, partial-success responses, 1 MiB body cap, 2,000 spans, 50 resourceSpans, 60k spans/min per caller, deterministic span IDs, duplicate suppression, child-before-parent linking, 24-hour late rejection, clock-skew flags, non-negative durations, redaction before persistence, and NULL cost when pricing/usage is unknown. Trace UI and decision correlation exist.
- **Retention (§11.4).** Default 7 days / 100k spans per workspace, whole-run deletion where possible, and no deletion of audit/policy/decisions/money. Terminal approvals are deleted, which is a separate role issue but not a trace-retention failure.
- **Network topology (§6).** Compose has `agent_edge` (agent + gateway), `gateway_upstream`/`tools` (`internal: true`, gateway + mock tools), and `control_plane`/`front`. The upstream has no published host port, the agent is not on the upstream network, and the gateway is the only application on it. No privileged containers or Docker socket. The names differ from the spec, but the segmentation intent is present.
- **OAuth validation.** JWT signature, issuer, audience, expiry, `nbf`, and scopes are checked; production refuses static-key-only auth. PRM metadata is exposed. The gap is the missing `resource` claim and ACPKCE, not the basic validation.
- **Build/test/secret hygiene.** `npm run build` passes every workspace. `npm test -w apps/api` passes 22 files / 228 tests against PostgreSQL; publisher 7, web 30, audit-chain 13, canonical-json 7, shim 17, policy-signing 7, TypeScript SDK 7. `npm run test:secrets` reports 0 findings across 231 tracked files.

## 4. Repository/API/layout conformance

| Spec requirement | Reality |
|---|---|
| pnpm workspaces + `pnpm-workspace.yaml` + `pnpm-lock.yaml` | **npm workspaces** + `package-lock.json`; no pnpm files |
| `apps/{web,api,gateway}` | `apps/{api,web}`; gateway is `apps/api/src/gateway.ts`, run from the API image |
| `packages/{contracts,policy-engine,canonical-json,audit-chain,mcp-client-shim}` | `packages/{audit-chain,canonical-json,mcp-client-shim,policy-signing,schemas}`; policy engine lives in `apps/api/src/policy.ts`; no `contracts` |
| `tests/{integration,e2e,security,fixtures}` | `tests/{e2e,security,faults,oauth}`; API integration tests under `apps/api/tests`; no top-level fixtures |
| `infra/compose` | Root `docker-compose.yml`; `infra/{k8s,postgres}` |
| `examples/{mock-mcp-read-server,mock-mcp-write-server}` | One `examples/mock-tools` server; no separate read/write examples |
| ADRs for approval states, ambiguous outcomes, signing, DB roles, checkpoints, network | **No ADR directory found** |
| Exact §14 REST paths | Broadly divergent (see 2.3) |
| Name “TraceGuard” | Unresolved collision; the spec explicitly warns against it and the repo accepts the risk as a user decision |

The layout deviations are not all functional failures — a gateway in the API package is still a separate process and container, and a single mock server can exercise read/write operations. But they are explicit spec deliverables, and the missing ADRs are part of the Phase 0 record the spec asks for.

## 5. Test and evidence status

**Executed in this audit:**

- `npm run build` — pass, all workspaces.
- `npm test -w apps/api` — 228/228 pass after starting PostgreSQL and applying migrations/roles.
- `npm test -w tools/policy-publisher` — 7/7 pass.
- Workspace unit tests: web 30, audit-chain 13, canonical-json 7, mcp-client-shim 17, policy-signing 7, TypeScript SDK 7.
- `npm run test:secrets` — 231 files, 0 findings.

**Also executed after the Compose stack was built:**

- `docker compose up -d --build` — all services built and reached healthy/running state (api, gateway, mock-tools, postgres, web; agent started).
- `npm run test:security` — 6/6 network-boundary checks pass: the agent cannot resolve or reach the upstream by service name or IP, cannot reach the API or PostgreSQL; the gateway can reach the upstream; the agent reaches the gateway as itself.
- `npm run test:e2e` — **10/10 pass in CI mode** (A, B, C, D, E, G, F, H, J, I), against its own PostgreSQL database, API, gateway, mock upstream, and built dashboard. Note: outside CI, `reuseExistingServer` attaches to an already-running Compose stack; with a non-default `.env` key that first run fails 401 at server registration. Setting `CI=true` and stopping Compose API/gateway/web gives the intended isolated run. This is a test-harness ergonomics issue, not a product failure.
- `npm run test:faults` — fail-closed checks pass with PostgreSQL down: API `/healthz` 200, `/readyz` 503, ingest 500, gateway tool call 500.
- `npm run test:oauth` (with `DATABASE_URL` pointed at the dev database) — static keys refused in production, OAuth read token reaches the API, OAuth gateway token reaches MCP, static key refused at `/mcp`.

**Not verified:** the complete 17-item §21 demo as one scripted sequence, and NFR-001/002/003 p95 targets. The E2E suite has 10 scenarios (A–J), not the whole §21 matrix in one place; several §21 items are covered by the 228 API tests. There is no reproducible benchmark run in this audit, so p95 policy overhead, <3 s ingest visibility, and <500 ms dashboard at 100k remain unverified.

**Self-audit discrepancy:** `docs/spec-conformance.md` claims 26/26 functional and 13/13 NFR implemented, “no must-have gaps,” and live checks. It also claims a conditional budget `UPDATE` and “new pin version” behavior that the code does not implement. The self-audit is useful as a map of tests, but it is not an independent conformance result.

> **Post-audit remediation re-run (2026-10-22, maintainer record):** after migrations 033–039 and the admin-route move, `npm test -w apps/api` passes **239/239** across 23 files (including integration **59/59** and identity **7/7**), the DB-role suite **16/16**, the publisher suite **8/8**, and the audit-chain suite **19/19**; `npm run build` passes every workspace. The identity suite includes the OAuth multi-project narrowing case and the production `agent_principal_required` rejection; the policy and audit-chain suites cover per-project policy state and v4 project attribution. The self-assessment was also reconciled with this audit (FR-002/016/017/024 and NFR-008 remain Partial; FR-001/012/014 are now Implemented). These runs verify the remediation work; they do not convert this document into an independent re-audit.

## 6. Recommended order of work

**Before any v1.0 release claim:**

1. **Fix audit trust and pruning.** Operator-side checkpoint key; exact segment checkpoint at the segment's last event; verify external export before prune; add event ID/sequence to the hash; add sequence/gap verification; move prune to `retention_job`. Add tamper tests for deleted middle events and renumbered sequences.
2. **Fix the DB role matrix.** Procedure-based approval transitions; gateway read-only on trusted config; publisher insert-only; retention no approval deletes; API no production role minting. Make `db-roles.test.ts` assert the spec denials.
3. **Add Project / AgentPrincipal / IngestApiKey.** Migrate scoping, caps, approvals, audit, and ingest keys. Add cross-project negative tests.
4. **Replace plaintext upstream credentials with secret references.**
5. **Make pin re-approval a signed, immutable version.** Remove the same-hash unquarantine shortcut; add the review routes.
6. **Remove the admin “Run now” dispatch path and localStorage bearer keys.** Add session cookies/CSRF; route execution through the shim.
7. **Implement ACPKCE and RFC 8707 `resource` validation; gate static tokens to dev.**
8. **Close the §14 contract gaps** (or publish an explicit compatibility map and versioned aliases).
9. **Fix budget reservation to the conditional update; cap settlement; add the managed wrapper or stop claiming §12 enforcement.**
10. **Adopt pnpm and the required layout/ADRs; correct threat-model/compatibility claims; resolve the name.**

## 7. Bottom line

TraceGuard has a credible enforcement core and unusually broad automated tests for a project at this stage. At the time of this audit the largest risks were trust-boundary failures: the audit checkpoint key sat in the gateway, the verifier could not see sequence gaps, the database roles let the gateway and publisher alter trusted state, and the identity model stopped at workspace instead of project/agent principal. Those have been remediated at the code/test level (033–039): the project/principal/ingest-key layer exists, signed policy versions and active pointers are project-scoped, and audit events carry project attribution. The project is still not the product the spec describes: upstream secrets remain plaintext, pins remain mutable, the dashboard still stores bearer keys and exposes an admin “Run now” path, ACPKCE/RFC 8707 are absent, and the API retains a local user/role-minting path.

The existing self-audit should be treated as a test inventory and implementation map, not as evidence of conformance. The 239 passing API tests are real and valuable, but at the time of this audit several of them asserted nonconformant behavior (notably the DB grants and the mutable pin path). The DB-role suite now asserts the tightened 035–037 matrix and the identity suite covers cross-project denials, while the mutable-pin tests and the other open findings remain the baseline.
