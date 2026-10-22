# Threat model

Status: living document, reviewed against the v3.0 specification.
Scope: the control plane as deployed by `docker-compose.yml` on a single node.

The hash-chained audit trail is **tamper-evident, not tamper-proof**. A host or
database owner can rewrite the deployment; only an externally stored, signed
checkpoint anchors history against that.

## Assets

- Tool-execution authority (the right to make an MCP upstream do something).
- Upstream MCP credentials and the secret references that resolve them.
- Tool arguments, which may contain secrets or business data.
- Human approval identity and decisions.
- Signed policy versions, tool-definition pins, and audit history.
- API key hashes, approval-argument encryption keys, and signing keys.
- Trace data (runs, spans, attributes) and project metadata.

## Trust boundaries

| Zone | Trust | Notes |
|---|---|---|
| Model output / agent runtime | **Untrusted** | May be prompt-injected or compromised; never an authorization source. |
| MCP request envelope (`/mcp`) | **Untrusted** | JSON-RPC body, headers, `_meta`, `clientInfo` are attacker-controlled. |
| Upstream MCP server | **Untrusted** | Separate trust domain; may be malicious or change behavior. |
| OTLP ingestion (`/v1/traces`) | **Untrusted** | Attributes and resource fields are data, never policy input. |
| Gateway process | **Trusted boundary** | The only network path to protected upstreams; applies policy and approvals. |
| Control API | **Limited trust** | Manages drafts and reads; cannot sign policy, approve, or alter audit. |
| Approver | **Authorized human** | May decide only for assigned projects; never sees another project's arguments. |
| Administrator | **Powerful, not trusted with execution** | Can change drafts; activation requires the out-of-process publisher. |
| Host / Docker / PostgreSQL owner | **Out of scope** | Can compromise the node; external checkpoints are the only anchor. |

## Threats

| # | Threat (STRIDE) | Mitigation in this repo | Status |
|---|---|---|---|
| T1 | **S** Agent bypasses the gateway and calls an upstream directly | Gateway is the only container on the upstream network; upstreams publish no host ports; `tests/security/bypass.mjs` runs **inside** the agent container and proves it cannot reach the upstream by service name or by IP, cannot reach the control API or postgres, and can reach the gateway (asserted as an unauthenticated 401, not just a TCP connect) | Implemented (compose; `security` CI job); residual: the k8s path relies on the cluster's NetworkPolicy, which is not shipped here |
| T2 | **T** Agent alters or replays an approval | `request_hash` over caller, server, tool, canonical args (RFC 8785), logical request id, and the tool-definition pin; single-use CAS to executing; retries keyed by logical request id | Implemented (`gateway.ts`, approval tests) |
| T3 | **T** Concurrent retries dispatch twice | `SELECT … FOR UPDATE` + CAS to `executing`; later retries observe the terminal state | Implemented |
| T4 | **S/T** Admin changes a tool description or schema | Pin covers title/description/both schemas/annotations/icons/execution/allowlisted _meta over RFC 8785; drift quarantines with the previous pin kept for the diff; external `$ref`, depth, node, and size bounds never pin; only a published bundle activates a pin | Implemented (`upstream.ts`, `pins.test.ts`) |
| T5 | **S** Malicious upstream URL / SSRF | Destination policy blocks loopback, link-local, metadata, private ranges unless explicitly allowed; DNS revalidated at connect | Partial — application checks only, no egress firewall |
| T6 | **I** Agent obtains an upstream credential | Inbound bearer tokens are never forwarded; upstream credentials come from gateway-owned refs; inbound auth stripped | Implemented |
| T7 | **T** Prompt injection drives a protected action | External policy + human approval, not model judgment; deny-overrides | Implemented (policy), partial (OAuth identity) |
| T8 | **D** ReDoS through a policy regex | Patterns are refused where a rule is stored or a bundle is loaded: invalid syntax, over 512 characters, backreferences, and an unbounded `+ * {n,}` over a group that itself repeats or alternates (`(a+)+`, `(a\|aa)+`); bounded repetition over such a group stays allowed. At match time the subject is capped at 4096 characters and an unusable pattern denies instead of throwing | Implemented (`@traceguard/schemas`, `policy.ts` `regexMatches`, `regex-bound.test.ts`); residual: the caps bound the cost rather than proving linear time for every pattern inside them, and a pattern can still be super-linear — a real timeout needs worker threads. Evaluation-assertion patterns are bounded at match time but not schema-validated |
| T9 | **T** Path traversal or symlink escape in arguments | `path_within` requires a server- and tool-scoped rule plus a pinned executor attestation (`io.traceguard/path-confinement`); the gateway refuses calls when the pinned definition does not attest to executor-side enforcement, and the bundled executor resolves `realpath` and refuses targets outside its attested root | Implemented — gateway refuses un-attested or out-of-root constraints; the reference executor blocks the symlink escape (`path-enforcement.test.ts`, e2e escape case) |
| T10 | **T** Audit events edited | Hash chain in `@traceguard/audit-chain`; migration 022 rejects UPDATE/DELETE at the database layer; `POST /v1/audit/verify` recomputes every event and link. Checkpoints and pruning are operator-only: `scripts/audit-checkpoint.mts` signs with a key held outside the API/gateway containers, prunes through the exact cutoff event, and requires an explicit external receipt; only `retention_job` may execute the prune function. The v3 payload records per-workspace segment heads and the verifier reports sequence gaps and anchors a pruned prefix only from a valid signed checkpoint; `npm run audit:verify` checks an exported history offline, including the prior signed checkpoint carried by artifacts after a prune | Implemented (`signed-policy.test.ts` tamper case; integration checkpoint/anchor case; `scripts/verify-audit.mts`, `scripts/audit-checkpoint.mts`) |
| T11 | **T** Audit fork under concurrency | Transactional advisory lock around chain-head append | Implemented |
| T12 | **I** Sensitive arguments leak to logs or UI | Approval arguments encrypted, TTL-limited, deleted on terminal state; approvals carry `Cache-Control: no-store`; content capture off by default | Implemented |
| T13 | **D** OTLP flood or storage poisoning | Body/span/attribute limits, per-project rate limits, schema validation | Implemented |
| T14 | **S** Stolen API key | Hashed at rest, scoped, revocable, rate-limited | Implemented |
| T15 | **T** Duplicate external side effect after a timeout | Post-dispatch ambiguity becomes `OUTCOME_UNKNOWN`; never auto-retried; UI says the action may have executed | Implemented |
| T16 | **T** Unsigned or rolled-back policy | Only the active signed bundle is enforced: content hash, Ed25519 signature, recomputed key id, retired-key refusal, version/history agreement, and rollback/fork/history-gap detection against the gateway's own accepted-version anchor | Implemented (`policy-bundle.ts`, `signed-policy.test.ts`) |
| T17 | **S** Forged or replayed OAuth token | Access tokens are validated as JWTs against the issuer's published keys: signature (EdDSA / RS256 / ES256 only), kid lookup with bounded refetch so rotation needs no restart, issuer, canonical audience, expiry and nbf with skew, and scope mapping; the gateway serves RFC 9728 protected-resource metadata and challenges with it; the bundled client discovers that metadata plus the issuer's, sends the RFC 8707 resource indicator, checks the issuer binding, and refreshes its cached token once on a 401; production refuses to start without an issuer and stops accepting static keys | Implemented (`oauth.ts`, `oauth.test.ts`, `packages/mcp-client-shim`); residual: no introspection mode, and no interactive Authorization Code + PKCE (the shim is headless) |
| T18 | **T** UI or API compromise changes execution authority | Gateway enforces from signed bundles it verifies itself; the control surface writes drafts only and no endpoint can sign, activate, or roll back a version; approve/reject requires the approver key at the gateway listener; migrations 023, 035–039 make the denials database privileges: the gateway cannot write `approvals`, `mcp_servers`, `server_tools`, `policies`, `policy_versions`, `active_config`, `policy_signing_keys`, or audit directly; approval transitions and publisher trust/activation run through narrow `SECURITY DEFINER` procedures owned by `approval_owner`/`policy_owner`; the API cannot touch signed policy, trust state, audit, or approvals. Migration 038 adds project-scoped `AgentPrincipal` mapping for OAuth subjects, separates hashed `tgi_` ingest keys from MCP credentials, and scopes approvals, budgets, MCP server lookup, and policy decisions by project; migration 039 scopes signed versions and active pointers by project and adds project attribution to the v4 audit hash. `identity.test.ts` proves the cross-project denials, and `signed-policy.test.ts`/`chain.test.ts` cover per-project policy state and audit attribution. `apps/api/tests/db-roles.test.ts` proves the role matrix, and both deploy paths connect the services as their roles. **Open limitation:** `api_runtime` can still insert/update `users`, `api_keys`, and `memberships`, so a non-OAuth deployment can mint trusted roles | Implemented for the execution/config boundary; identity role-minting open |

## Residual limitations

- Exactly-once external effects are impossible without upstream idempotency; the
  gateway guarantees at-most-once dispatch for a given approval.
- Prompt injection is not solved. Allowed tools can still exfiltrate data the
  policy permits.
- A definition pin cannot detect a server whose code changes while its declared
  schema stays identical.
- Docker DNS isolation is not an egress firewall. The enforcement promise holds
  only when the agent runtime is network-constrained.
- An administrator who owns the host, database, and checkpoint key defeats the
  audit trail entirely.

## Release gate

No release candidate until automated tests cover, at minimum:

1. Direct agent-to-upstream connection fails; gateway-to-upstream succeeds (T1).
2. Approval replay with changed arguments or logical request id is rejected (T2).
3. Two concurrent retries produce one dispatch (T3).
4. Tool-definition drift quarantines and blocks the call (T4).
5. SSRF destinations (loopback, metadata, link-local) are rejected (T5).
6. A denied call leaves the mock upstream call count at zero (T7).
7. Expired or undecryptable approval arguments fail closed (T12).
8. Agent credentials cannot reach approval decision endpoints (T18).
9. Tampering with an audit event is detected by the verifier (T10).
10. Telemetry outage neither crashes nor blocks the agent (T13).
11. Invalid signature, rollback, or fork is rejected by the gateway (T16).
12. Wrong-issuer / wrong-audience token is rejected (T17).

Status in this tree: 1 (partial — no compose agent container), 2–4, 6–7,
9–12 are covered by `apps/api/tests` (`signed-policy.test.ts`, `pins.test.ts`,
`oauth.test.ts`, `approvals.test.ts`, `integration.test.ts`) and
`tools/policy-publisher/tests`; 5 is covered at the application layer only; 8
is covered in `integration.test.ts`. The release gate's network-segmentation
item is covered by `tests/security/bypass.mjs` (agent on `agent_edge` cannot
reach the upstream, the api, or postgres, and gets a 401 from the gateway);
the client half of FR-002 is covered by the shim's OAuth tests for the
headless flow, and interactive consent (Authorization Code + PKCE) remains a
browser-client concern rather than a gate item.
