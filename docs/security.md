# Security

## What TraceGuard guarantees

- No protected tool runs without a matching allow rule or a granted, bound,
  unexpired, single-use approval — and both are read from a **signed policy
  bundle** whose content hash, Ed25519 signature, key, version, and history
  the gateway verifies first. Unsigned, tampered, rolled-back, forked, or
  retired-key versions fail closed; the gateway never enforces a draft.
- Only servers listed in the active bundle are connectable, and only tools
  whose exact reviewed definition the bundle activated are callable. A tool
  definition that changed after publication is quarantined until a new signed
  bundle carries the new pin.
- Denied calls never contact the upstream server. The security suite asserts
  this with upstream hit counters, not just status codes.
- Agent credentials cannot decide approvals. The decision endpoint takes a
  separate key and answers 403 to agent keys.
- The audit log is append-only at the database layer (UPDATE/DELETE rejected
  by trigger), hash-chained, and verifiable through `POST /v1/audit/verify`;
  a detected mutation means a database owner disabled the guard.
- Access tokens are validated as JWTs against the configured issuer's keys
  when OAuth is on (`OAUTH_ISSUER` + `OAUTH_AUDIENCE` + a JWKS source): the
  algorithm is pinned to EdDSA / RS256 / ES256, the issuer, audience,
  expiry, and nbf are checked, and a token that fails validation is never
  retried as some other credential. `NODE_ENV=production` refuses to start
  without an issuer and stops accepting the static development keys.
- Costs are estimates from provider-reported usage and versioned prices,
  never billing truth.

## Database roles

Since migration `023`, the boundary between "can enforce" and "can rewrite
policy" is a database privilege, not a convention. Six roles exist, all
`NOLOGIN` until a deployment gives them credentials:

| Role | Holds | Denied |
|---|---|---|
| `api_runtime` | reads; drafts (`policies`, `mcp_servers`); users/keys; runs, spans, budgets, evals, webhooks, retention rules; trace-data deletes | every write to `policy_versions`, `policy_signing_keys`, `active_config`; direct insert/update/delete on `audit_events`; all approval transitions (it cannot UPDATE or DELETE `approvals`) |
| `gateway_runtime` | reads of signed policy, trust keys, active config; approval transitions, decisions, pins, discovery; spans | publish or alter `policy_versions`/`active_config`/`policy_signing_keys`; direct `audit_events` DML |
| `policy_publisher` | inserts `policy_versions` and trust keys, moves the active pointer, appends audit | update/delete of `policy_versions` (the immutability trigger backs this up); any audit DML |
| `retention_job` | deletes `spans`, `runs`, terminal `approvals`, webhook deliveries; its own run bookkeeping | no privilege at all on `audit_events`, `policy_versions`, or trust state |
| `audit_owner` | owns `audit_events` and `append_audit_event`; cannot log in | runtime traffic |
| `migration_owner` | a membership target for the deployer; migrations should run as it | runtime traffic |

The append-only guarantee is now structural: runtime roles hold no `INSERT`
on `audit_events`. They call `append_audit_event(...)`, which takes the chain
lock, refuses an append that does not link to the current head (returning
`false`, so a caller's transaction survives the retry), and inserts. The hash
formula stays in `@traceguard/audit-chain`, where the verifier shares it.

Two deviations from the spec's §13.4 table, on purpose: the gateway holds
table-level `UPDATE` on `approvals` (its CAS transitions are one shape in one
file) rather than one procedure per transition, and this single-node
deployment serves the policy screens from the gateway, so `gateway_runtime`
keeps the draft writes those routes make. Tightening either is a follow-up
that does not change the denials above.

`apps/api/tests/db-roles.test.ts` proves the matrix at the database layer by
running each probe under `SET ROLE`; it fails if a grant widens.

## What it does not do

Model output truth, prompt injection in general, safety of tools called
outside the gateway, or protection when the agent can reach upstream
servers directly. Run upstreams on the internal `tools` network and the
agent on `agent_edge`: the gateway is then the only container with a foot on
both, and `tests/security/bypass.mjs` fails if that stops being true.

The `caller` and `agent_id` fields on gateway calls are attribution the
caller supplies, not authenticated identity; policy scoping on them tells
cooperative agents apart, not adversaries. Give each agent its own key when
identity must be authenticated.

## Sensitive data inventory

Raw prompts, responses, and tool arguments are not stored by default: known
content keys in span attributes are replaced with `[NOT CAPTURED]` before
persistence. Setting `CAPTURE_RAW_ATTRIBUTES=true` opts into capture (the
api logs a startup warning). Recognized secret patterns are always redacted
first, even with capture enabled: PEM private keys, `sk-…`/`sk-ant-…` API
keys, GitHub `gh[pousr]_` tokens, AWS key ids (`AKIA…`), Slack `xox…` tokens,
JWTs, and `Bearer` tokens. The same pass runs at ingest, OTLP ingestion,
evaluation replay, and gateway-denial span writes.

| Field | Handling |
|---|---|
| `spans.attributes` | content keys `[NOT CAPTURED]` unless capture is on; recognized secrets always `[REDACTED]` |
| `approvals.args` / `args_enc` | sealed with AES-256-GCM while pending; wiped on deny, expiry, and consumption |
| `approvals.args_summary` | redacted summary kept after terminal states |
| `approvals.args_hash` | canonical argument hash bound into the approval (caller, server, tool, args, logical request id, tool pin); kept |
| `policy_decisions.args_hash` | hash only; decisions never store arguments |
| `audit_events.metadata` | actions and rule ids; never tool arguments or output |
| `policy_versions.bundle` | trusted rule set, server endpoints, and pin hashes; **never** secret values — the server manifest records only how the gateway authenticates (`auth_mode`) |
| `policy_signing_keys.public_key_pem` | verification keys only; the private key lives on the operator's host and is never in PostgreSQL or a service container |
| `users.password_hash`, `api_keys.key_hash` | scrypt and SHA-256 hashes only; plaintext is never stored |

## Retention

Execution data does not live forever. Retention rules name a target
(`runs`, terminal `approvals`, `webhook_deliveries`), a maximum age in
days, and an on/off switch. `POST /v1/retention/run` executes every
enabled rule and reports per-rule deletion counts; call it from cron.
Policies, decisions, pending approvals, the audit log, and money tables
are not valid targets, and the API refuses them.

## Reporting a vulnerability

Email the repository owner with a description, reproduction steps, and the
affected version or commit. Expect an acknowledgment within 5 business days.
Do not open a public issue for an unpatched hole. See SECURITY.md.
