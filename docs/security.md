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
- Agent credentials cannot decide approvals. The queue and decision endpoints
  live on the gateway's separate control listener (`GATEWAY_CONTROL_PORT`,
  default 8093) rather than the agent-facing port; the approve scope is
  required there — no `admin` shortcut — and agent, read-scope, and plain
  admin keys answer 403.
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

Since migration `023`, with the later tightening in `035`–`039`, the boundary
between "can enforce" and "can rewrite policy" is a database privilege, not a
convention. Eight roles exist, all `NOLOGIN` until a deployment gives them
credentials:

| Role | Holds | Denied |
|---|---|---|
| `api_runtime` | reads; control-plane drafts (`policies`, `mcp_servers`, `server_tools`); projects, agent principals, ingest keys; users/keys/memberships; runs, spans, budgets, evals, webhooks, retention rules; trace-data deletes | every write to `policy_versions`, `policy_signing_keys`, `active_config`; direct insert/update/delete on `audit_events`; all approval writes |
| `gateway_runtime` | reads of signed policy, trust keys, active config, projects, principals; approval procedures, decisions, discovery; spans | publish or alter `policy_versions`/`active_config`/`policy_signing_keys`; server, pin, or policy writes; direct `approvals` or `audit_events` DML |
| `policy_publisher` | inserts `policy_versions`; executes `policy_trust_key`/`policy_activate_version`; appends audit | update/delete of `policy_versions` (the immutability trigger backs this up); direct trust or active-pointer writes; any audit DML |
| `retention_job` | deletes `spans`, `runs`, webhook deliveries; its own run bookkeeping; executes the checkpoint-gated audit prune | approval deletes; ordinary audit DML; `policy_versions` or trust-state writes |
| `approval_owner` | owns the approval procedures and tables; cannot log in | runtime traffic |
| `policy_owner` | owns the trust/activation procedures and `lock_active_config_share`; cannot log in | runtime traffic |
| `audit_owner` | owns `audit_events` and `append_audit_event`; cannot log in | runtime traffic |
| `migration_owner` | a membership target for the deployer; migrations should run as it | runtime traffic |

The append-only guarantee is structural: runtime roles hold no `INSERT` on
`audit_events`. They call `append_audit_event(...)`, which takes the chain
lock, refuses an append that does not link to the current head (returning
`false`, so a caller's transaction survives the retry), and inserts. New
events use v4 hashes with workspace and project attribution; v1–v3 hashes
remain byte-identical for old rows. The hash formula stays in
`@traceguard/audit-chain`, where the verifier shares it.

The remaining deviation from the spec's §13.4 table is the local identity
path: `api_runtime` can still insert/update `users`, `api_keys`, and
`memberships`, so a non-OAuth deployment can mint trusted roles. Removing
that path is tracked as an open identity workstream, not a hidden exception.

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
(`runs`, `spans`, terminal `approvals`, `webhook_deliveries`), a maximum
age in days, an optional row cap for whole traces, and an on/off switch.
`POST /v1/retention/run` executes every enabled rule and reports per-rule
deletion counts; call it from cron. A span target prunes whole traces —
never single spans — and the seeded `default-span-retention` keeps 7 days
or 100,000 spans, whichever comes first. Policies, decisions, pending
approvals, the audit log, and money tables are not valid targets, and the
API refuses them.

## Reporting a vulnerability

Email the repository owner with a description, reproduction steps, and the
affected version or commit. Expect an acknowledgment within 5 business days.
Do not open a public issue for an unpatched hole. See SECURITY.md.
