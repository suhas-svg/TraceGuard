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
- Costs are estimates from provider-reported usage and versioned prices,
  never billing truth.

## What it does not do

Model output truth, prompt injection in general, safety of tools called
outside the gateway, or protection when the agent can reach upstream
servers directly. Run upstreams on the internal tools network.

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
