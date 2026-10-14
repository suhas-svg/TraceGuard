# Security

## What TraceGuard guarantees

- No protected tool runs without a matching allow rule or a granted, bound,
  unexpired, single-use approval.
- Denied calls never contact the upstream server. The security suite asserts
  this with upstream hit counters, not just status codes.
- Agent credentials cannot decide approvals. The decision endpoint takes a
  separate key and answers 401 to agent keys.
- Costs are estimates from provider-reported usage and versioned prices,
  never billing truth.

## What it does not do

Model output truth, prompt injection in general, safety of tools called
outside the gateway, or protection when the agent can reach upstream
servers directly. Run upstreams on the internal tools network.

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
