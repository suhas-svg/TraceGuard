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

## Reporting a vulnerability

Email the repository owner with a description, reproduction steps, and the
affected version or commit. Expect an acknowledgment within 5 business days.
Do not open a public issue for an unpatched hole. See SECURITY.md.
