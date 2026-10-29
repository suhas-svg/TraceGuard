# ADR-0010: The gateway alone resolves upstream credentials

- Status: Accepted
- Date: 2026-10-28
- Implemented: 2026-10-29
- Deciders: TraceGuard maintainers
- Related: spec §7.3, §7.4; ADR-0004, ADR-0006; `apps/api/src/secret-ref.ts`,
  `apps/api/src/admin.ts`, `apps/api/src/gateway.ts`, `docker-compose.yml`,
  `infra/k8s/`

## Context

The specification puts upstream credentials under the gateway's control: the
gateway "resolves an independent upstream credential from the configured secret
source and injects only that credential" (§7.3), and a new server's first
signed bundle may authorize discovery only (§7.4). The database stores a
reference (`env:NAME` or `file:/absolute/path`) and never the value; the value
is resolved at the point of use and a missing reference fails closed.

That holds for tool calls: `apps/api/src/gateway.ts` resolves the reference
immediately before `callUpstreamTool` and never persists, returns, or logs the
value.

It does not hold for discovery. `POST /v1/servers/:id/discover` and
`POST /v1/mcp-servers/:id/refresh-tools` run in the API and call
`discoverTools` directly, so `apps/api/src/admin.ts` resolves the same
reference out of the API process environment or filesystem. An operator who
wants discovery to work must provision the upstream credential to the API
container as well as the gateway. That is two credential holders for one
upstream, and the API has no other use for the value. A compromise of the
control API, a heap dump, or an error path that prints the process environment
exposes an upstream credential that only the gateway should be able to read.

`docs/spec-conformance.md` records this as the remaining follow-up: "the API
still resolves `secret_ref` for the admin discovery call (it is never persisted
or returned), so full gateway-only credential custody remains a follow-up."

The discovery network call itself is legitimate for the gateway: it already
owns the egress path to upstreams, the DNS-rebinding and private-destination
checks, and the credential. What is missing is the control-plane path that lets
the API ask for discovery results without ever holding the credential.

## Decision

Move discovery behind the gateway's custody boundary. The API keeps
authorization, pinning, quarantine, and auditing; the gateway keeps the
credential and the upstream connection.

1. **Dedicated internal listener.** Add `buildGatewayInternal()` on
   `GATEWAY_INTERNAL_PORT` (default 8094). It joins only the `front` network
   (API to gateway), is never published on the host, and is never attached to
   `agent_edge` or `tools`. It is separate from the agent-facing listener
   (8091) and the human control listener (8093).

2. **Service authentication.** API and gateway share `GATEWAY_INTERNAL_TOKEN`.
   The internal listener compares it in constant time and refuses to start when
   the variable is unset. The Compose reference uses a development default;
   Kubernetes reads it from `traceguard-secrets`. The token only authorizes the
   internal discovery route, never an agent, approval, or admin route.

3. **Internal route.** `POST /internal/v1/servers/:id/discover`, no request
   body. The gateway reads the `mcp_servers` row itself with `gateway_runtime`
   (SELECT only), refuses a disabled server, re-runs the resolved-URL check at
   connect time, resolves `secret_ref` in the gateway process, calls
   `discoverTools`, and returns only the normalized tool definitions and a
   duration. The credential, the `Authorization` header, and any upstream
   response header are never returned or logged.

4. **Error mapping.** The gateway answers `404 server_not_found`,
   `409 server_disabled`, `400 unsafe_upstream`, `503 secret_unavailable`,
   `504 discovery_timeout`, or `502 discovery_failed`. The API maps them to its
   existing route errors so the dashboard behavior does not change.

5. **API side.** Both admin routes keep their authentication, workspace and
   project scope checks, and the entire pin/quarantine write path. They replace
   the direct upstream call with an HTTP request to `GATEWAY_INTERNAL_URL`
   bounded by a 15 second timeout. `apps/api/src/admin.ts` no longer imports
   `resolveSecretRef` or `discoverTools`; `secret-ref.ts` is imported only by
   the gateway. When `GATEWAY_INTERNAL_URL` is unset or the gateway is
   unreachable, discovery returns `503 discovery_unavailable`. There is no
   direct-upstream fallback: a missing internal path must fail closed rather
   than silently restore the custody hole.

6. **Deployment.** The API gains `GATEWAY_INTERNAL_URL`; API and gateway gain
   `GATEWAY_INTERNAL_TOKEN`. The Kubernetes gateway Service and NetworkPolicy
   expose 8094 to the API pods only. Compose keeps 8094 on the `front` network
   without a host port.

7. **Tests.** The API suite already builds the gateway in-process. The shared
   test setup starts it on an ephemeral loopback port and sets
   `GATEWAY_INTERNAL_URL` and the token, so discovery tests exercise the real
   boundary instead of a stub. New cases cover a missing or wrong token, an
   unreachable gateway, an unset secret reference, a disabled server, an unsafe
   URL, and the existing pin/quarantine behavior.

## Consequences

- An upstream credential exists only in the gateway container's environment or
  mounted secret. The API image can run with no upstream credential at all,
  which is what "gateway-owned" should mean operationally.
- Discovery now depends on the gateway being up. The gateway is already a hard
  dependency for tool calls and is health-checked; while it is down the API
  returns `503 discovery_unavailable` instead of pretending discovery worked.
- One more port and a shared token need provisioning and rotation. Rotation
  means updating both services and restarting them; the runbook must say so.
- The internal listener must never be published, and must never join the agent
  or upstream networks. The manifest checks in `infra/k8s/check.py` and the
  Compose review should assert the network and port posture.
- No database migration: the schema still stores only references, and the
  discovery result shape is unchanged.

## Alternatives considered

- **Keep API-side resolution and document a waiver.** Rejected: it leaves two
  holders of every upstream credential, contradicts the §7.3 gateway-owned
  model, and keeps the conformance gap open for a purely operational
  convenience.
- **Move discovery, pinning, and quarantine into the gateway.** Rejected: the
  gateway deliberately has no trusted-state write privileges; pin transitions
  run through `policy_owner` procedures (ADR-0004). Widening the gateway's role
  to write pins would weaken the boundary this ADR is trying to strengthen.
- **Keep an encrypted secret store that the API reads, with decryption in the
  gateway.** Rejected: the API would still receive or hold plaintext at some
  point, and the extra key management buys nothing over moving the call.
- **mTLS or SPIFFE identities instead of a shared token.** Deferred, not
  rejected: a constant-time token over a private `front` network is
  proportionate for 1.0. Revisit when the API and gateway are deployed across
  trust zones or a service-mesh identity is available.

## Implementation plan

1. Add `buildGatewayInternal()` with the token check and the discovery route,
   reusing `discoverTools` and `checkUpstreamUrlResolved`.
2. Add an API-side `discoverViaGateway()` client and switch both admin routes;
   remove the API's secret resolution import.
3. Plumb configuration: `docker-compose.yml`, `infra/k8s/gateway.yaml`,
   `api.yaml`, `secrets.example.yaml`, `networkpolicy.yaml`, `.env.example`,
   `docs/configuration.md`.
4. Update `docs/security.md` and `docs/spec-conformance.md`; change this ADR to
   Accepted when the code lands.
5. Run the full local matrix, including the e2e and fault suites, and merge as
   its own change.

## Revisit triggers

- `front` stops being a private network, or the API and gateway are deployed in
  different trust zones.
- Another control-plane service needs discovery (the internal route should not
  become a general-purpose upstream proxy).
- The secret backend changes the reference model (for example Vault-issued
  short-lived credentials), which may remove the file/env indirection.
- mTLS or workload identity becomes available and the shared token can be
  retired.
