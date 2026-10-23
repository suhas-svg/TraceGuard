# ADR-0006: The gateway is the only path from the agent to an upstream

- Status: Accepted
- Date: 2026-10-23
- Deciders: TraceGuard maintainers
- Related: spec §6, §13.2, FR-004; `docker-compose.yml`,
  `tests/security/bypass.mjs`, `infra/k8s/networkpolicy.yaml`

## Context

Policy enforcement is meaningless if an agent can reach an upstream MCP server
directly, reach the control API, or reach PostgreSQL. The reference deployment
must make the gateway the only bridge between the agent network and the tools
network, and the security test must prove it from inside the agent container
rather than from a developer shell.

## Decision

Compose defines three networks:

- `agent_edge`: the agent and the gateway. The agent has no other network.
- `tools`: the gateway, PostgreSQL, and mock/real upstream servers. It is
  `internal: true`, so it has no host route.
- `front`: the browser, API, and gateway admin/control listener.

The gateway is the only container attached to both `agent_edge` and `tools`.
`mock-tools` publishes no host port. The human approval listener is a separate
port and, in production, stays off the agent network. The gateway re-resolves
and re-validates the upstream URL before every forward, so a DNS rebind between
registration and dispatch fails closed.

Kubernetes mirrors the same rule with `NetworkPolicy` resources: default-deny
ingress, agent egress only to the gateway, upstream ingress only from the
gateway, and no agent access to PostgreSQL or the control API.

## Consequences

- `pnpm test:security` must run inside the compose `agent` container; a host
  run proves nothing about the network topology.
- Adding a service to `agent_edge` or `tools` is a security review item, not a
  convenience change.
- Debugging an upstream from the host requires an explicit exec into the
  gateway or tools network.
- A single-network development shortcut would invalidate the bypass evidence
  and is not an accepted configuration for a release claim.

## Alternatives considered

- **One flat compose network.** Rejected: the agent could bypass the gateway
  and the bypass test would be meaningless.
- **Host-published upstream port.** Rejected: exposes the upstream outside the
  controlled network.
- **Agent-side allowlist only.** Rejected: network reachability must not depend
  on agent cooperation.
