# Threat model outline (early deliverable, per review)

Assets: stored traces, policy rules, approval decisions, audit events, upstream MCP credentials, API keys.

Actors: agent with ingest key, dashboard admin, approver, upstream tool server, local operator with host access.

Trust boundaries: agent to API (bearer key, validation, size limits), dashboard to API (separate admin session, never reuse ingest key), gateway to upstream (gateway holds credentials, agent never sees them), agent to upstream (must be impossible on the internal network, enforced by Docker network, not by asking).

Abuse cases for the security suite: unregistered tool call, denied call with upstream spy asserting no contact, approval replay with same ID, expired approval, tampered policy version, direct upstream connection attempt from agent network.

Guarantee: no protected tool runs without a matching allow or approval. Out of scope: model output truth, prompt injection in general, anything that bypasses the gateway.
