# Compatibility matrix

What this build actually supports, and what it does not. Everything listed as
"not supported" is rejected rather than best-effort.

| Integration / protocol | Status | Conditions / limitations |
|---|---|---|
| MCP client to gateway, Streamable HTTP revision `2026-07-28` | Supported (subset) | `server/discover`, `tools/list`, `tools/call` only. Per-request `_meta.io.modelcontextprotocol/protocolVersion` and `clientCapabilities` are required; `MCP-Protocol-Version`, `Mcp-Method` and (for `tools/call`) `Mcp-Name` headers must match the JSON-RPC body. `tools/list` returns namespaced `alias__tool` names with `ttlMs`, `cacheScope`, `resultType: "complete"`. Everything else - resources, prompts, subscriptions, sampling, elicitation, roots, Tasks, Apps, unknown methods - is rejected and never forwarded. No server-initiated stream (GET returns 405). |
| Approval retry contract | Supported (in-gateway) | `tools/call` retries match a durable approval by `_meta.io.traceguard/logical_request_id` + authenticated caller. A call that needs approval without that metadata is refused with `APPROVAL_CLIENT_REQUIRED`. The certified client shim (`packages/mcp-client-shim`) is not yet published; the contract is versioned as `approval-client-profile: 1` when it lands. |
| MCP upstream server, Streamable HTTP | Supported | Registered servers only; egress allowlist, destination checks at register/discover/call, gateway-owned upstream credentials. Definitions are pinned and drift quarantines the tool. |
| MCP stdio upstream | Not supported | Unrepresentable in the schema and rejected; the gateway never spawns local processes. |
| Older MCP protocol revisions | Not certified | The gateway requires `2026-07-28` and rejects other versions with an explicit error. |
| OAuth-protected MCP access (RFC 9728 / RFC 8707) | Not yet implemented | Current auth is static bearer keys (`API_KEY` / `APPROVER_KEY` or scoped `api_keys` rows). The OAuth 2.1 resource-server behaviour is planned; until then the deployment is a development profile and must not be exposed. |
| Static development bearer tokens | Dev profile only | No production mode that refuses them exists yet; that gate lands with the OAuth work. |
| OTLP/HTTP traces, protobuf encoding | Supported | Trace signal only; batching and per-project limits apply (see `docs/security.md`). |
| OTLP/HTTP JSON | Supported (extra) | Not required by the target; accepted for convenience. |
| OTLP/gRPC | Not supported directly | A Collector can translate to the OTLP/HTTP endpoint. |
| OpenTelemetry GenAI attributes | Best-effort mapping | A documented subset maps to columns; unknown attributes are bounded and never treated as security inputs. |
| Provider token usage | Supported when present | Missing usage or unknown price yields `NULL`, never zero. |
| @modelcontextprotocol/sdk | `^1.32.1` | Used as the upstream client only; the agent-facing surface is implemented in `apps/api/src/mcp.ts`, not by the SDK server classes. Exact-version pinning and a protocol compatibility test land with the signed-policy work. |
