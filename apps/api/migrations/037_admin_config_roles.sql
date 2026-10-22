-- §5.3/§13.4: the gateway enforces active configuration; it does not edit
-- servers, tool pins, or policies. Migration 023 let it do so because the
-- admin routes lived in gateway.ts. Those routes now run in the API process,
-- so move the write grants to api_runtime and take them away from the gateway.
BEGIN;

GRANT INSERT, UPDATE ON mcp_servers, server_tools TO api_runtime;
REVOKE INSERT, UPDATE ON mcp_servers, server_tools, policies FROM gateway_runtime;

COMMIT;
