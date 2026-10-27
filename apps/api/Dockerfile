FROM node:22-alpine
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && corepack prepare pnpm@9.15.4 --activate
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
# All workspace manifests are copied so the frozen lockfile resolves exactly
# as it does in the repository; only the API's dependency closure is installed.
COPY apps/api/package.json ./apps/api/
COPY apps/web/package.json ./apps/web/
COPY examples/demo-agent-ts/package.json ./examples/demo-agent-ts/
COPY packages/audit-chain/package.json ./packages/audit-chain/
COPY packages/canonical-json/package.json ./packages/canonical-json/
COPY packages/mcp-client-shim/package.json ./packages/mcp-client-shim/
COPY packages/policy-signing/package.json ./packages/policy-signing/
COPY packages/schemas/package.json ./packages/schemas/
COPY sdks/typescript/package.json ./sdks/typescript/
COPY tools/policy-publisher/package.json ./tools/policy-publisher/
RUN pnpm install --frozen-lockfile --ignore-scripts --filter @traceguard/api...
COPY packages/schemas ./packages/schemas
COPY packages/canonical-json ./packages/canonical-json
COPY packages/policy-signing ./packages/policy-signing
COPY packages/audit-chain ./packages/audit-chain
COPY apps/api ./apps/api
# apps/api imports these workspaces, so their dist/ must exist before its
# build; the filter follows the workspace dependency order.
RUN pnpm --filter @traceguard/api... build
# §13.3: the gateway's rollback anchor lives in GATEWAY_STATE_DIR. Create the
# mount point owned by the runtime user so a fresh named volume inherits the
# ownership instead of being root-owned and unwritable.
RUN mkdir -p /app/gateway-state && chown node:node /app/gateway-state
# Non-root: an RCE in a span parser or the MCP client should not land as uid 0.
USER node
EXPOSE 8080
CMD ["node", "apps/api/dist/index.js"]
