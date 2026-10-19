FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY packages/schemas/package.json ./packages/schemas/
COPY packages/canonical-json/package.json ./packages/canonical-json/
COPY packages/policy-signing/package.json ./packages/policy-signing/
COPY packages/audit-chain/package.json ./packages/audit-chain/
COPY apps/api/package.json ./apps/api/
RUN npm install --workspaces --include-workspace-root || (npm install -g npm@11 && npm install --workspaces --include-workspace-root)
COPY packages/schemas ./packages/schemas
COPY packages/canonical-json ./packages/canonical-json
COPY packages/policy-signing ./packages/policy-signing
COPY packages/audit-chain ./packages/audit-chain
COPY apps/api ./apps/api
# apps/api imports these workspaces, so their dist/ must exist before its
# build; the order below is their dependency order.
RUN npm run build --workspace=@traceguard/schemas --workspace=@traceguard/canonical-json --workspace=@traceguard/policy-signing --workspace=@traceguard/audit-chain --workspace=@traceguard/api
# §13.3: the gateway's rollback anchor lives in GATEWAY_STATE_DIR. Create the
# mount point owned by the runtime user so a fresh named volume inherits the
# ownership instead of being root-owned and unwritable.
RUN mkdir -p /app/gateway-state && chown node:node /app/gateway-state
# Non-root: an RCE in a span parser or the MCP client should not land as uid 0.
USER node
EXPOSE 8080
CMD ["node", "apps/api/dist/index.js"]
