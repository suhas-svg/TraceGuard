FROM node:22-alpine
WORKDIR /app
COPY package.json ./
COPY packages/schemas/package.json ./packages/schemas/
COPY apps/api/package.json ./apps/api/
RUN npm install --workspaces --include-workspace-root || (npm install -g npm@11 && npm install --workspaces --include-workspace-root)
COPY packages/schemas ./packages/schemas
COPY apps/api ./apps/api
RUN npm run build --workspace=@traceguard/schemas --workspace=@traceguard/api
# Non-root: an RCE in a span parser or the MCP client should not land as uid 0.
USER node
EXPOSE 8080
CMD ["node", "apps/api/dist/index.js"]
