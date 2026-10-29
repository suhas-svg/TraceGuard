FROM node:22-alpine AS build
ENV COREPACK_ENABLE_DOWNLOAD_PROMPT=0
RUN corepack enable && corepack prepare pnpm@9.15.4 --activate
WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml .npmrc ./
# All workspace manifests are copied so the frozen lockfile resolves exactly
# as it does in the repository; only the web dependency closure is installed.
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
RUN pnpm install --frozen-lockfile --ignore-scripts --filter @traceguard/web...
COPY apps/web ./apps/web
RUN pnpm --filter @traceguard/web build

FROM nginx:alpine
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
# Unprivileged listener: the image runs as nginx (runAsNonRoot), and :80
# cannot bind without root. The k8s Service keeps port 80 externally.
COPY apps/web/nginx.conf /etc/nginx/conf.d/default.conf
# The base image keeps /var/cache/nginx and the pid path root-owned, so an
# unprivileged master cannot even create its temp dirs. Hand them over.
RUN chown -R nginx:nginx /var/cache/nginx && touch /var/run/nginx.pid && chown nginx:nginx /var/run/nginx.pid
# nginx:alpine already runs its workers as the unprivileged nginx user; this
# only pins the master to a non-root uid for the k8s runAsNonRoot rule.
USER nginx
EXPOSE 80
