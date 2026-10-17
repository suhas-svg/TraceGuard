FROM node:22-alpine AS build
WORKDIR /app
COPY package.json ./
COPY apps/web/package.json ./apps/web/
RUN npm install --workspace=@traceguard/web --include-workspace-root --ignore-scripts
COPY apps/web ./apps/web
RUN npm run build --workspace=@traceguard/web

FROM nginx:alpine
COPY --from=build /app/apps/web/dist /usr/share/nginx/html
# nginx:alpine already runs its workers as the unprivileged nginx user; this
# only pins the master to a non-root uid for the k8s runAsNonRoot rule.
USER nginx
EXPOSE 80
