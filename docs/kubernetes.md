# Kubernetes

Single-node friendly: one replica of everything, one 10Gi volume for
Postgres, cluster-local services only.

```bash
# Images (ghcr paths are set in kustomization.yaml, retag as needed)
docker build -f apps/api/Dockerfile -t ghcr.io/suhas-svg/traceguard-api:latest .
docker build -f apps/web/Dockerfile -t ghcr.io/suhas-svg/traceguard-web:latest .
docker build -f infra/k8s/Dockerfile.migrate -t ghcr.io/suhas-svg/traceguard-migrate:latest .
docker push ghcr.io/suhas-svg/traceguard-api:latest
docker push ghcr.io/suhas-svg/traceguard-web:latest
docker push ghcr.io/suhas-svg/traceguard-migrate:latest

# Secrets (never committed)
cp infra/k8s/secrets.example.yaml infra/k8s/secrets.yaml
# edit every change-me, generate APPROVAL_ARGS_KEY with node -e \
#   "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Check the manifests before touching a cluster (needs kubectl and pyyaml)
python infra/k8s/check.py

# Roll out in order
kubectl apply -k infra/k8s/          # namespace, secrets, postgres, migrate job
kubectl wait --for=condition=complete job/migrate -n traceguard --timeout=180s
kubectl get pods -n traceguard       # api, gateway, web come up after migrate
kubectl port-forward svc/api 8080:8080 -n traceguard &
curl http://localhost:8080/healthz
```

`infra/k8s/check.py` renders the kustomization and checks the things that silently break a
deploy: env refs that point at keys the secret template no longer has, services whose
selector matches no workload, containers without resources or probes, and env keys that
compose sets but the Deployment forgot.

What this does not do: ingress and TLS (front the web service with your
own), autoscaling (replicas are 1), pod disruption budgets, or backups.
Back up the pgdata volume on your own schedule before trusting this.

Two settings to revisit the moment you front this with ingress: set `DASHBOARD_ORIGIN`
in `configmap.yaml` to the origin that serves the dashboard — CORS rejects its calls from
any other origin — and set `ALLOW_PRIVATE_UPSTREAMS: "true"` if your upstream MCP servers
are registered by private IP (DNS names pass either way). `infra/k8s/networkpolicy.yaml` now provides the boundary: default deny plus DNS and postgres rules. `infra/k8s/check.py` validates it. This path still does not provide ingress/TLS.
