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

# Roll out in order
kubectl apply -k infra/k8s/          # namespace, secrets, postgres, migrate job
kubectl wait --for=condition=complete job/migrate -n traceguard --timeout=180s
kubectl get pods -n traceguard       # api, gateway, web come up after migrate
curl http://<api-ip>:8080/healthz
```

What this does not do: ingress and TLS (front the web service with your
own), autoscaling (replicas are 1), pod disruption budgets, or backups.
Back up the pgdata volume on your own schedule before trusting this.
