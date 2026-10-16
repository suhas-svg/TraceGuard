#!/usr/bin/env python3
"""Validate infra/k8s before apply: kustomize render plus cross-reference checks.

    python infra/k8s/check.py     # needs kubectl and pyyaml; no cluster required

Checks, each one a defect class this deploy path has shipped before:
  1. the kustomization renders;
  2. every secretKeyRef / configMapKeyRef key exists in secrets.example.yaml / configmap.yaml;
  3. every Service selector matches exactly one workload;
  4. every container declares resources, and every long-running container has a probe;
  5. every env key docker-compose sets for the api or gateway is set in its Deployment too,
     so the two deploy paths cannot drift apart silently.
"""
import pathlib
import subprocess
import sys

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
K8S = ROOT / "infra" / "k8s"

failures: list[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(("ok   " if ok else "FAIL ") + label + (f" — {detail}" if detail and not ok else ""))
    if not ok:
        failures.append(label)


def _pod_spec(doc: dict) -> dict:
    return (doc.get("spec", {}).get("template", {}).get("spec", {}) or {})


def containers(doc: dict) -> list[dict]:
    """Every container, init containers included, for the resources rule."""
    spec = _pod_spec(doc)
    return (spec.get("containers", []) or []) + (spec.get("initContainers", []) or [])


def main_containers(doc: dict) -> list[dict]:
    """Only containers that take probes."""
    return _pod_spec(doc).get("containers", []) or []


# 1. render
try:
    out = subprocess.run(["kubectl", "kustomize", str(K8S)],
                         capture_output=True, text=True, check=True).stdout
except (subprocess.CalledProcessError, FileNotFoundError) as err:
    print("FAIL kustomize render:", getattr(err, "stderr", err))
    sys.exit(1)
docs = [d for d in yaml.safe_load_all(out) if d]
check(f"1. render: {len(docs)} resources", len(docs) > 0)

# 2. env refs resolve
secret_keys = set(yaml.safe_load((K8S / "secrets.example.yaml").read_text())["stringData"])
cm_keys = set(yaml.safe_load((K8S / "configmap.yaml").read_text())["data"])
bad_refs = []
for doc in docs:
    for con in containers(doc):
        for env in con.get("env", []) or []:
            ref = env.get("valueFrom", {}) or {}
            for kind, known in (("secretKeyRef", secret_keys), ("configMapKeyRef", cm_keys)):
                if kind in ref and ref[kind]["key"] not in known:
                    bad_refs.append(f"{doc['metadata']['name']}/{env['name']} -> {ref[kind]['key']}")
check("2. env refs resolve", not bad_refs, "; ".join(bad_refs))

# 3. service selectors match exactly one workload
workloads = [d for d in docs if d["kind"] in ("Deployment", "StatefulSet")]
bad_sel = []
for svc in [d for d in docs if d["kind"] == "Service"]:
    sel = svc["spec"]["selector"]
    hits = [w for w in workloads
            if all(w["spec"]["template"]["metadata"]["labels"].get(k) == v for k, v in sel.items())]
    if len(hits) != 1:
        bad_sel.append(f"{svc['metadata']['name']} -> {len(hits)} workloads")
check("3. service selectors match one workload", not bad_sel, "; ".join(bad_sel))

# 4. resources and probes
for doc in docs:
    for con in containers(doc):
        name = f"{doc['kind']}/{doc['metadata']['name']}/{con['name']}"
        res = con.get("resources", {}) or {}
        check(f"4a. {name} resources", bool(res.get("requests")) and bool(res.get("limits")))
    if doc["kind"] != "Job":  # batch containers are not probed
        for con in main_containers(doc):
            name = f"{doc['kind']}/{doc['metadata']['name']}/{con['name']}"
            check(f"4b. {name} probe", bool(con.get("livenessProbe") or con.get("readinessProbe")))

# 5. compose/deployment env parity
compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]
for svc_name, k8s_name in (("api", "api"), ("gateway", "gateway")):
    compose_env = set((compose[svc_name].get("environment") or {}).keys())
    dep = next(d for d in docs if d["kind"] == "Deployment" and d["metadata"]["name"] == k8s_name)
    dep_env = {e["name"] for con in containers(dep) for e in con.get("env", []) or []}
    missing = sorted(compose_env - dep_env)
    check(f"5. {k8s_name} sets every compose env", not missing, "missing: " + ", ".join(missing))

print()
if failures:
    print(f"{len(failures)} check(s) failed")
    sys.exit(1)
print("all checks passed")
