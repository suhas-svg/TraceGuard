"""Reference agent: submit events, retrieve the run."""

import os
import urllib.request
import json
from traceguard.client import TraceGuardClient

BASE = os.environ.get("TRACEGUARD_URL", "http://localhost:8090")
KEY = os.environ.get("TRACEGUARD_API_KEY", "dev_key_change_me")

client = TraceGuardClient(BASE, KEY)
run_id = client.start_run()
print("run:", run_id)
client.model_event(run_id, provider="demo", model="demo-1",
                   input_tokens=1200, output_tokens=240,
                   attributes={"note": "no prompt text stored by default"})
client.end_run(run_id, ok=True)
client.flush(timeout=60)

# The compose agent can reach only the gateway (FR-004), so reading the trace
# over that network would not work. Print the trace when the API is directly
# reachable (the host path above), otherwise point at the dashboard and exit 0.
try:
    req = urllib.request.Request(
        f"{BASE}/v1/runs/{run_id}/trace",
        headers={"Authorization": f"Bearer {KEY}"},
    )
    print(json.dumps(json.loads(urllib.request.urlopen(req, timeout=30).read()), indent=2)[:2000])
except Exception:
    print(f"trace: http://localhost:5173/#/runs/{run_id}")
