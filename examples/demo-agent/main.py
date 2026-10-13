"""Reference agent for Phase 1 exit criterion: submit events, retrieve the run."""

import os
import time
import urllib.request
import json
from traceguard.client import TraceGuardClient

BASE = os.environ.get("TRACEGUARD_URL", "http://localhost:8080")
KEY = os.environ.get("TRACEGUARD_API_KEY", "dev_key_change_me")

client = TraceGuardClient(BASE, KEY)
run_id = client.start_run()
print("run:", run_id)
client.model_event(run_id, provider="demo", model="demo-1",
                   input_tokens=1200, output_tokens=240,
                   attributes={"note": "no prompt text stored by default"})
time.sleep(1)  # let background sender flush
client.end_run(run_id, ok=True)
time.sleep(1)

req = urllib.request.Request(
    f"{BASE}/v1/runs/{run_id}/trace",
    headers={"Authorization": f"Bearer {KEY}"},
)
print(json.dumps(json.loads(urllib.request.urlopen(req, timeout=5).read()), indent=2)[:2000])
