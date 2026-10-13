"""Phase 1 SDK. Stdlib only, telemetry never crashes the agent (fails open)."""

from __future__ import annotations

import json
import queue
import threading
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class TraceGuardClient:
    base_url: str
    api_key: str
    agent_name: str = "demo-agent"
    workspace_name: str = "default"
    _queue: queue.Queue = field(default_factory=lambda: queue.Queue(maxsize=500), init=False)

    def _post(self, payload: dict) -> None:
        try:
            req = urllib.request.Request(
                self.base_url.rstrip("/") + "/v1/ingest/events",
                data=json.dumps(payload).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}",
                },
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5).read()
        except Exception:
            pass  # telemetry fails open by design

    def emit(self, event: dict) -> None:
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            pass  # bounded queue drops oldest pressure instead of blocking
        events = []
        while not self._queue.empty():
            events.append(self._queue.get_nowait())
        if events:
            t = threading.Thread(target=self._post, args=({"events": events},), daemon=True)
            t.start()

    def start_run(self, run_id: str | None = None) -> str:
        run_id = run_id or str(uuid.uuid4())
        root = str(uuid.uuid4())
        self.emit(
            {
                "schema_version": "1",
                "event_id": f"evt-{uuid.uuid4()}",
                "workspace_name": self.workspace_name,
                "agent_name": self.agent_name,
                "run_id": run_id,
                "span_id": root,
                "parent_span_id": None,
                "event_type": "run.started",
                "timestamp": _now(),
                "status": "success",
                "attributes": {},
            }
        )
        return run_id

    def model_event(self, run_id: str, parent_span: str | None = None, **kw) -> str:
        span = str(uuid.uuid4())
        self.emit(
            {
                "schema_version": "1",
                "event_id": f"evt-{uuid.uuid4()}",
                "workspace_name": self.workspace_name,
                "agent_name": self.agent_name,
                "run_id": run_id,
                "span_id": span,
                "parent_span_id": parent_span,
                "event_type": "model.request",
                "timestamp": _now(),
                "status": kw.get("status", "success"),
                "provider": kw.get("provider"),
                "model": kw.get("model"),
                "input_tokens": kw.get("input_tokens"),
                "output_tokens": kw.get("output_tokens"),
                "usage_source": kw.get("usage_source", "provider_reported"),
                "attributes": kw.get("attributes", {}),
            }
        )
        return span

    def end_run(self, run_id: str, ok: bool = True) -> None:
        self.emit(
            {
                "schema_version": "1",
                "event_id": f"evt-{uuid.uuid4()}",
                "workspace_name": self.workspace_name,
                "agent_name": self.agent_name,
                "run_id": run_id,
                "span_id": str(uuid.uuid4()),
                "parent_span_id": None,
                "event_type": "run.completed" if ok else "run.failed",
                "timestamp": _now(),
                "status": "success" if ok else "failed",
                "attributes": {},
            }
        )
