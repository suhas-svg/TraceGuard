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
    # Zod's datetime() parser wants a Z suffix, not +00:00.
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


@dataclass
class TraceGuardClient:
    base_url: str
    api_key: str
    agent_name: str = "demo-agent"
    workspace_name: str = "default"
    _queue: queue.Queue = field(default_factory=lambda: queue.Queue(maxsize=500), init=False)
    _threads: list = field(default_factory=list, init=False)

    def _post(self, payload: dict) -> None:
        # Background thread, so a generous timeout only delays flush, never
        # the agent. Local disks can stall a first write for seconds.
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
            urllib.request.urlopen(req, timeout=30).read()
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
            self._threads.append(t)

    def flush(self, timeout: float = 10) -> None:
        """Wait for queued events to send. Call before process exit,
        otherwise daemon sender threads die with unsent events."""
        for t in self._threads:
            t.join(timeout=max(0.1, timeout / max(1, len(self._threads))))
        self._threads = [t for t in self._threads if t.is_alive()]

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


class BudgetExceeded(Exception):
    pass


class BudgetGuard:
    """Managed model-call wrapper. Checks the budget before the provider call
    and settles to the measured cost after. Fails closed: any check error or
    denial raises instead of calling the provider."""

    def __init__(self, client: TraceGuardClient, budget_id: str):
        self.client = client
        self.budget_id = budget_id

    def _api(self, path: str, payload: dict) -> tuple[int, dict]:
        # Generous timeout: local Docker disks can stall a first write for
        # seconds (seen 5-13s on this box). Telemetry stays fire-and-forget.
        req = urllib.request.Request(
            self.client.base_url.rstrip("/") + path,
            data=json.dumps(payload).encode(),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.client.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as res:
                return res.status, json.loads(res.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.loads(e.read() or b"{}")
            except Exception:
                return e.code, {}

    def reserve(self, max_cost_micro: int, ttl_seconds: int = 300) -> str:
        status, body = self._api(
            "/v1/budgets/check",
            {"budget_id": self.budget_id, "max_cost_micro": max_cost_micro,
             "ttl_seconds": ttl_seconds},
        )
        if status != 200:
            raise BudgetExceeded(body.get("error", f"budget check failed: {status}"))
        return body["reservation_id"]

    def settle(self, reservation_id: str, actual_cost_micro: int | None = None) -> None:
        self._api("/v1/budgets/settle",
                  {"reservation_id": reservation_id, "actual_cost_micro": actual_cost_micro})
