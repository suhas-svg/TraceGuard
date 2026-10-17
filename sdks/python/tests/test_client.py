"""Python SDK tests: telemetry fails open, budget checks fail closed.

The fake control plane is a stdlib HTTP server so the SDK's urllib-based
transport is exercised end to end without any dependencies.
"""

from __future__ import annotations

import json
import queue
import socketserver
import threading
import time
import urllib.error
from http.server import BaseHTTPRequestHandler

import pytest

from traceguard.client import BudgetExceeded, BudgetGuard, TraceGuardClient


class _Handler(BaseHTTPRequestHandler):
    """Records every request and answers from the backend's scripted plan."""

    def do_POST(self) -> None:  # noqa: N802 - stdlib hook name
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        body = json.loads(raw or b"{}")
        self.server.requests.append(
            {"path": self.path, "body": body, "auth": self.headers.get("Authorization")}
        )
        status, payload = self.server.response_for(self.path, body)
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args) -> None:  # keep test output quiet
        pass


class _Backend(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.requests: list = []
        # Scripted per-path responses; tests override before calling in.
        self.response_for = lambda path, body: (200, {"ok": True})


@pytest.fixture()
def backend():
    server = _Backend()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture()
def base_url(backend):
    host, port = backend.server_address
    return f"http://{host}:{port}"


def ingest_events(backend) -> list:
    """Flatten every event the server received on the ingest endpoint."""
    events = []
    for req in backend.requests:
        if req["path"] == "/v1/ingest/events":
            events.extend(req["body"].get("events", []))
    return events


def test_emit_flushes_a_whole_run_with_auth(base_url, backend):
    backend.response_for = lambda path, body: (200, {"accepted": len(body.get("events", []))})
    client = TraceGuardClient(base_url, "secret-key", agent_name="unit-agent")
    run_id = client.start_run()
    assert run_id
    span = client.model_event(run_id, provider="openai", model="gpt-x", input_tokens=7, output_tokens=3)
    assert span
    client.end_run(run_id, ok=True)
    client.flush(timeout=10)

    events = ingest_events(backend)
    types = [e["event_type"] for e in events]
    assert types.count("run.started") == 1
    assert types.count("model.request") == 1
    assert types.count("run.completed") == 1
    started = next(e for e in events if e["event_type"] == "run.started")
    assert started["schema_version"] == "1"
    # Zod's datetime() only accepts the Z suffix, never +00:00.
    assert started["timestamp"].endswith("Z")
    assert started["run_id"] == run_id
    assert all(r["auth"] == "Bearer secret-key" for r in backend.requests)


def test_emit_and_flush_never_raise_when_the_endpoint_is_down():
    client = TraceGuardClient("http://127.0.0.1:9", "k", agent_name="down-agent")
    run_id = client.start_run()
    client.model_event(run_id, input_tokens=1, output_tokens=1)
    client.end_run(run_id, ok=False)
    client.flush(timeout=2)  # failures are swallowed by design


def test_emit_drops_instead_of_blocking_when_the_queue_is_full(base_url, backend):
    backend.response_for = lambda path, body: (200, {"accepted": len(body.get("events", []))})
    client = TraceGuardClient(base_url, "k")
    # A tiny queue stands in for a flood: the drop path must not raise and
    # must not stall the caller.
    client._queue = queue.Queue(maxsize=1)
    kept = {"schema_version": "1", "event_id": "evt-kept", "run_id": "r", "span_id": "s",
            "event_type": "run.started", "timestamp": "2026-01-01T00:00:00.000Z", "attributes": {}}
    client._queue.put_nowait(kept)
    dropped = {**kept, "event_id": "evt-dropped"}
    client.emit(dropped)  # Full: dropped silently
    client.flush(timeout=10)

    ids = [e["event_id"] for e in ingest_events(backend)]
    assert ids == ["evt-kept"]


def test_emit_keeps_one_sender_under_a_slow_endpoint(base_url, backend):
    # A blocking endpoint used to cost one live thread per event, each holding
    # its payload until flush. The bound must hold the sender count down.
    release = threading.Event()

    def slow(path, body):
        release.wait(timeout=10)
        return 200, {"ok": True}

    backend.response_for = slow
    client = TraceGuardClient(base_url, "k")
    baseline = threading.active_count()
    try:
        for i in range(50):
            client.emit({"schema_version": "1", "event_id": f"evt-{i}", "run_id": "r",
                         "span_id": "s", "event_type": "run.started",
                         "timestamp": "2026-01-01T00:00:00.000Z", "attributes": {}})
        assert threading.active_count() - baseline < 20
    finally:
        release.set()
    client.flush(timeout=20)
    assert len(ingest_events(backend)) == 50


def test_budget_guard_reserves_then_settles(base_url, backend):
    def plan(path, body):
        if path == "/v1/budgets/check":
            return 200, {"ok": True, "reservation_id": "res-1", "remaining_micro": 5}
        if path == "/v1/budgets/settle":
            return 200, {"ok": True, "actual_cost_micro": body.get("actual_cost_micro")}
        return 404, {"error": "not_found"}

    backend.response_for = plan
    guard = BudgetGuard(TraceGuardClient(base_url, "k"), "budget-1")
    reservation = guard.reserve(100, ttl_seconds=5)
    assert reservation == "res-1"
    guard.settle(reservation, actual_cost_micro=42)
    paths = [r["path"] for r in backend.requests]
    assert paths == ["/v1/budgets/check", "/v1/budgets/settle"]
    assert backend.requests[0]["body"]["max_cost_micro"] == 100
    assert backend.requests[1]["body"]["actual_cost_micro"] == 42


def test_budget_guard_fails_closed_on_a_denial(base_url, backend):
    backend.response_for = lambda path, body: (409, {"error": "budget_exceeded"})
    guard = BudgetGuard(TraceGuardClient(base_url, "k"), "budget-1")
    with pytest.raises(BudgetExceeded):
        guard.reserve(100)


def test_budget_guard_fails_closed_when_the_server_is_unreachable():
    guard = BudgetGuard(TraceGuardClient("http://127.0.0.1:9", "k"), "budget-1")
    with pytest.raises((urllib.error.URLError, OSError)):
        guard.reserve(100)
