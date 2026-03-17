from __future__ import annotations

import pytest
import shared.orchestrator as shared_orchestrator
from shared.orchestrator import ScanOrchestrator


class FakeApiClient:
    def __init__(self) -> None:
        self.calls = []

    def start_scan(self, **kwargs):
        self.calls.append(("start_scan", kwargs))
        return "scan-1"

def test_run_polling_loop_repeats_until_interrupted(monkeypatch: pytest.MonkeyPatch) -> None:
    handled = []
    sleeps = []

    def poll_once() -> bool:
        handled.append(True)
        return False

    def fake_sleep(seconds: int) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise KeyboardInterrupt()

    monkeypatch.setattr(shared_orchestrator.time, "sleep", fake_sleep)

    with pytest.raises(KeyboardInterrupt):
        shared_orchestrator.run_polling_loop(poll_once, interval_seconds=7)

    assert len(handled) == 1
    assert sleeps == [1, 1]


def test_run_polling_loop_stops_cleanly_when_stop_requested(monkeypatch: pytest.MonkeyPatch) -> None:
    handled = []
    stop_requested = {"value": False}

    def poll_once() -> bool:
        handled.append(True)
        return False

    def fake_sleep(seconds: int) -> None:
        assert seconds == 1
        stop_requested["value"] = True

    monkeypatch.setattr(shared_orchestrator.time, "sleep", fake_sleep)

    shared_orchestrator.run_polling_loop(
        poll_once,
        interval_seconds=7,
        should_stop=lambda: stop_requested["value"],
    )

    assert len(handled) == 1


def test_orchestrator_start_scan_maps_trigger_mode_to_request_source() -> None:
    api_client = FakeApiClient()
    orchestrator = ScanOrchestrator(config=None, api_client=api_client)

    result = orchestrator.start_scan(scanner_type="aws", trigger_mode="manual")

    assert result == "scan-1"
    assert api_client.calls == [
        ("start_scan", {"scanner_type": "aws", "request_source": "manual"})
    ]


def test_orchestrator_removes_worker_start_fallback_and_error_reporting() -> None:
    assert not hasattr(ScanOrchestrator, "bind_or_start_scan")
    assert not hasattr(ScanOrchestrator, "report_error")
    assert not hasattr(ScanOrchestrator, "handle_failure")
