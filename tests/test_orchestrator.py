from __future__ import annotations

from shared.orchestrator import ScanOrchestrator
import pytest
import shared.orchestrator as shared_orchestrator


class FakeApiClient:
    def __init__(self) -> None:
        self.calls = []

    def report_error(self, message: str, detail=None) -> None:
        self.calls.append((message, detail))

    def start_scan(self, **kwargs):
        self.calls.append(("start_scan", kwargs))
        return "scan-1"


def test_orchestrator_handle_failure_reports_once() -> None:
    api_client = FakeApiClient()
    orchestrator = ScanOrchestrator(config=None, api_client=api_client)
    exc = RuntimeError("upload failed")

    orchestrator.handle_failure(exc, phase="upload", detail={"scanner_type": "aws"})
    orchestrator.handle_failure(exc, phase="upload", detail={"scanner_type": "aws"})

    assert len(api_client.calls) == 1
    message, detail = api_client.calls[0]
    assert message == "Scan failed during upload: upload failed"
    assert detail["phase"] == "upload"
    assert detail["scanner_type"] == "aws"
    assert detail["error_type"] == "RuntimeError"
    assert detail["error"] == "upload failed"


def test_orchestrator_handle_failure_for_interrupt() -> None:
    api_client = FakeApiClient()
    orchestrator = ScanOrchestrator(config=None, api_client=api_client)
    exc = KeyboardInterrupt()

    orchestrator.handle_failure(exc, phase="execution", detail={"scanner_type": "k8s"})

    assert len(api_client.calls) == 1
    message, detail = api_client.calls[0]
    assert message == "Scan interrupted"
    assert detail["phase"] == "execution"
    assert detail["scanner_type"] == "k8s"
    assert detail["error_type"] == "KeyboardInterrupt"
    assert "error" not in detail


def test_run_polling_loop_repeats_until_interrupted(monkeypatch: pytest.MonkeyPatch) -> None:
    states = iter([False, True, False])
    handled = []
    sleeps = []

    def poll_once() -> bool:
        handled.append(True)
        return next(states)

    def fake_sleep(seconds: int) -> None:
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise KeyboardInterrupt()

    monkeypatch.setattr(shared_orchestrator.time, "sleep", fake_sleep)

    with pytest.raises(KeyboardInterrupt):
        shared_orchestrator.run_polling_loop(poll_once, interval_seconds=7)

    assert len(handled) == 3
    assert sleeps == [7, 7]


def test_orchestrator_start_scan_maps_trigger_mode_to_request_source() -> None:
    api_client = FakeApiClient()
    orchestrator = ScanOrchestrator(config=None, api_client=api_client)

    result = orchestrator.start_scan(scanner_type="aws", trigger_mode="manual")

    assert result == "scan-1"
    assert api_client.calls == [
        ("start_scan", {"scanner_type": "aws", "request_source": "manual"})
    ]
