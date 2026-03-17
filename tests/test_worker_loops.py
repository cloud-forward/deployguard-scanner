from __future__ import annotations

import json
import sys
from types import SimpleNamespace

import pytest

from tests.conftest import load_root_module, load_scanner_module


def test_main_scheduled_uses_resident_polling_loop(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    main_module = load_root_module("main")

    class FakeScanner:
        def __init__(self, config) -> None:
            self.api_client = SimpleNamespace()
            self.calls = 0
            self.api_client.poll_scan = self.poll_scan

        def poll_scan(self):
            self.calls += 1
            if self.calls == 1:
                return None
            return {"scan_id": "scan-1", "trigger_mode": "scheduled"}

        def run_worker_scan(self, scan_id: str, trigger_mode: str = "scheduled"):
            return {
                "scan_id": scan_id,
                "status": "completed",
                "uploaded_files": ["f1"],
                "payload": {"resource_counts": {"x": 1}},
            }

    loop_calls = []

    def fake_run_polling_loop(poll_once, interval_seconds=30):
        loop_calls.append(interval_seconds)
        assert poll_once() is False
        assert poll_once() is True
        raise KeyboardInterrupt()

    monkeypatch.setattr(main_module, "CloudScanner", FakeScanner)
    monkeypatch.setattr(main_module, "load_config", lambda cls: SimpleNamespace(cluster_id="cid", region="us-east-1", aws_recommended_cron_schedule="22 */4 * * *"))
    monkeypatch.setattr(main_module, "run_polling_loop", fake_run_polling_loop)
    monkeypatch.setattr(sys, "argv", ["main.py", "scheduled"])

    assert main_module.main() == 130
    output = capsys.readouterr()
    assert '"scan_id": "scan-1"' in output.out
    assert loop_calls == [30]


def test_scanner_scheduled_uses_resident_polling_loop(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    scan_module = load_scanner_module("scan")

    config = scan_module.ScannerConfig(
        cluster_id="cluster-id",
        api_url="https://analysis.deployguard.org",
        scanner_type="k8s",
    )
    poll_calls = {"count": 0}

    class FakeApiClient:
        def __init__(self, _config) -> None:
            pass

        def poll_scan(self):
            poll_calls["count"] += 1
            if poll_calls["count"] == 1:
                return None
            return {"scan_id": "scan-k8s-1", "trigger_mode": "scheduled"}

    class FakeK8sScanner:
        def __init__(self, _config) -> None:
            pass

        def run_worker_scan(self, scan_id: str, trigger_mode: str = "scheduled"):
            return {
                "scan_id": scan_id,
                "status": "completed",
                "payload": {"summary": {"total_resources": 1, "by_type": {}}},
            }

    loop_calls = []

    def fake_run_polling_loop(poll_once, interval_seconds=30):
        loop_calls.append(interval_seconds)
        assert poll_once() is False
        assert poll_once() is True
        raise KeyboardInterrupt()

    monkeypatch.setattr(scan_module, "load_config", lambda cls: config)
    monkeypatch.setattr(scan_module, "DeployGuardAPIClient", FakeApiClient)
    monkeypatch.setattr(scan_module, "K8sScanner", FakeK8sScanner)
    monkeypatch.setattr(scan_module, "run_polling_loop", fake_run_polling_loop)
    monkeypatch.setattr(scan_module, "_print_k8s_summary", lambda result: None)
    monkeypatch.setattr(sys, "argv", ["scan.py", "scheduled"])

    assert scan_module.main() == 130
    output = capsys.readouterr()
    assert '"k8s_scan_id": "scan-k8s-1"' in output.out
    assert loop_calls == [30]
