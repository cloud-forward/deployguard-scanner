from __future__ import annotations

import json
import signal
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

    def fake_run_polling_loop(poll_once, interval_seconds=30, should_stop=None):
        loop_calls.append(interval_seconds)
        assert poll_once() is False
        assert poll_once() is True
        raise KeyboardInterrupt()

    monkeypatch.setattr(main_module, "CloudScanner", FakeScanner)
    monkeypatch.setattr(main_module, "load_config", lambda cls: SimpleNamespace(cluster_id="cid", region="us-east-1", aws_recommended_cron_schedule="22 */4 * * *"))
    monkeypatch.setattr(main_module, "run_polling_loop", fake_run_polling_loop)
    monkeypatch.setattr(sys, "argv", ["main.py", "worker"])

    assert main_module.main() == 130
    output = capsys.readouterr()
    assert '"scan_id": "scan-1"' in output.out
    assert loop_calls == [30]


def test_main_defaults_to_worker_mode(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
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
            return {"scan_id": "scan-default", "trigger_mode": "scheduled"}

        def run_worker_scan(self, scan_id: str, trigger_mode: str = "scheduled"):
            return {
                "scan_id": scan_id,
                "status": "completed",
                "uploaded_files": ["f1"],
                "payload": {"resource_counts": {"x": 1}},
            }

    loop_calls = []

    def fake_run_polling_loop(poll_once, interval_seconds=30, should_stop=None):
        loop_calls.append(interval_seconds)
        assert poll_once() is False
        assert poll_once() is True
        raise KeyboardInterrupt()

    monkeypatch.setattr(main_module, "CloudScanner", FakeScanner)
    monkeypatch.setattr(main_module, "load_config", lambda cls: SimpleNamespace(cluster_id="cid", region="us-east-1", aws_recommended_cron_schedule="22 */4 * * *"))
    monkeypatch.setattr(main_module, "run_polling_loop", fake_run_polling_loop)
    monkeypatch.setattr(sys, "argv", ["main.py"])

    assert main_module.main() == 130
    output = capsys.readouterr()
    assert '"scan_id": "scan-default"' in output.out
    assert loop_calls == [30]


def test_main_manual_mode_is_rejected(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    main_module = load_root_module("main")
    scanner_created = {"value": False}
    polling_started = {"value": False}

    monkeypatch.setattr(main_module, "load_config", lambda cls: SimpleNamespace(cluster_id="cid", region="us-east-1", aws_recommended_cron_schedule="22 */4 * * *"))
    monkeypatch.setattr(main_module, "CloudScanner", lambda config: scanner_created.__setitem__("value", True))
    monkeypatch.setattr(main_module, "run_polling_loop", lambda *args, **kwargs: polling_started.__setitem__("value", True))
    monkeypatch.setattr(sys, "argv", ["main.py", "manual"])

    assert main_module.main() == 1
    output = capsys.readouterr()
    assert "supports only 'worker'" in output.err
    assert scanner_created["value"] is False
    assert polling_started["value"] is False


def test_main_scheduled_mode_is_rejected(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    main_module = load_root_module("main")
    scanner_created = {"value": False}
    polling_started = {"value": False}

    monkeypatch.setattr(main_module, "load_config", lambda cls: SimpleNamespace(cluster_id="cid", region="us-east-1", aws_recommended_cron_schedule="22 */4 * * *"))
    monkeypatch.setattr(main_module, "CloudScanner", lambda config: scanner_created.__setitem__("value", True))
    monkeypatch.setattr(main_module, "run_polling_loop", lambda *args, **kwargs: polling_started.__setitem__("value", True))
    monkeypatch.setattr(sys, "argv", ["main.py", "scheduled"])

    assert main_module.main() == 1
    output = capsys.readouterr()
    assert "supports only 'worker'" in output.err
    assert scanner_created["value"] is False
    assert polling_started["value"] is False


def test_main_unknown_mode_is_rejected(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    main_module = load_root_module("main")
    scanner_created = {"value": False}
    polling_started = {"value": False}

    monkeypatch.setattr(main_module, "load_config", lambda cls: SimpleNamespace(cluster_id="cid", region="us-east-1", aws_recommended_cron_schedule="22 */4 * * *"))
    monkeypatch.setattr(main_module, "CloudScanner", lambda config: scanner_created.__setitem__("value", True))
    monkeypatch.setattr(main_module, "run_polling_loop", lambda *args, **kwargs: polling_started.__setitem__("value", True))
    monkeypatch.setattr(sys, "argv", ["main.py", "foo"])

    assert main_module.main() == 1
    output = capsys.readouterr()
    assert "supports only 'worker'" in output.err
    assert scanner_created["value"] is False
    assert polling_started["value"] is False


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

    def fake_run_polling_loop(poll_once, interval_seconds=30, should_stop=None):
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


def test_scanner_worker_mode_uses_resident_polling_loop(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
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
            return {"scan_id": "scan-k8s-worker", "trigger_mode": "scheduled"}

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

    def fake_run_polling_loop(poll_once, interval_seconds=30, should_stop=None):
        loop_calls.append(interval_seconds)
        assert should_stop is not None
        assert should_stop() is False
        assert poll_once() is False
        assert poll_once() is True
        raise KeyboardInterrupt()

    monkeypatch.setattr(scan_module, "load_config", lambda cls: config)
    monkeypatch.setattr(scan_module, "DeployGuardAPIClient", FakeApiClient)
    monkeypatch.setattr(scan_module, "K8sScanner", FakeK8sScanner)
    monkeypatch.setattr(scan_module, "run_polling_loop", fake_run_polling_loop)
    monkeypatch.setattr(scan_module, "_print_k8s_summary", lambda result: None)
    monkeypatch.setattr(sys, "argv", ["scan.py", "worker"])

    assert scan_module.main() == 130
    output = capsys.readouterr()
    assert '"action": "worker.start"' in output.out
    assert '"action": "worker.poll"' in output.out
    assert '"action": "worker.idle"' in output.out
    assert '"action": "worker.claimed"' in output.out
    assert '"mode": "worker"' in output.out
    assert '"k8s_scan_id": "scan-k8s-worker"' in output.out
    assert loop_calls == [30]


def test_scanner_worker_mode_retries_after_poll_error(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
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
                raise RuntimeError("temporary poll failure")
            if poll_calls["count"] == 2:
                return None
            return {"scan_id": "scan-k8s-retry", "trigger_mode": "scheduled"}

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

    def fake_run_polling_loop(poll_once, interval_seconds=30, should_stop=None):
        loop_calls.append(interval_seconds)
        assert poll_once() is False
        assert poll_once() is False
        assert poll_once() is True
        raise KeyboardInterrupt()

    monkeypatch.setattr(scan_module, "load_config", lambda cls: config)
    monkeypatch.setattr(scan_module, "DeployGuardAPIClient", FakeApiClient)
    monkeypatch.setattr(scan_module, "K8sScanner", FakeK8sScanner)
    monkeypatch.setattr(scan_module, "run_polling_loop", fake_run_polling_loop)
    monkeypatch.setattr(scan_module, "_print_k8s_summary", lambda result: None)
    monkeypatch.setattr(sys, "argv", ["scan.py", "worker"])

    assert scan_module.main() == 130
    output = capsys.readouterr()
    assert '"action": "worker.retry"' in output.err
    assert "temporary poll failure" in output.err
    assert '"action": "worker.idle"' in output.out
    assert '"k8s_scan_id": "scan-k8s-retry"' in output.out
    assert loop_calls == [30]


def test_scanner_worker_mode_retries_after_scan_error(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    scan_module = load_scanner_module("scan")

    config = scan_module.ScannerConfig(
        cluster_id="cluster-id",
        api_url="https://analysis.deployguard.org",
        scanner_type="k8s",
    )
    run_calls = {"count": 0}

    class FakeApiClient:
        def __init__(self, _config) -> None:
            pass

        def poll_scan(self):
            return {"scan_id": f"scan-k8s-{run_calls['count'] + 1}", "trigger_mode": "scheduled"}

    class FakeK8sScanner:
        def __init__(self, _config) -> None:
            pass

        def run_worker_scan(self, scan_id: str, trigger_mode: str = "scheduled"):
            run_calls["count"] += 1
            if run_calls["count"] == 1:
                raise RuntimeError("temporary scan failure")
            return {
                "scan_id": scan_id,
                "status": "completed",
                "payload": {"summary": {"total_resources": 1, "by_type": {}}},
            }

    loop_calls = []

    def fake_run_polling_loop(poll_once, interval_seconds=30, should_stop=None):
        loop_calls.append(interval_seconds)
        assert poll_once() is False
        assert poll_once() is True
        raise KeyboardInterrupt()

    monkeypatch.setattr(scan_module, "load_config", lambda cls: config)
    monkeypatch.setattr(scan_module, "DeployGuardAPIClient", FakeApiClient)
    monkeypatch.setattr(scan_module, "K8sScanner", FakeK8sScanner)
    monkeypatch.setattr(scan_module, "run_polling_loop", fake_run_polling_loop)
    monkeypatch.setattr(scan_module, "_print_k8s_summary", lambda result: None)
    monkeypatch.setattr(sys, "argv", ["scan.py", "worker"])

    assert scan_module.main() == 130
    output = capsys.readouterr()
    assert '"action": "worker.retry"' in output.err
    assert "temporary scan failure" in output.err
    assert '"action": "worker.claimed"' in output.out
    assert '"k8s_scan_id": "scan-k8s-2"' in output.out
    assert loop_calls == [30]


def test_image_only_worker_preserves_k8s_discovery(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    scan_module = load_scanner_module("scan")

    config = scan_module.ScannerConfig(
        cluster_id="cluster-id",
        api_url="https://analysis.deployguard.org",
        scanner_type="image",
    )
    poll_calls = {"count": 0}
    observed = {}

    class FakeApiClient:
        def __init__(self, _config) -> None:
            pass

        def poll_scan(self):
            poll_calls["count"] += 1
            if poll_calls["count"] == 1:
                return None
            return {"scan_id": "scan-image-1", "trigger_mode": "scheduled"}

    class FakeK8sScanner:
        def __init__(self, _config) -> None:
            pass

        def scan(self):
            observed["k8s_scan_called"] = True
            return {"summary": {"total_resources": 3}}

    class FakeImageScanner:
        def __init__(self, _config, k8s_scan_result=None) -> None:
            observed["k8s_scan_result"] = k8s_scan_result

        def run_worker_scan(self, scan_id: str, trigger_mode: str = "scheduled"):
            observed["image_run"] = (scan_id, trigger_mode)
            return {
                "scan_id": scan_id,
                "status": "completed",
                "payload": {"summary": {"total_images": 1, "scanned_images": 1, "skipped_images": 0}},
            }

    loop_calls = []

    def fake_run_polling_loop(poll_once, interval_seconds=30, should_stop=None):
        loop_calls.append(interval_seconds)
        assert poll_once() is False
        assert poll_once() is True
        raise KeyboardInterrupt()

    monkeypatch.setattr(scan_module, "load_config", lambda cls: config)
    monkeypatch.setattr(scan_module, "DeployGuardAPIClient", FakeApiClient)
    monkeypatch.setattr(scan_module, "K8sScanner", FakeK8sScanner)
    monkeypatch.setattr(scan_module, "ImageScanner", FakeImageScanner)
    monkeypatch.setattr(scan_module, "run_polling_loop", fake_run_polling_loop)
    monkeypatch.setattr(scan_module, "_print_image_summary", lambda result: None)
    monkeypatch.setattr(sys, "argv", ["scan.py", "scheduled"])

    assert scan_module.main() == 130
    output = capsys.readouterr()
    assert '"image_scan_id": "scan-image-1"' in output.out
    assert observed["k8s_scan_called"] is True
    assert observed["k8s_scan_result"] == {"summary": {"total_resources": 3}}
    assert observed["image_run"] == ("scan-image-1", "scheduled")
    assert loop_calls == [30]


def test_scanner_worker_mode_stops_cleanly_on_sigterm(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    scan_module = load_scanner_module("scan")

    config = scan_module.ScannerConfig(
        cluster_id="cluster-id",
        api_url="https://analysis.deployguard.org",
        scanner_type="k8s",
    )
    registered_handlers = {}

    def fake_getsignal(signum):
        return signal.SIG_DFL

    def fake_signal(signum, handler):
        registered_handlers[signum] = handler
        return signal.SIG_DFL

    def fake_run_polling_loop(poll_once, interval_seconds=30, should_stop=None):
        assert should_stop is not None
        assert should_stop() is False
        registered_handlers[signal.SIGTERM](signal.SIGTERM, None)
        assert should_stop() is True

    monkeypatch.setattr(scan_module, "load_config", lambda cls: config)
    monkeypatch.setattr(scan_module, "run_polling_loop", fake_run_polling_loop)
    monkeypatch.setattr(scan_module.signal, "getsignal", fake_getsignal)
    monkeypatch.setattr(scan_module.signal, "signal", fake_signal)
    monkeypatch.setattr(sys, "argv", ["scan.py", "worker"])

    assert scan_module.main() == 0
    output = capsys.readouterr()
    assert '"action": "worker.shutdown_requested"' in output.out
    assert '"signal": "SIGTERM"' in output.out
    assert '"action": "worker.stopped"' in output.out
