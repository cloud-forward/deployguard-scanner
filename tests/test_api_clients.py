from __future__ import annotations

from types import SimpleNamespace
import json

import pytest

from tests.conftest import load_root_module, load_scanner_src_module


def test_root_api_client_poll_scan_binds_scan_state() -> None:
    api_module = load_root_module("api_client")
    config_module = load_root_module("config")
    config = config_module.ScannerConfig(
        cluster_id="f1e96491-a558-4403-b363-e0c68d9a8c22",
        region="us-east-1",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="aws",
        scan_type="full",
        scan_poll_path="/api/v1/scans/pending",
    )
    client = api_module.DeployGuardApiClient(config)
    client.engine_client.poll_scan = lambda path, query_params: {
        "scan_id": "scan-123",
        "scanner_type": "aws",
        "trigger_mode": "scheduled",
    }

    result = client.poll_scan()

    assert result["scan_id"] == "scan-123"
    assert client.scan_id == "scan-123"
    assert client.scanner_type == "aws"


def test_root_api_client_start_scan_uses_backend_contract() -> None:
    api_module = load_root_module("api_client")
    config_module = load_root_module("config")
    config = config_module.ScannerConfig(
        cluster_id="f1e96491-a558-4403-b363-e0c68d9a8c22",
        region="us-east-1",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="aws",
        scan_type="full",
    )
    client = api_module.DeployGuardApiClient(config)
    client.bind_scan("scan-123", "aws")

    result = client.start_scan("aws", "scheduled")

    assert result == "scan-123"
    assert client.scan_id == "scan-123"
    assert client.scanner_type == "aws"
    assert client.uploaded_files == []


def test_root_api_client_upload_and_complete_flow() -> None:
    api_module = load_root_module("api_client")
    config_module = load_root_module("config")
    config = config_module.ScannerConfig(
        cluster_id="f1e96491-a558-4403-b363-e0c68d9a8c22",
        region="us-east-1",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="aws",
        scan_type="full",
    )
    client = api_module.DeployGuardApiClient(config)
    client.bind_scan("scan-321", "aws")
    client.uploader.upload_scan_result = lambda **kwargs: {"file_key": "scans/key.json"}
    complete_calls = {}

    def fake_complete_scan(scan_id, json_body):
        complete_calls["scan_id"] = scan_id
        complete_calls["json_body"] = json_body
        return {"status": "completed"}

    client.engine_client.complete_scan = fake_complete_scan

    file_key = client.upload_scan_result({"payload": True}, "aws.json")
    result = client.complete_scan(resource_counts={"buckets": 2}, meta={"trigger_mode": "scheduled"})

    assert file_key == "scans/key.json"
    assert result == {"status": "completed"}
    assert complete_calls["scan_id"] == "scan-321"
    assert complete_calls["json_body"]["files"] == ["scans/key.json"]
    assert complete_calls["json_body"]["resource_counts"] == {"buckets": 2}
    assert complete_calls["json_body"]["meta"] == {"trigger_mode": "scheduled"}


def test_scanner_api_client_complete_requires_uploaded_files() -> None:
    api_module = load_scanner_src_module("api_client")
    config_module = load_scanner_src_module("config")
    config = config_module.ScannerConfig(
        cluster_id="cluster-id",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="k8s",
    )
    client = api_module.DeployGuardAPIClient(config)
    client.bind_scan("scan-555", "k8s")

    try:
        client.complete_scan()
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "No files uploaded" in str(exc)


def test_scanner_api_client_start_scan_uses_backend_contract() -> None:
    api_module = load_scanner_src_module("api_client")
    config_module = load_scanner_src_module("config")
    config = config_module.ScannerConfig(
        cluster_id="cluster-id",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="k8s",
    )
    client = api_module.DeployGuardAPIClient(config)
    captured = {}

    def fake_start_scan(json_body):
        captured["json_body"] = json_body
        return {"scan_id": "scan-456"}

    client.engine_client.start_scan = fake_start_scan

    result = client.start_scan("k8s", "manual")

    assert result == "scan-456"
    assert captured["json_body"]["cluster_id"] == config.cluster_id
    assert captured["json_body"]["scanner_type"] == "k8s"
    assert captured["json_body"]["request_source"] == "manual"
    assert "trigger_mode" not in captured["json_body"]
    assert "scan_type" not in captured["json_body"]
    assert captured["json_body"]["request_source"] in {"manual", "scheduled"}


def test_scanner_api_client_logs_upload_and_complete_actions(capsys) -> None:
    api_module = load_scanner_src_module("api_client")
    config_module = load_scanner_src_module("config")
    config = config_module.ScannerConfig(
        cluster_id="cluster-id",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="k8s",
    )
    client = api_module.DeployGuardAPIClient(config)
    client.bind_scan("scan-789", "k8s")
    client.uploader.upload_scan_result = lambda **kwargs: {"s3_key": "scans/scan-789/k8s/scan.json"}
    client.engine_client.complete_scan = lambda scan_id, json_body: {"status": "completed"}

    file_key = client.upload_scan_result({"payload": True}, "scan.json")
    result = client.complete_scan(meta={"trigger_mode": "scheduled"})

    output = capsys.readouterr().out
    assert file_key == "scans/scan-789/k8s/scan.json"
    assert result == {"status": "completed"}
    assert "[+] Uploaded to S3 successfully" in output
    assert "[+] Scan completed: scan-789" in output


def test_scanner_api_client_removes_legacy_error_and_direct_flow_helpers() -> None:
    api_module = load_scanner_src_module("api_client")
    config_module = load_scanner_src_module("config")
    config = config_module.ScannerConfig(
        cluster_id="cluster-id",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="image",
    )
    client = api_module.DeployGuardAPIClient(config)
    assert hasattr(client, "report_error")
    assert hasattr(client, "full_scan_flow")


def test_cloud_scanner_worker_path_binds_claimed_scan_before_upload(monkeypatch) -> None:
    scanner_module = load_root_module("scanner")
    config_module = load_root_module("config")
    config = config_module.ScannerConfig(
        cluster_id="f1e96491-a558-4403-b363-e0c68d9a8c22",
        region="us-east-1",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="aws",
        scan_type="full",
        save_local_copy=False,
    )
    calls = []

    monkeypatch.setattr(scanner_module, "create_boto3_session", lambda **kwargs: SimpleNamespace(client=lambda *args, **kwargs: SimpleNamespace()))
    monkeypatch.setattr(scanner_module, "validate_credentials", lambda session, region: {"Account": "123456789012"})

    scanner = scanner_module.CloudScanner(config)

    def bind_scan(scan_id, scanner_type):
        calls.append(("bind_scan", scan_id, scanner_type))
        scanner.api_client.scan_id = scan_id
        scanner.api_client.scanner_type = scanner_type
        scanner.api_client.uploaded_files = []

    def upload_scan_result(payload, filename):
        calls.append(("upload_scan_result", scanner.api_client.scan_id, scanner.api_client.scanner_type, filename))
        assert scanner.api_client.scan_id == "scan-claimed"
        assert scanner.api_client.scanner_type == "aws"
        scanner.api_client.uploaded_files.append("scans/aws.json")
        return "scans/aws.json"

    def complete_scan(meta=None, resource_counts=None):
        calls.append(("complete_scan", list(scanner.api_client.uploaded_files), meta, resource_counts))
        return {"status": "completed"}

    scanner.api_client.bind_scan = bind_scan
    scanner.api_client.upload_scan_result = upload_scan_result
    scanner.api_client.complete_scan = complete_scan
    scanner._resolve_account_id = lambda: "123456789012"
    scanner._collect_all_resources = lambda scan_id, aws_account_id: {
        "iam_roles": [],
        "iam_users": [],
        "s3_buckets": [],
        "rds_instances": [],
        "ec2_instances": [],
        "security_groups": [],
    }

    result = scanner.run_worker_scan("scan-claimed", trigger_mode="scheduled")

    assert result["scan_id"] == "scan-claimed"
    assert calls[0] == ("bind_scan", "scan-claimed", "aws")
    assert calls[1] == ("upload_scan_result", "scan-claimed", "aws", config.upload_file_name)
    assert calls[2][0] == "complete_scan"
    assert calls[2][1] == ["scans/aws.json"]


def test_cloud_scanner_worker_failure_does_not_report_error(monkeypatch) -> None:
    scanner_module = load_root_module("scanner")
    config_module = load_root_module("config")
    config = config_module.ScannerConfig(
        cluster_id="f1e96491-a558-4403-b363-e0c68d9a8c22",
        region="us-east-1",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="aws",
        scan_type="full",
        save_local_copy=False,
    )

    monkeypatch.setattr(scanner_module, "create_boto3_session", lambda **kwargs: SimpleNamespace(client=lambda *args, **kwargs: SimpleNamespace()))
    monkeypatch.setattr(scanner_module, "validate_credentials", lambda session, region: {"Account": "123456789012"})

    scanner = scanner_module.CloudScanner(config)

    scanner.api_client.start_scan = lambda *args, **kwargs: scanner.api_client.scan_id
    scanner.api_client.bind_scan = lambda scan_id, scanner_type: (
        setattr(scanner.api_client, "scan_id", scan_id),
        setattr(scanner.api_client, "scanner_type", scanner_type),
        setattr(scanner.api_client, "uploaded_files", []),
    )
    scanner.api_client.engine_client.report_error = lambda *args, **kwargs: (_ for _ in ()).throw(
        AssertionError("worker path must not call report_error")
    )
    scanner.api_client.upload_scan_result = lambda payload, filename: (_ for _ in ()).throw(RuntimeError("upload failed"))
    scanner._resolve_account_id = lambda: "123456789012"
    scanner._collect_all_resources = lambda scan_id, aws_account_id: {
        "iam_roles": [],
        "iam_users": [],
        "s3_buckets": [],
        "rds_instances": [],
        "ec2_instances": [],
        "security_groups": [],
    }

    try:
        scanner.run_worker_scan("scan-claimed", trigger_mode="scheduled")
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert str(exc) == "upload failed"


def test_k8s_worker_path_uses_claimed_scan_without_start(monkeypatch) -> None:
    scanner_module = load_scanner_src_module("k8s_scanner")
    config_module = load_scanner_src_module("config")
    config = config_module.ScannerConfig(
        cluster_id="cluster-id",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="k8s",
        save_local_copy=False,
    )
    calls = []

    monkeypatch.setattr(scanner_module.K8sScanner, "_init_k8s_client", lambda self: setattr(self, "cluster_type", "self-managed"))

    class FakeApiClient:
        def __init__(self, _config) -> None:
            self.scan_id = None
            self.scanner_type = None
            self.uploaded_files = []

        def start_scan(self, *args, **kwargs):
            raise AssertionError("worker path must not call start_scan")

        def bind_scan(self, scan_id, scanner_type):
            calls.append(("bind_scan", scan_id, scanner_type))
            self.scan_id = scan_id
            self.scanner_type = scanner_type
            self.uploaded_files = []

        def upload_scan_result(self, payload, filename):
            calls.append(("upload_scan_result", self.scan_id, self.scanner_type, filename))
            self.uploaded_files.append("scans/k8s.json")
            return "scans/k8s.json"

        def complete_scan(self, meta=None, resource_counts=None):
            calls.append(("complete_scan", list(self.uploaded_files), meta, resource_counts))
            return {"status": "completed"}

    monkeypatch.setattr(scanner_module, "DeployGuardAPIClient", FakeApiClient)

    scanner = scanner_module.K8sScanner(config)
    scanner._collect_all_resources = lambda: {"pods": []}
    scanner._build_payload = lambda scan_id, resources: {
        "cluster_type": "self-managed",
        "summary": {"by_type": {"pods": 0}, "security_indicators": {}}
    }

    result = scanner.run_worker_scan("scan-k8s-claimed", trigger_mode="scheduled")

    assert result["scan_id"] == "scan-k8s-claimed"
    assert calls[0] == ("bind_scan", "scan-k8s-claimed", "k8s")
    assert calls[1] == ("upload_scan_result", "scan-k8s-claimed", "k8s", config.upload_file_name)
    assert calls[2][0] == "complete_scan"
    assert calls[2][1] == ["scans/k8s.json"]


def test_image_worker_path_uses_claimed_scan_without_start(monkeypatch) -> None:
    scanner_module = load_scanner_src_module("image_scanner")
    config_module = load_scanner_src_module("config")
    config = config_module.ScannerConfig(
        cluster_id="cluster-id",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="image",
        save_local_copy=False,
    )
    calls = []

    monkeypatch.setattr(scanner_module.ImageScanner, "_check_tool", lambda self, name: False)
    monkeypatch.setattr(scanner_module.ImageScanner, "_get_trivy_version", lambda self: None)

    class FakeApiClient:
        def __init__(self, _config) -> None:
            self.scan_id = None
            self.scanner_type = None
            self.uploaded_files = []

        def start_scan(self, *args, **kwargs):
            raise AssertionError("worker path must not call start_scan")

        def bind_scan(self, scan_id, scanner_type):
            calls.append(("bind_scan", scan_id, scanner_type))
            self.scan_id = scan_id
            self.scanner_type = scanner_type
            self.uploaded_files = []

        def upload_scan_result(self, payload, filename):
            calls.append(("upload_scan_result", self.scan_id, self.scanner_type, filename))
            self.uploaded_files.append("scans/image.json")
            return "scans/image.json"

        def complete_scan(self, meta=None, resource_counts=None):
            calls.append(("complete_scan", list(self.uploaded_files), meta, resource_counts))
            return {"status": "completed"}

    monkeypatch.setattr(scanner_module, "DeployGuardAPIClient", FakeApiClient)

    scanner = scanner_module.ImageScanner(config, k8s_scan_result={"pods": []})
    scanner._collect_images = lambda: [{"image_ref": "nginx:latest"}]
    scanner._scan_single_image = lambda img_info: {"image_ref": img_info["image_ref"], "vulnerabilities": []}
    scanner._build_payload = lambda scan_id, trigger_mode, images: {
        "summary": {"total_images": 1, "scanned_images": 1, "by_severity": {}}
    }

    result = scanner.run_worker_scan("scan-image-claimed", trigger_mode="scheduled")

    assert result["scan_id"] == "scan-image-claimed"
    assert calls[0] == ("bind_scan", "scan-image-claimed", "image")
    assert calls[1] == ("upload_scan_result", "scan-image-claimed", "image", config.upload_file_name)
    assert calls[2][0] == "complete_scan"
    assert calls[2][1] == ["scans/image.json"]
