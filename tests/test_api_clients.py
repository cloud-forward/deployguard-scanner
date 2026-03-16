from __future__ import annotations

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
        scan_poll_path="/api/scans/poll",
    )
    client = api_module.DeployGuardApiClient(config)
    client.engine_client.poll_scan = lambda path, json_body: {
        "scan_id": "scan-123",
        "scanner_type": "aws",
        "trigger_mode": "scheduled",
    }

    result = client.poll_scan()

    assert result["scan_id"] == "scan-123"
    assert client.scan_id == "scan-123"
    assert client.scanner_type == "aws"


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


def test_scanner_api_client_report_error_ignores_engine_failure() -> None:
    api_module = load_scanner_src_module("api_client")
    config_module = load_scanner_src_module("config")
    config = config_module.ScannerConfig(
        cluster_id="cluster-id",
        api_url="https://api.example.com",
        api_token="token",
        scanner_type="image",
    )
    client = api_module.DeployGuardAPIClient(config)
    client.bind_scan("scan-777", "image")

    def fail_report_error(scan_id, json_body):
        raise RuntimeError("engine down")

    client.engine_client.report_error = fail_report_error

    client.report_error(message="failed", detail={"phase": "upload"})
