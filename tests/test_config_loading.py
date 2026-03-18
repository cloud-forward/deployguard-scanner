from __future__ import annotations

import pytest

from backend.app.scanners.cloud_scanner import config as aws_config
from tests.conftest import load_scanner_src_module


def test_aws_config_from_env_loads_token_and_poll_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DG_CLUSTER_ID", "f1e96491-a558-4403-b363-e0c68d9a8c22")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    monkeypatch.setenv("DG_ENGINE_URL", "https://api.example.com/")
    monkeypatch.setenv("DG_API_TOKEN", "secret-token")
    monkeypatch.setenv("DG_SCAN_POLL_PATH", "/custom/poll")
    monkeypatch.setenv("DG_SAVE_LOCAL_COPY", "false")

    loaded = aws_config.ScannerConfig.from_env()

    assert loaded.cluster_id == "f1e96491-a558-4403-b363-e0c68d9a8c22"
    assert loaded.region == "us-west-2"
    assert loaded.api_url == "https://api.example.com"
    assert loaded.api_token == "secret-token"
    assert loaded.scan_poll_path == "/custom/poll"
    assert loaded.save_local_copy is False


def test_aws_config_from_env_rejects_invalid_cluster_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DG_CLUSTER_ID", "not-a-uuid")
    monkeypatch.setenv("AWS_REGION", "us-east-1")
    monkeypatch.setenv("API_URL", "https://api.example.com")

    with pytest.raises(ValueError, match="UUID format"):
        aws_config.ScannerConfig.from_env()


def test_scanner_config_from_env_loads_expected_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner_config = load_scanner_src_module("config")

    monkeypatch.setenv("DG_CLUSTER_ID", "cluster-metadata-id")
    monkeypatch.setenv("DG_API_URL", "https://engine.example.com/")
    monkeypatch.setenv("API_TOKEN", "scanner-token")
    monkeypatch.setenv("DG_SCANNER_TYPE", "image")
    monkeypatch.setenv("DG_SCAN_POLL_PATH", "/worker/poll")
    monkeypatch.setenv("DG_MAX_IMAGES_PER_SCAN", "25")

    loaded = scanner_config.ScannerConfig.from_env()

    assert loaded.cluster_id == "cluster-metadata-id"
    assert loaded.api_url == "https://engine.example.com"
    assert loaded.api_token == "scanner-token"
    assert loaded.scanner_type == "image"
    assert loaded.scan_poll_path == "/worker/poll"
    assert loaded.max_images_per_scan == 25


def test_scanner_config_from_env_rejects_invalid_scanner_type(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner_config = load_scanner_src_module("config")

    monkeypatch.setenv("CLUSTER_ID", "cluster-metadata-id")
    monkeypatch.setenv("API_URL", "https://engine.example.com")
    monkeypatch.setenv("DG_SCANNER_TYPE", "bad-type")

    with pytest.raises(ValueError, match="DG_SCANNER_TYPE must be one of"):
        scanner_config.ScannerConfig.from_env()


def test_aws_config_prefers_dg_api_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DG_CLUSTER_ID", "f1e96491-a558-4403-b363-e0c68d9a8c22")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    monkeypatch.setenv("DG_API_ENDPOINT", "https://primary.example.com")
    monkeypatch.setenv("API_URL", "https://legacy-api.example.com")
    monkeypatch.setenv("DG_API_URL", "https://legacy-dg-api.example.com")
    monkeypatch.setenv("DG_ENGINE_URL", "https://legacy-engine.example.com")

    loaded = aws_config.ScannerConfig.from_env()

    assert loaded.api_url == "https://primary.example.com"


def test_aws_config_accepts_api_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DG_CLUSTER_ID", "f1e96491-a558-4403-b363-e0c68d9a8c22")
    monkeypatch.setenv("AWS_REGION", "us-west-2")
    monkeypatch.setenv("API_BASE_URL", "https://worker.example.com/")

    loaded = aws_config.ScannerConfig.from_env()

    assert loaded.api_url == "https://worker.example.com"
    assert loaded.scan_poll_path == "/api/v1/scans/pending"


def test_scanner_config_prefers_dg_api_endpoint(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner_config = load_scanner_src_module("config")

    monkeypatch.setenv("DG_CLUSTER_ID", "cluster-metadata-id")
    monkeypatch.setenv("DG_API_ENDPOINT", "https://primary.example.com")
    monkeypatch.setenv("API_URL", "https://legacy-api.example.com")
    monkeypatch.setenv("DG_API_URL", "https://legacy-dg-api.example.com")
    monkeypatch.setenv("DG_ENGINE_URL", "https://legacy-engine.example.com")

    loaded = scanner_config.ScannerConfig.from_env()

    assert loaded.api_url == "https://primary.example.com"


def test_scanner_config_defaults_to_pending_claim_path(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner_config = load_scanner_src_module("config")

    monkeypatch.setenv("DG_CLUSTER_ID", "cluster-metadata-id")
    monkeypatch.setenv("DG_API_URL", "https://engine.example.com/")

    loaded = scanner_config.ScannerConfig.from_env()

    assert loaded.scan_poll_path == "/api/v1/scans/pending"


def test_scanner_config_defaults_exclude_kube_system(monkeypatch: pytest.MonkeyPatch) -> None:
    scanner_config = load_scanner_src_module("config")

    monkeypatch.setenv("DG_CLUSTER_ID", "cluster-metadata-id")
    monkeypatch.setenv("DG_API_URL", "https://engine.example.com/")

    loaded = scanner_config.ScannerConfig.from_env()

    assert loaded.exclude_namespaces == ["kube-system", "kube-public", "kube-node-lease"]
