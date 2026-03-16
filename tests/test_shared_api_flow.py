from __future__ import annotations

from types import SimpleNamespace

import pytest
import requests

from shared.api_client import EngineApiClient
from shared.uploader import JsonResultUploader
from tests.conftest import Response


def test_engine_api_client_poll_scan_returns_none_on_204(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def fake_request(method, url, json, headers, timeout):
        captured["method"] = method
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        return Response(204)

    monkeypatch.setattr(requests, "request", fake_request)

    client = EngineApiClient(
        SimpleNamespace(
            api_url="https://api.example.com",
            api_token="token-1",
            http_timeout_seconds=15,
            max_retries=2,
            backoff_seconds=0,
        )
    )

    result = client.poll_scan("/api/scans/poll", {"scanner_type": "aws"})

    assert result is None
    assert captured["method"] == "POST"
    assert captured["url"] == "https://api.example.com/api/scans/poll"
    assert captured["json"] == {"scanner_type": "aws"}
    assert captured["headers"]["Authorization"] == "Bearer token-1"


def test_engine_api_client_retries_transient_error(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = {"count": 0}

    def fake_request(method, url, json, headers, timeout):
        calls["count"] += 1
        if calls["count"] == 1:
            return Response(503, text="busy")
        return Response(200, {"scan_id": "scan-123"})

    monkeypatch.setattr(requests, "request", fake_request)

    client = EngineApiClient(
        SimpleNamespace(
            api_url="https://api.example.com",
            api_token="token-2",
            http_timeout_seconds=10,
            max_retries=2,
            backoff_seconds=0,
        )
    )

    result = client.start_scan({"scanner_type": "aws"})

    assert result == {"scan_id": "scan-123"}
    assert calls["count"] == 2


def test_json_result_uploader_uploads_serialized_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def fake_put(url, data, headers, timeout):
        captured["url"] = url
        captured["data"] = data
        captured["headers"] = headers
        captured["timeout"] = timeout
        return Response(200)

    monkeypatch.setattr(requests, "put", fake_put)

    class FakeApiClient:
        def get_upload_url(self, scan_id, scanner_type, filename):
            assert scan_id == "scan-1"
            assert scanner_type == "aws"
            assert filename == "result.json"
            return {"upload_url": "https://upload.example.com", "file_key": "bucket/key.json"}

    uploader = JsonResultUploader(
        SimpleNamespace(max_retries=1, upload_timeout_seconds=30, backoff_seconds=0),
        FakeApiClient(),
    )

    result = uploader.upload_scan_result(
        scan_id="scan-1",
        scanner_type="aws",
        payload={"hello": "world"},
        filename="result.json",
    )

    assert result == {"upload_url": "https://upload.example.com", "file_key": "bucket/key.json"}
    assert captured["url"] == "https://upload.example.com"
    assert captured["headers"] == {"Content-Type": "application/json"}
    assert b'"hello": "world"' in captured["data"]


def test_json_result_uploader_raises_after_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_put(url, data, headers, timeout):
        raise requests.Timeout("timed out")

    monkeypatch.setattr(requests, "put", fake_put)

    uploader = JsonResultUploader(
        SimpleNamespace(max_retries=2, upload_timeout_seconds=30, backoff_seconds=0),
        SimpleNamespace(get_upload_url=lambda **kwargs: {"upload_url": "https://upload.example.com"}),
    )

    with pytest.raises(RuntimeError, match="Upload failed after retries"):
        uploader._upload_to_s3("https://upload.example.com", b"{}")
