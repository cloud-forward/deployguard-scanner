from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

import requests

from .config import ScannerConfig

logger = logging.getLogger(__name__)


class DeployGuardApiClient:
    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

    def start_scan(self, scanner_type: str, trigger_mode: str, scan_type: str) -> str:
        response = self._request_with_retry(
            method="POST",
            url=f"{self.config.api_url}/api/scans/start",
            json_body={
                "cluster_id": self.config.cluster_id,
                "scanner_type": scanner_type,
                "trigger_mode": trigger_mode,
                "scan_type": scan_type,
            },
        )
        data = response.json()
        scan_id = data.get("scan_id")
        if not scan_id:
            raise RuntimeError(f"scan_id not found in /api/scans/start response: {data}")
        return str(scan_id)

    def get_upload_url(self, scan_id: str, scanner_type: str, filename: str) -> Dict[str, Any]:
        response = self._request_with_retry(
            method="POST",
            url=f"{self.config.api_url}/api/scans/{scan_id}/upload-url",
            json_body={
                "cluster_id": self.config.cluster_id,
                "scanner_type": scanner_type,
                "filename": filename,
                "file_name": filename,
            },
        )
        data = response.json()

        upload_url = data.get("presigned_url") or data.get("upload_url")
        file_key = data.get("s3_key") or data.get("key") or data.get("file_key")
        if not upload_url:
            raise RuntimeError(f"presigned_url/upload_url not found in upload-url response: {data}")
        if not file_key:
            file_key = f"scans/{self.config.cluster_id}/{scan_id}/{scanner_type}/{filename}"

        return {
            **data,
            "upload_url": upload_url,
            "file_key": file_key,
        }

    def upload_to_s3(self, upload_url: str, content: bytes) -> None:
        last_error: Optional[Exception] = None

        for attempt in range(self.config.max_retries):
            try:
                response = requests.put(
                    upload_url,
                    data=content,
                    headers={"Content-Type": "application/json"},
                    timeout=self.config.upload_timeout_seconds,
                )

                if 200 <= response.status_code < 300:
                    return

                if response.status_code in {403, 408, 429} or 500 <= response.status_code < 600:
                    last_error = RuntimeError(
                        f"S3 upload failed with {response.status_code}: {response.text}"
                    )
                    self._sleep_before_retry(attempt)
                    continue

                raise RuntimeError(f"S3 upload failed with {response.status_code}: {response.text}")

            except requests.Timeout as exc:
                last_error = exc
                self._sleep_before_retry(attempt)
            except requests.RequestException as exc:
                last_error = exc
                self._sleep_before_retry(attempt)

        if last_error:
            raise RuntimeError(f"Upload failed after retries: {last_error}") from last_error
        raise RuntimeError("Upload failed after retries")

    def complete_scan(
        self,
        scan_id: str,
        files: list[str],
        resource_counts: Optional[Dict[str, Any]] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        json_body: Dict[str, Any] = {"files": files}
        if resource_counts is not None:
            json_body["resource_counts"] = resource_counts
        if meta:
            json_body["meta"] = meta

        response = self._request_with_retry(
            method="POST",
            url=f"{self.config.api_url}/api/scans/{scan_id}/complete",
            json_body=json_body,
        )
        return response.json()

    def report_error(self, scan_id: str, message: str, detail: Optional[Dict[str, Any]] = None) -> None:
        payload: Dict[str, Any] = {"message": message}
        if detail:
            payload["detail"] = detail

        try:
            self._request_with_retry(
                method="POST",
                url=f"{self.config.api_url}/api/scans/{scan_id}/error",
                json_body=payload,
            )
        except Exception:
            logger.exception("Failed to report scan error to engine")

    def _request_with_retry(
        self,
        method: str,
        url: str,
        json_body: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> requests.Response:
        last_error: Optional[Exception] = None
        request_timeout = timeout or self.config.http_timeout_seconds

        for attempt in range(self.config.max_retries):
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    json=json_body,
                    timeout=request_timeout,
                )

                if 200 <= response.status_code < 300:
                    return response

                if response.status_code in {408, 409, 425, 429} or 500 <= response.status_code < 600:
                    last_error = RuntimeError(
                        f"{method} {url} failed with {response.status_code}: {response.text}"
                    )
                    self._sleep_before_retry(attempt)
                    continue

                raise RuntimeError(f"{method} {url} failed with {response.status_code}: {response.text}")

            except requests.Timeout as exc:
                last_error = exc
                self._sleep_before_retry(attempt)
            except requests.RequestException as exc:
                last_error = exc
                self._sleep_before_retry(attempt)

        if last_error:
            raise RuntimeError(f"Request failed after retries: {last_error}") from last_error
        raise RuntimeError(f"Request failed after retries: {method} {url}")

    def _sleep_before_retry(self, attempt: int) -> None:
        if attempt >= self.config.max_retries - 1:
            return
        time.sleep(self.config.backoff_seconds * (2 ** attempt))