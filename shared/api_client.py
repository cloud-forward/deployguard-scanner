from __future__ import annotations

import time
from typing import Any, Dict, Optional

import requests


class EngineApiClient:
    def __init__(self, config: Any) -> None:
        self.config = config
        self.base_url = config.api_url.rstrip("/")

    def start_scan(self, json_body: Dict[str, Any]) -> Dict[str, Any]:
        response = self._request_with_retry(
            method="POST",
            url=f"{self.base_url}/api/scans/start",
            json_body=json_body,
        )
        return response.json()

    def poll_scan(self, path: str, json_body: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        response = self._request_with_retry(
            method="POST",
            url=f"{self.base_url}{path}",
            json_body=json_body,
            allow_statuses={204},
        )
        if response.status_code == 204:
            return None
        return response.json()

    def get_upload_url(self, scan_id: str, json_body: Dict[str, Any]) -> Dict[str, Any]:
        response = self._request_with_retry(
            method="POST",
            url=f"{self.base_url}/api/scans/{scan_id}/upload-url",
            json_body=json_body,
        )
        return response.json()

    def complete_scan(self, scan_id: str, json_body: Dict[str, Any]) -> Dict[str, Any]:
        response = self._request_with_retry(
            method="POST",
            url=f"{self.base_url}/api/scans/{scan_id}/complete",
            json_body=json_body,
        )
        return response.json()

    def report_error(self, scan_id: str, json_body: Dict[str, Any]) -> Dict[str, Any]:
        response = self._request_with_retry(
            method="POST",
            url=f"{self.base_url}/api/scans/{scan_id}/error",
            json_body=json_body,
        )
        return response.json()

    def _request_with_retry(
        self,
        method: str,
        url: str,
        json_body: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        allow_statuses: Optional[set[int]] = None,
    ) -> requests.Response:
        last_error: Optional[Exception] = None
        request_timeout = timeout or self.config.http_timeout_seconds
        allowed = allow_statuses or set()

        for attempt in range(self.config.max_retries):
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    json=json_body,
                    headers=self._headers(),
                    timeout=request_timeout,
                )

                if 200 <= response.status_code < 300 or response.status_code in allowed:
                    return response

                if response.status_code in {408, 409, 425, 429, 502, 503, 504}:
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

    def _headers(self) -> Dict[str, str]:
        token = getattr(self.config, "api_token", None)
        if not token:
            raise ValueError("Missing required environment variable: DG_API_TOKEN or API_TOKEN")
        return {
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
        }

    def _sleep_before_retry(self, attempt: int) -> None:
        if attempt >= self.config.max_retries - 1:
            return
        time.sleep(self.config.backoff_seconds * (2 ** attempt))
