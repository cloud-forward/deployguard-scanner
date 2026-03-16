from __future__ import annotations

import json
import time
from typing import Any, Dict, Optional

import requests


class JsonResultUploader:
    def __init__(self, config: Any, api_client: Any) -> None:
        self.config = config
        self.api_client = api_client

    def upload_scan_result(
        self,
        scan_id: str,
        scanner_type: str,
        payload: Dict[str, Any],
        filename: str,
    ) -> Dict[str, Any]:
        upload_info = self.api_client.get_upload_url(
            scan_id=scan_id,
            scanner_type=scanner_type,
            filename=filename,
        )
        content = json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            default=str,
        ).encode("utf-8")
        self._upload_to_s3(upload_info["upload_url"], content)
        return upload_info

    def _upload_to_s3(self, upload_url: str, content: bytes) -> None:
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

    def _sleep_before_retry(self, attempt: int) -> None:
        if attempt >= self.config.max_retries - 1:
            return
        time.sleep(self.config.backoff_seconds * (2 ** attempt))
