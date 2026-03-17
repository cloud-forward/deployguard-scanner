from __future__ import annotations

import time
from typing import Any, Callable, Dict, Optional

DEFAULT_POLL_INTERVAL_SECONDS = 30


class ScanOrchestrator:
    def __init__(self, config: Any, api_client: Any) -> None:
        self.config = config
        self.api_client = api_client

    def poll_scan(self) -> Optional[Dict[str, Any]]:
        return self.api_client.poll_scan()

    def start_scan(
        self,
        scanner_type: str,
        trigger_mode: str = "scheduled",
        **kwargs: Any,
    ) -> str:
        request_source = "manual" if trigger_mode == "manual" else "scheduled"
        return self.api_client.start_scan(
            scanner_type=scanner_type,
            request_source=request_source,
            **kwargs,
        )

    def upload_result(self, payload: Dict[str, Any], filename: str) -> str:
        return self.api_client.upload_scan_result(payload, filename)

    def complete_scan(
        self,
        meta: Optional[Dict[str, Any]] = None,
        resource_counts: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self.api_client.complete_scan(
            meta=meta,
            resource_counts=resource_counts,
        )

    def build_result(
        self,
        scan_id: str,
        payload: Dict[str, Any],
        complete_result: Dict[str, Any],
        uploaded_files: list[str],
        local_file: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        result = {
            "scan_id": scan_id,
            "payload": payload,
            "uploaded_files": uploaded_files,
            "local_file": local_file,
            "status": complete_result.get("status", "unknown"),
        }
        if len(uploaded_files) == 1:
            result["s3_key"] = uploaded_files[0]
        if extra:
            result.update(extra)
        return result


def run_polling_loop(
    poll_once: Callable[[], bool],
    interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS,
    should_stop: Optional[Callable[[], bool]] = None,
) -> None:
    while True:
        if should_stop and should_stop():
            return
        handled = poll_once()
        if should_stop and should_stop():
            return
        if not handled:
            remaining_sleep = interval_seconds
            while remaining_sleep > 0:
                if should_stop and should_stop():
                    return
                sleep_seconds = min(1, remaining_sleep)
                time.sleep(sleep_seconds)
                remaining_sleep -= sleep_seconds
