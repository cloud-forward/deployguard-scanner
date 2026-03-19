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
        )

    def bind_or_start_scan(
        self,
        scanner_type: str,
        trigger_mode: str = "scheduled",
        assigned_scan_id: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        if assigned_scan_id:
            self.api_client.bind_scan(assigned_scan_id, scanner_type)
            return assigned_scan_id

        try:
            self.start_scan(
                scanner_type=scanner_type,
                trigger_mode=trigger_mode,
            )
        except RuntimeError as exc:
            if "409" not in str(exc):
                raise

        pending = self.api_client.poll_scan()
        if not pending:
            raise RuntimeError("Failed to claim pending scan after start")

        return str(pending["scan_id"])

    def upload_result(self, payload: Dict[str, Any], filename: str) -> str:
        return self.api_client.upload_scan_result(payload, filename)

    def complete_scan(
        self,
        meta: Optional[Dict[str, Any]] = None,
        resource_counts: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        result = self.api_client.complete_scan(
            meta=meta,
            resource_counts=resource_counts,
        )
        # 스캔 완료 후 analysis/jobs 트리거 시도
        try:
            trigger = getattr(self.api_client, "trigger_analysis_if_ready", None)
            if trigger is not None:
                trigger()
        except Exception as exc:
            print(f"[-] trigger_analysis_if_ready failed (non-fatal): {exc}")
        return result

    def report_error(
        self,
        message: str,
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        report_error = getattr(self.api_client, "report_error", None)
        if report_error is None:
            return
        report_error(message=message, detail=detail)

    def handle_failure(
        self,
        exc: BaseException,
        phase: str,
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        if getattr(exc, "_deployguard_reported", False):
            return

        failure_detail = {
            "phase": phase,
            "error_type": type(exc).__name__,
        }
        if detail:
            failure_detail.update(detail)
        if not isinstance(exc, KeyboardInterrupt):
            failure_detail["error"] = str(exc)

        message = "Scan interrupted" if isinstance(exc, KeyboardInterrupt) else f"Scan failed during {phase}: {exc}"
        self.report_error(message=message, detail=failure_detail)

        try:
            setattr(exc, "_deployguard_reported", True)
        except Exception:
            pass

    def build_result(
        self,
        scan_id: str,
        payload: Dict[str, Any],
        complete_result: Dict[str, Any],
        uploaded_files: list,
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
            time.sleep(interval_seconds)