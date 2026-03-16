from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from .config import ScannerConfig
from shared.api_client import EngineApiClient
from shared.uploader import JsonResultUploader

logger = logging.getLogger(__name__)


class DeployGuardApiClient:
    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self.engine_client = EngineApiClient(config)
        self.uploader = JsonResultUploader(config, self)
        self.scan_id: Optional[str] = None
        self.scanner_type: Optional[str] = None
        self.uploaded_files: list[str] = []

    def start_scan(self, scanner_type: str, trigger_mode: str, scan_type: str) -> str:
        data = self.engine_client.start_scan(
            json_body={
                "scanner_type": scanner_type,
                "trigger_mode": trigger_mode,
                "scan_type": scan_type,
            },
        )
        scan_id = data.get("scan_id")
        if not scan_id:
            raise RuntimeError(f"scan_id not found in /api/scans/start response: {data}")

        self.scan_id = str(scan_id)
        self.scanner_type = scanner_type
        self.uploaded_files = []
        return str(scan_id)

    def bind_scan(self, scan_id: str, scanner_type: str) -> None:
        self.scan_id = scan_id
        self.scanner_type = scanner_type
        self.uploaded_files = []

    def poll_scan(self) -> Optional[Dict[str, Any]]:
        data = self.engine_client.poll_scan(
            path=self.config.scan_poll_path,
            json_body={
                "scanner_type": self.config.scanner_type,
                "scan_type": self.config.scan_type,
            },
        )
        if not data:
            return None

        scan_id = data.get("scan_id")
        scanner_type = data.get("scanner_type", self.config.scanner_type)
        if not scan_id:
            raise RuntimeError(f"scan_id not found in poll response: {data}")

        self.bind_scan(str(scan_id), str(scanner_type))
        return data

    def get_upload_url(
        self,
        scan_id: Optional[str] = None,
        scanner_type: Optional[str] = None,
        filename: str = "aws-snapshot.json",
    ) -> Dict[str, Any]:
        resolved_scan_id = scan_id or self.scan_id
        resolved_scanner_type = scanner_type or self.scanner_type
        if not resolved_scan_id:
            raise ValueError("scan_id is None. Call start_scan() first.")
        if not resolved_scanner_type:
            raise ValueError("scanner_type is None. Call start_scan() first.")

        data = self.engine_client.get_upload_url(
            scan_id=resolved_scan_id,
            json_body={
                "scanner_type": resolved_scanner_type,
                "filename": filename,
                "file_name": filename,
            },
        )

        upload_url = data.get("presigned_url") or data.get("upload_url")
        file_key = data.get("s3_key") or data.get("key") or data.get("file_key")
        if not upload_url:
            raise RuntimeError(f"presigned_url/upload_url not found in upload-url response: {data}")
        if not file_key:
            file_key = f"scans/{self.config.cluster_id}/{resolved_scan_id}/{resolved_scanner_type}/{filename}"

        return {
            **data,
            "upload_url": upload_url,
            "file_key": file_key,
        }

    def upload_to_s3(self, upload_url: str, content: bytes) -> None:
        self.uploader._upload_to_s3(upload_url, content)

    def upload_scan_result(self, payload: Dict[str, Any], filename: str = "aws-snapshot.json") -> str:
        if not self.scan_id:
            raise ValueError("scan_id is None. Call start_scan() first.")
        if not self.scanner_type:
            raise ValueError("scanner_type is None. Call start_scan() first.")

        upload_info = self.uploader.upload_scan_result(
            scan_id=self.scan_id,
            scanner_type=self.scanner_type,
            payload=payload,
            filename=filename,
        )
        file_key = upload_info["file_key"]
        self.uploaded_files.append(file_key)
        return file_key

    def complete_scan(
        self,
        scan_id: Optional[str] = None,
        files: Optional[list[str]] = None,
        resource_counts: Optional[Dict[str, Any]] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        resolved_scan_id = scan_id or self.scan_id
        resolved_files = files or self.uploaded_files
        if not resolved_scan_id:
            raise ValueError("scan_id is None. Call start_scan() first.")
        if not resolved_files:
            raise ValueError("No files uploaded. Call upload_scan_result() first.")

        json_body: Dict[str, Any] = {"files": resolved_files}
        if resource_counts is not None:
            json_body["resource_counts"] = resource_counts
        if meta:
            json_body["meta"] = meta

        return self.engine_client.complete_scan(
            scan_id=resolved_scan_id,
            json_body=json_body,
        )

    def report_error(
        self,
        scan_id: Optional[str] = None,
        message: str = "",
        detail: Optional[Dict[str, Any]] = None,
    ) -> None:
        resolved_scan_id = scan_id or self.scan_id
        if not resolved_scan_id:
            return

        payload: Dict[str, Any] = {"message": message}
        if detail:
            payload["detail"] = detail

        try:
            self.engine_client.report_error(
                scan_id=resolved_scan_id,
                json_body=payload,
            )
        except Exception:
            logger.exception("Failed to report scan error to engine")
