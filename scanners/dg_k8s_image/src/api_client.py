from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from .config import ScannerConfig
from shared.api_client import EngineApiClient
from shared.uploader import JsonResultUploader

logger = logging.getLogger(__name__)


class DeployGuardAPIClient:
    """
    DeployGuard Analysis API 클라이언트
    
    새로운 API 호출 방식:
    1. POST /api/scans/start → scan_id 획득
    2. POST /api/scans/{scan_id}/upload-url → presigned URL 획득
    3. PUT presigned_url → S3 업로드
    4. POST /api/scans/{scan_id}/complete → 완료 알림
    """

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self.base_url = config.api_url
        self.engine_client = EngineApiClient(config)
        self.uploader = JsonResultUploader(config, self)
        self.scan_id: Optional[str] = None
        self.scanner_type: Optional[str] = None
        self.uploaded_files: List[str] = []

    def start_scan(self, scanner_type: str, request_source: str = "scheduled") -> str:
        """
        스캔 시작 등록
        
        Args:
            scanner_type: k8s, image, aws
            request_source: manual, scheduled
            
        Returns:
            scan_id
        """
        data = self.engine_client.start_scan(
            json_body={
                "cluster_id": self.config.cluster_id,
                "scanner_type": scanner_type,
                "request_source": request_source,
            },
        )

        self.scan_id = data.get("scan_id")
        self.scanner_type = scanner_type
        self.uploaded_files = []

        if not self.scan_id:
            raise RuntimeError(f"scan_id not found in response: {data}")

        print(f"[+] Scan started: {self.scan_id}")
        return str(self.scan_id)

    def bind_scan(self, scan_id: str, scanner_type: str) -> None:
        self.scan_id = scan_id
        self.scanner_type = scanner_type
        self.uploaded_files = []

    def poll_scan(self) -> Optional[Dict[str, Any]]:
        data = self.engine_client.poll_scan(
            path=self.config.scan_poll_path,
            json_body={
                "scanner_type": self.config.scanner_type,
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
        scan_id: str,
        scanner_type: str,
        filename: str = "scan.json",
    ) -> Dict[str, Any]:
        """
        S3 Presigned URL 획득
        
        Returns:
            {
                "upload_url": "https://s3...",
                "s3_key": "scans/{cluster_id}/{scan_id}/{scanner_type}/scan.json"
            }
        """
        resolved_scan_id = scan_id or self.scan_id
        resolved_scanner_type = scanner_type or self.scanner_type

        if not resolved_scan_id:
            raise ValueError("scan_id is None. Call start_scan() first.")
        if not resolved_scanner_type:
            raise ValueError("scanner_type is None. Call start_scan() first.")

        data = self.engine_client.get_upload_url(
            scan_id=resolved_scan_id,
            json_body={
                "file_name": filename,
                "scanner_type": resolved_scanner_type,
            },
        )

        upload_url = data.get("upload_url") or data.get("presigned_url")
        if not upload_url:
            raise RuntimeError(f"upload_url not found in response: {data}")

        s3_key = data.get("s3_key") or data.get("key") or filename

        print(f"[+] Got upload URL for: {s3_key}")

        return {
            "upload_url": upload_url,
            "s3_key": s3_key,
        }

    def upload_to_s3(self, upload_url: str, payload: Dict[str, Any]) -> bool:
        """
        S3에 JSON 직접 업로드
        """
        self.uploader._upload_to_s3(
            upload_url,
            self._serialize_payload(payload),
        )
        print(f"[+] Uploaded to S3 successfully")
        return True

    def upload_scan_result(self, payload: Dict[str, Any], filename: str = "scan.json") -> str:
        """
        스캔 결과 업로드 (get_upload_url + upload_to_s3 통합)
        
        Returns:
            s3_key
        """
        if not self.scan_id:
            raise ValueError("scan_id is None. Call start_scan() first.")
        if not self.scanner_type:
            raise ValueError("scanner_type is None. Call start_scan() first.")

        url_info = self.uploader.upload_scan_result(
            scan_id=self.scan_id,
            scanner_type=self.scanner_type,
            payload=payload,
            filename=filename,
        )

        s3_key = url_info["s3_key"]
        self.uploaded_files.append(s3_key)
        print(f"[+] Uploaded to S3 successfully")
        return s3_key

    def complete_scan(
        self,
        meta: Optional[Dict[str, Any]] = None,
        resource_counts: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        스캔 완료 알림
        
        Args:
            meta: 추가 메타데이터 (resource_counts 등)
        """
        if not self.scan_id:
            raise ValueError("scan_id is None. Call start_scan() first.")

        if not self.uploaded_files:
            raise ValueError("No files uploaded. Call upload_scan_result() first.")

        json_body: Dict[str, Any] = {
            "files": self.uploaded_files,
        }

        if resource_counts is not None:
            json_body["resource_counts"] = resource_counts
        if meta:
            json_body["meta"] = meta

        data = self.engine_client.complete_scan(
            scan_id=self.scan_id,
            json_body=json_body,
        )

        status = data.get("status", "unknown")
        print(f"[+] Scan completed: {self.scan_id} → {status}")

        return data

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

    def full_scan_flow(
        self,
        scanner_type: str,
        payload: Dict[str, Any],
        trigger_mode: str = "scheduled",
        filename: str = "scan.json",
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        전체 스캔 플로우 실행 (start → upload → complete)
        
        Returns:
            {
                "scan_id": "...",
                "s3_key": "...",
                "status": "...",
            }
        """
        request_source = "manual" if trigger_mode == "manual" else "scheduled"
        scan_id = self.start_scan(scanner_type, request_source)
        s3_key = self.upload_scan_result(payload, filename)
        complete_result = self.complete_scan(meta)

        return {
            "scan_id": scan_id,
            "s3_key": s3_key,
            "status": complete_result.get("status", "unknown"),
            "complete_response": complete_result,
        }

    def _serialize_payload(self, payload: Dict[str, Any]) -> bytes:
        return json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            default=str,
        ).encode("utf-8")