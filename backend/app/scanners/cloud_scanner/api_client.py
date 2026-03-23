from __future__ import annotations

from typing import Any, Dict, Optional

import boto3
from botocore.exceptions import ClientError

from .config import ScannerConfig
from shared.api_client import EngineApiClient
from shared.uploader import JsonResultUploader

S3_BUCKET = "dg-raw-scans"
REQUIRED_SCANNER_TYPES = {"k8s", "aws", "image"}


class DeployGuardApiClient:
    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self.engine_client = EngineApiClient(config)
        self.uploader = JsonResultUploader(config, self)
        self.scan_id: Optional[str] = None
        self.scanner_type: Optional[str] = None
        self.uploaded_files: list[str] = []

    def start_scan(self, scanner_type: str, request_source: str = "scheduled") -> str:
        """poll_scan으로 이미 claim된 scan_id가 있으므로 상태만 세팅."""
        if not self.scan_id:
            raise ValueError("scan_id is None. Call poll_scan() first.")
        self.scanner_type = scanner_type
        self.uploaded_files = []
        return str(self.scan_id)

    def bind_scan(self, scan_id: str, scanner_type: str) -> None:
        self.scan_id = scan_id
        self.scanner_type = scanner_type
        self.uploaded_files = []

    def poll_scan(self) -> Optional[Dict[str, Any]]:
        data = self.engine_client.poll_scan(
            path=self.config.scan_poll_path,
            query_params={
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
        scan_id: Optional[str] = None,
        scanner_type: Optional[str] = None,
        filename: str = "aws-snapshot.json",
    ) -> Dict[str, Any]:
        resolved_scan_id = scan_id or self.scan_id
        resolved_scanner_type = scanner_type or self.scanner_type
        if not resolved_scan_id:
            raise ValueError("scan_id is None. Call poll_scan() first.")
        if not resolved_scanner_type:
            raise ValueError("scanner_type is None. Call poll_scan() first.")

        data = self.engine_client.get_upload_url(
            scan_id=resolved_scan_id,
            json_body={
                "file_name": filename,
                "scanner_type": resolved_scanner_type,
            },
        )
        upload_url = data.get("upload_url") or data.get("presigned_url")
        s3_key = data.get("s3_key") or data.get("key") or data.get("file_key")
        if not upload_url:
            raise RuntimeError(f"upload_url not found in upload-url response: {data}")
        if not s3_key:
            s3_key = f"scans/{self.config.cluster_id}/{resolved_scan_id}/{resolved_scanner_type}/{filename}"
        return {"upload_url": upload_url, "s3_key": s3_key}

    def upload_to_s3(self, upload_url: str, content: bytes) -> None:
        self.uploader._upload_to_s3(upload_url, content)

    def upload_scan_result(self, payload: Dict[str, Any], filename: str = "aws-snapshot.json") -> str:
        if not self.scan_id:
            raise ValueError("scan_id is None. Call poll_scan() first.")
        if not self.scanner_type:
            raise ValueError("scanner_type is None. Call poll_scan() first.")

        upload_info = self.uploader.upload_scan_result(
            scan_id=self.scan_id,
            scanner_type=self.scanner_type,
            payload=payload,
            filename=filename,
        )
        s3_key = upload_info.get("s3_key") or upload_info.get("file_key")
        self.uploaded_files.append(s3_key)
        return s3_key

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
            raise ValueError("scan_id is None. Call poll_scan() first.")
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

    def trigger_analysis_if_ready(self) -> None:
        """
        S3에서 cluster_id 아래 k8s, aws, image 3개 스캔이 모두 있으면
        POST /api/v1/analysis/jobs 호출하여 분석 파이프라인 트리거
        """
        cluster_id = self.config.cluster_id
        region = getattr(self.config, "region", None) or "ap-northeast-2"

        try:
            s3 = boto3.client("s3", region_name=region)
            resp = s3.list_objects_v2(
                Bucket=S3_BUCKET,
                Prefix=f"scans/{cluster_id}/",
            )
        except ClientError as e:
            print(f"[-] S3 list failed: {e}")
            return

        scan_ids: Dict[str, Any] = {}
        for obj in resp.get("Contents", []):
            parts = obj["Key"].split("/")
            if len(parts) < 4:
                continue
            _, _cluster, scan_id, scanner_type = parts[0], parts[1], parts[2], parts[3]
            if scanner_type not in REQUIRED_SCANNER_TYPES:
                continue
            if scanner_type not in scan_ids or obj["LastModified"] > scan_ids[scanner_type][0]:
                scan_ids[scanner_type] = (obj["LastModified"], scan_id)

        latest = {k: v[1] for k, v in scan_ids.items()}

        if not REQUIRED_SCANNER_TYPES.issubset(latest.keys()):
            print(f"[*] Not all scans ready yet: {list(latest.keys())}")
            return

        print(f"[+] All 3 scans ready, triggering analysis: {latest}")
        try:
            resp = self.engine_client._request_with_retry(
                method="POST",
                url=f"{self.config.api_url}/api/v1/analysis/jobs",
                json_body={
                    "cluster_id": cluster_id,
                    "k8s_scan_id": latest["k8s"],
                    "aws_scan_id": latest["aws"],
                    "image_scan_id": latest["image"],
                },
            )
            print(f"[+] Analysis job triggered: {resp.json()}")
        except Exception as e:
            print(f"[-] Analysis trigger failed: {e}")
            raise