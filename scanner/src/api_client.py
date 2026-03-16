from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

import requests

from .config import ScannerConfig


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
        self.scan_id: Optional[str] = None
        self.scanner_type: Optional[str] = None
        self.uploaded_files: List[str] = []

    def start_scan(self, scanner_type: str, trigger_mode: str = "scheduled") -> str:
        """
        스캔 시작 등록
        
        Args:
            scanner_type: k8s, image, aws
            trigger_mode: manual, scheduled
            
        Returns:
            scan_id
        """
        response = self._request_with_retry(
            method="POST",
            url=f"{self.base_url}/api/scans/start",
            json_body={
                "cluster_id": self.config.cluster_id,
                "scanner_type": scanner_type,
                "trigger_mode": trigger_mode,
            },
        )
        
        data = response.json()
        self.scan_id = data.get("scan_id")
        self.scanner_type = scanner_type
        self.uploaded_files = []
        
        if not self.scan_id:
            raise RuntimeError(f"scan_id not found in response: {data}")
        
        print(f"[+] Scan started: {self.scan_id}")
        return str(self.scan_id)

    def get_upload_url(self, filename: str = "scan.json") -> Dict[str, Any]:
        """
        S3 Presigned URL 획득
        
        Returns:
            {
                "upload_url": "https://s3...",
                "s3_key": "scans/{cluster_id}/{scan_id}/{scanner_type}/scan.json"
            }
        """
        if not self.scan_id:
            raise ValueError("scan_id is None. Call start_scan() first.")
        
        response = self._request_with_retry(
            method="POST",
            url=f"{self.base_url}/api/scans/{self.scan_id}/upload-url",
            json_body={
                "file_name": filename,
                "scanner_type": self.scanner_type,
            },
        )
        
        data = response.json()
        
        # presigned_url 또는 upload_url 필드 처리
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
        json_bytes = json.dumps(
            payload, 
            ensure_ascii=False, 
            indent=2, 
            default=str
        ).encode("utf-8")
        
        last_error: Optional[Exception] = None
        
        for attempt in range(self.config.max_retries):
            try:
                response = requests.put(
                    upload_url,
                    data=json_bytes,
                    headers={"Content-Type": "application/json"},
                    timeout=self.config.upload_timeout_seconds,
                )
                
                if 200 <= response.status_code < 300:
                    print(f"[+] Uploaded to S3 successfully")
                    return True
                
                if response.status_code in {403, 408, 429} or response.status_code >= 500:
                    last_error = RuntimeError(
                        f"S3 upload failed: {response.status_code} - {response.text[:200]}"
                    )
                    self._sleep_before_retry(attempt)
                    continue
                
                raise RuntimeError(
                    f"S3 upload failed: {response.status_code} - {response.text[:200]}"
                )
                
            except requests.Timeout as e:
                last_error = e
                self._sleep_before_retry(attempt)
            except requests.RequestException as e:
                last_error = e
                self._sleep_before_retry(attempt)
        
        if last_error:
            raise RuntimeError(f"S3 upload failed after {self.config.max_retries} retries: {last_error}")
        return False

    def upload_scan_result(self, payload: Dict[str, Any], filename: str = "scan.json") -> str:
        """
        스캔 결과 업로드 (get_upload_url + upload_to_s3 통합)
        
        Returns:
            s3_key
        """
        url_info = self.get_upload_url(filename)
        self.upload_to_s3(url_info["upload_url"], payload)
        
        s3_key = url_info["s3_key"]
        self.uploaded_files.append(s3_key)
        
        return s3_key

    def complete_scan(self, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
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
        
        if meta:
            json_body["meta"] = meta
        
        response = self._request_with_retry(
            method="POST",
            url=f"{self.base_url}/api/scans/{self.scan_id}/complete",
            json_body=json_body,
        )
        
        data = response.json()
        status = data.get("status", "unknown")
        print(f"[+] Scan completed: {self.scan_id} → {status}")
        
        return data

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
        scan_id = self.start_scan(scanner_type, trigger_mode)
        s3_key = self.upload_scan_result(payload, filename)
        complete_result = self.complete_scan(meta)
        
        return {
            "scan_id": scan_id,
            "s3_key": s3_key,
            "status": complete_result.get("status", "unknown"),
            "complete_response": complete_result,
        }

    def _request_with_retry(
        self,
        method: str,
        url: str,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """재시도 로직이 포함된 HTTP 요청"""
        last_error: Optional[Exception] = None
        
        for attempt in range(self.config.max_retries):
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    json=json_body,
                    timeout=self.config.http_timeout_seconds,
                )
                
                if 200 <= response.status_code < 300:
                    return response
                
                # 재시도 가능한 에러
                if response.status_code in {408, 429, 502, 503, 504}:
                    last_error = RuntimeError(
                        f"Request failed: {response.status_code} - {response.text[:200]}"
                    )
                    self._sleep_before_retry(attempt)
                    continue
                
                # 재시도 불가능한 에러
                response.raise_for_status()
                
            except requests.Timeout as e:
                last_error = e
                self._sleep_before_retry(attempt)
            except requests.RequestException as e:
                last_error = e
                self._sleep_before_retry(attempt)
        
        if last_error:
            raise RuntimeError(f"Request failed after {self.config.max_retries} retries: {last_error}")
        raise RuntimeError(f"Request failed: {method} {url}")

    def _sleep_before_retry(self, attempt: int) -> None:
        if attempt >= self.config.max_retries - 1:
            return
        sleep_time = self.config.backoff_seconds * (2 ** attempt)
        print(f"[*] Retrying in {sleep_time}s...")
        time.sleep(sleep_time)