"""DeployGuard API Client - S3 Presigned URL 방식"""

import json
import requests
from typing import List, Optional
from .config import ScannerConfig


class DeployGuardAPIClient:
    def __init__(self, base_url: str, config: ScannerConfig = None):
        self.base_url = base_url.rstrip('/')
        self.config = config or ScannerConfig()
        self.scan_id: Optional[str] = None
        self.scanner_type: Optional[str] = None
        self.s3_keys: List[str] = []

    def health_check(self) -> dict:
        resp = requests.get(f"{self.base_url}/health", timeout=10)
        resp.raise_for_status()
        return resp.json()

    def start_scan(self, cluster_id: str, scanner_type: str) -> str:
        resp = requests.post(
            f"{self.base_url}/api/scans/start",
            json={"cluster_id": cluster_id, "scanner_type": scanner_type},
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        self.scan_id = data["scan_id"]
        self.scanner_type = scanner_type
        self.s3_keys = []
        print(f"[+] Scan started: {self.scan_id}")
        return self.scan_id

    def get_upload_url(self, file_name: str) -> dict:
        if not self.scan_id:
            raise ValueError("scan_id가 없습니다. start_scan()을 먼저 호출하세요.")
        resp = requests.post(
            f"{self.base_url}/api/scans/{self.scan_id}/upload-url",
            json={"file_name": file_name},
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        print(f"[+] Got upload URL for: {data['s3_key']}")
        return data

    def upload_to_s3(self, upload_url: str, content: dict) -> bool:
        """S3에 직접 업로드 - 예쁘게 포맷팅"""
        json_data = json.dumps(content, ensure_ascii=False, default=str, indent=2)
        
        resp = requests.put(
            upload_url,
            data=json_data.encode('utf-8'),
            timeout=300
        )
        
        if resp.status_code == 200:
            print(f"[+] Uploaded to S3 successfully")
            return True
            
        print(f"[-] S3 upload failed: {resp.status_code}")
        print(f"[-] Response: {resp.text[:500]}")
        resp.raise_for_status()
        return False

    def upload_file(self, content: dict, file_name: str = "scan.json") -> str:
        url_info = self.get_upload_url(file_name)
        upload_url = url_info["upload_url"]
        s3_key = url_info["s3_key"]
        self.upload_to_s3(upload_url, content)
        self.s3_keys.append(s3_key)
        return s3_key

    def complete_scan(self) -> dict:
        if not self.scan_id:
            raise ValueError("scan_id가 없습니다.")
        if not self.s3_keys:
            raise ValueError("업로드된 파일이 없습니다.")
        resp = requests.post(
            f"{self.base_url}/api/scans/{self.scan_id}/complete",
            json={"files": self.s3_keys},
            timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        print(f"[+] Scan complete: {self.scan_id} → {data['status']}")
        return data

    def get_scan_status(self) -> dict:
        if not self.scan_id:
            raise ValueError("scan_id가 없습니다.")
        resp = requests.get(
            f"{self.base_url}/api/scans/{self.scan_id}/status",
            timeout=30
        )
        resp.raise_for_status()
        return resp.json()

    def upload_scan_result(self, cluster_id: str, scanner_type: str, scan_result: dict) -> str:
        self.start_scan(cluster_id, scanner_type)
        self.upload_file(scan_result, "scan.json")
        self.complete_scan()
        return self.scan_id
