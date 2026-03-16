"""API로 스캔 결과 전송 - 새 API 흐름 (Presigned URL)"""
import logging
import json
import gzip
import time
from typing import Optional
from dataclasses import asdict

import requests

from ..config import Config
from ..models.schemas import ScanResult

logger = logging.getLogger(__name__)


class APIExporter:
    """
    Analysis Engine API로 결과 전송
    
    흐름:
    1. POST /api/v1/scans/start → scan_id 받기
    2. POST /api/v1/scans/{scan_id}/upload-url → presigned URL 받기
    3. PUT presigned URL → S3에 파일 업로드
    4. POST /api/v1/scans/{scan_id}/complete → 완료 알림
    """
    
    def __init__(self, cfg: Config):
        self.config = cfg
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {cfg.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "DeployGuard-Scanner/1.0",
        })
        self.base_url = cfg.api_endpoint.rstrip('/')
    
    def export(self, result: ScanResult) -> bool:
        """스캔 결과 전송 - 새로운 API 흐름"""
        try:
            # Step 1: 스캔 세션 시작
            scan_id = self._start_scan(result)
            if not scan_id:
                logger.error("Failed to start scan session")
                return False
            
            logger.info(f"Scan session started: {scan_id}")
            
            files_uploaded = []
            
            # Step 2-3: K8s 결과 업로드
            k8s_uploaded = self._upload_k8s(scan_id, result)
            if not k8s_uploaded:
                logger.error("Failed to upload K8s results")
                return False
            files_uploaded.append("k8s/resources.json")
            
            # Step 2-3: Image 결과 업로드 (있을 때만)
            if result.images:
                image_uploaded = self._upload_images(scan_id, result)
                if image_uploaded:
                    files_uploaded.append("images/vulnerabilities.json")
                else:
                    logger.warning("Failed to upload image results (continuing)")
            
            # Step 4: 완료 알림
            completed = self._complete_scan(scan_id, files_uploaded)
            if not completed:
                logger.error("Failed to complete scan")
                return False
            
            logger.info(f"Scan export completed successfully: {scan_id}")
            return True
            
        except Exception as e:
            logger.error(f"Export failed with exception: {e}")
            return False
    
    def _start_scan(self, result: ScanResult) -> Optional[str]:
        """Step 1: 스캔 세션 시작"""
        url = f"{self.base_url}/api/v1/scans/start"
        
        payload = {
            "cluster_id": result.metadata.cluster_id,
            "cluster_name": result.metadata.cluster_name,
            "scanner_version": result.metadata.scanner_version,
            "scan_timestamp": result.metadata.scan_timestamp,
            "scan_type": "k8s",
        }
        
        for attempt in range(self.config.api_retry_count):
            try:
                response = self.session.post(
                    url, 
                    json=payload, 
                    timeout=self.config.api_timeout
                )
                
                if response.status_code in (200, 201):
                    data = response.json()
                    return data.get("scan_id")
                else:
                    logger.warning(f"Start scan attempt {attempt + 1} failed: {response.status_code} - {response.text[:200]}")
                    
            except requests.exceptions.RequestException as e:
                logger.warning(f"Start scan attempt {attempt + 1} error: {e}")
            
            if attempt < self.config.api_retry_count - 1:
                time.sleep(2 ** attempt)  # Exponential backoff
        
        return None
    
    def _upload_k8s(self, scan_id: str, result: ScanResult) -> bool:
        """Step 2-3: K8s 결과 업로드"""
        # Presigned URL 받기
        upload_url = self._get_upload_url(scan_id, "k8s/resources.json")
        if not upload_url:
            return False
        
        # 데이터 준비
        k8s_data = {
            "metadata": self._to_dict(result.metadata),
            "resources": self._k8s_to_dict(result.k8s),
        }
        
        # S3에 업로드
        return self._upload_to_s3(upload_url, k8s_data)
    
    def _upload_images(self, scan_id: str, result: ScanResult) -> bool:
        """Step 2-3: Image 결과 업로드"""
        # Presigned URL 받기
        upload_url = self._get_upload_url(scan_id, "images/vulnerabilities.json")
        if not upload_url:
            return False
        
        # 데이터 준비
        image_data = {
            "metadata": self._to_dict(result.metadata),
            "images": [self._to_dict(img) for img in result.images],
        }
        
        # S3에 업로드
        return self._upload_to_s3(upload_url, image_data)
    
    def _get_upload_url(self, scan_id: str, file_path: str) -> Optional[str]:
        """Step 2: Presigned URL 받기"""
        url = f"{self.base_url}/api/v1/scans/{scan_id}/upload-url"
        
        for attempt in range(self.config.api_retry_count):
            try:
                response = self.session.post(
                    url,
                    json={"file_path": file_path},
                    timeout=self.config.api_timeout
                )
                
                if response.status_code == 200:
                    data = response.json()
                    return data.get("upload_url")
                else:
                    logger.warning(f"Get upload URL attempt {attempt + 1} failed: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.warning(f"Get upload URL attempt {attempt + 1} error: {e}")
            
            if attempt < self.config.api_retry_count - 1:
                time.sleep(2 ** attempt)
        
        return None
    
    def _upload_to_s3(self, upload_url: str, data: dict) -> bool:
        """Step 3: S3에 직접 업로드 (Presigned URL)"""
        try:
            # JSON 직렬화 + gzip 압축
            json_str = json.dumps(data, default=str, ensure_ascii=False)
            json_bytes = json_str.encode('utf-8')
            compressed = gzip.compress(json_bytes)
            
            logger.info(f"Uploading to S3: {len(json_bytes)} bytes -> {len(compressed)} bytes (compressed)")
            
            # Presigned URL로 PUT (Authorization 헤더 없이!)
            response = requests.put(
                upload_url,
                data=compressed,
                headers={
                    "Content-Type": "application/json",
                    "Content-Encoding": "gzip",
                },
                timeout=120
            )
            
            if response.status_code in (200, 201, 204):
                logger.info("S3 upload successful")
                return True
            else:
                logger.error(f"S3 upload failed: {response.status_code} - {response.text[:200]}")
                return False
                
        except Exception as e:
            logger.error(f"S3 upload error: {e}")
            return False
    
    def _complete_scan(self, scan_id: str, files: list[str]) -> bool:
        """Step 4: 스캔 완료 알림"""
        url = f"{self.base_url}/api/v1/scans/{scan_id}/complete"
        
        for attempt in range(self.config.api_retry_count):
            try:
                response = self.session.post(
                    url,
                    json={"files": files},
                    timeout=self.config.api_timeout
                )
                
                if response.status_code in (200, 202):
                    logger.info(f"Scan marked complete: {scan_id}")
                    return True
                else:
                    logger.warning(f"Complete scan attempt {attempt + 1} failed: {response.status_code}")
                    
            except requests.exceptions.RequestException as e:
                logger.warning(f"Complete scan attempt {attempt + 1} error: {e}")
            
            if attempt < self.config.api_retry_count - 1:
                time.sleep(2 ** attempt)
        
        return False
    
    def _to_dict(self, obj) -> dict:
        """객체를 dict로 변환"""
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        elif hasattr(obj, '__dict__'):
            result = {}
            for k, v in obj.__dict__.items():
                if not k.startswith('_'):
                    if hasattr(v, '__dict__'):
                        result[k] = self._to_dict(v)
                    elif isinstance(v, list):
                        result[k] = [self._to_dict(item) if hasattr(item, '__dict__') else item for item in v]
                    else:
                        result[k] = v
            return result
        elif isinstance(obj, dict):
            return obj
        else:
            return obj
    
    def _k8s_to_dict(self, k8s) -> dict:
        """K8s 리소스를 dict로 변환"""
        if hasattr(k8s, '__dict__'):
            result = {}
            for key, value in k8s.__dict__.items():
                if isinstance(value, list):
                    result[key] = [self._to_dict(item) for item in value]
                else:
                    result[key] = value
            return result
        return k8s
    
    def health_check(self) -> bool:
        """API 연결 확인"""
        try:
            response = self.session.get(
                f"{self.base_url}/health",
                timeout=10
            )
            return response.status_code == 200
        except:
            return False