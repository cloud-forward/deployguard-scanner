"""S3로 결과 업로드 - 실제 S3 구조에 맞춤"""
import logging
import json
import gzip
from datetime import datetime
from typing import Optional

from ..config import Config
from ..models.schemas import ScanResult

logger = logging.getLogger(__name__)


class S3Exporter:
    """S3로 업로드 - 실제 구조에 맞춤"""
    
    def __init__(self, cfg: Config):
        self.config = cfg
        self.client = None
        self._init_client()
    
    def _init_client(self):
        """S3 클라이언트 초기화"""
        if not self.config.s3_bucket:
            logger.info("S3 bucket not configured - S3 export disabled")
            return
        
        try:
            import boto3
            self.client = boto3.client('s3', region_name=self.config.s3_region)
            logger.info(f"S3 client initialized for bucket: {self.config.s3_bucket}")
        except ImportError:
            logger.warning("boto3 not installed - S3 export disabled")
        except Exception as e:
            logger.error(f"Failed to initialize S3 client: {e}")
    
    def _get_timestamp(self) -> str:
        """타임스탬프 생성: YYYYMMDDTHHMMSS"""
        return datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    
    def export(self, result: ScanResult) -> bool:
        """S3로 업로드 - K8s와 Image 분리"""
        if not self.client or not self.config.s3_bucket:
            return False
        
        try:
            cluster_id = result.metadata.cluster_id
            timestamp = self._get_timestamp()
            
            # K8s 결과 업로드
            k8s_success = self._upload_k8s(cluster_id, timestamp, result)
            
            # Image 결과 업로드 (이미지가 있을 때만)
            image_success = True
            if result.images:
                image_success = self._upload_images(cluster_id, timestamp, result)
            
            return k8s_success and image_success
            
        except Exception as e:
            logger.error(f"S3 upload failed: {e}")
            return False
    
    def _upload_k8s(self, cluster_id: str, timestamp: str, result: ScanResult) -> bool:
        """K8s 결과 업로드"""
        try:
            # 경로: {cluster_id}/{timestamp}-k8s/resources.json
            key = f"{cluster_id}/{timestamp}-k8s/resources.json"
            
            data = {
                "metadata": {
                    "scan_id": result.metadata.scan_id,
                    "cluster_id": result.metadata.cluster_id,
                    "cluster_name": result.metadata.cluster_name,
                    "scan_timestamp": result.metadata.scan_timestamp,
                    "scanner_version": result.metadata.scanner_version,
                    "scan_type": "k8s",
                },
                "resources": {
                    "namespaces": [self._to_dict(ns) for ns in result.k8s.namespaces],
                    "nodes": [self._to_dict(n) for n in result.k8s.nodes],
                    "workloads": [self._to_dict(w) for w in result.k8s.workloads],
                    "services": [self._to_dict(s) for s in result.k8s.services],
                    "ingresses": [self._to_dict(i) for i in result.k8s.ingresses],
                    "service_accounts": [self._to_dict(sa) for sa in result.k8s.service_accounts],
                    "rbac": [self._to_dict(r) for r in result.k8s.rbac],
                    "network_policies": [self._to_dict(np) for np in result.k8s.network_policies],
                    "secrets": [self._to_dict(s) for s in result.k8s.secrets],
                    "configmaps": [self._to_dict(cm) for cm in result.k8s.configmaps],
                    "persistent_volumes": [self._to_dict(pv) for pv in result.k8s.persistent_volumes],
                    "persistent_volume_claims": [self._to_dict(pvc) for pvc in result.k8s.persistent_volume_claims],
                    "limit_ranges": [self._to_dict(lr) for lr in result.k8s.limit_ranges],
                    "resource_quotas": [self._to_dict(rq) for rq in result.k8s.resource_quotas],
                }
            }
            
            self._upload_json(key, data)
            logger.info(f"K8s results uploaded: s3://{self.config.s3_bucket}/{key}")
            return True
            
        except Exception as e:
            logger.error(f"K8s upload failed: {e}")
            return False
    
    def _upload_images(self, cluster_id: str, timestamp: str, result: ScanResult) -> bool:
        """Image 결과 업로드"""
        try:
            # 경로: {cluster_id}/{timestamp}-image/vulnerabilities.json
            key = f"{cluster_id}/{timestamp}-image/vulnerabilities.json"
            
            data = {
                "metadata": {
                    "scan_id": result.metadata.scan_id,
                    "cluster_id": result.metadata.cluster_id,
                    "cluster_name": result.metadata.cluster_name,
                    "scan_timestamp": result.metadata.scan_timestamp,
                    "scanner_version": result.metadata.scanner_version,
                    "scan_type": "image",
                },
                "images": [self._to_dict(img) for img in result.images],
                "summary": {
                    "total_images": len(result.images),
                    "critical": sum(img.summary.get("CRITICAL", 0) for img in result.images),
                    "high": sum(img.summary.get("HIGH", 0) for img in result.images),
                    "medium": sum(img.summary.get("MEDIUM", 0) for img in result.images),
                    "low": sum(img.summary.get("LOW", 0) for img in result.images),
                }
            }
            
            self._upload_json(key, data)
            logger.info(f"Image results uploaded: s3://{self.config.s3_bucket}/{key}")
            return True
            
        except Exception as e:
            logger.error(f"Image upload failed: {e}")
            return False
    
    def _upload_json(self, key: str, data: dict):
        """JSON 데이터를 S3에 업로드"""
        json_str = json.dumps(data, default=str, ensure_ascii=False, indent=2)
        
        self.client.put_object(
            Bucket=self.config.s3_bucket,
            Key=key,
            Body=json_str.encode('utf-8'),
            ContentType='application/json'
        )
    
    def _to_dict(self, obj) -> dict:
        """객체를 dict로 변환"""
        if hasattr(obj, '__dict__'):
            return {k: v for k, v in obj.__dict__.items() if not k.startswith('_')}
        return obj


def save_local(result: ScanResult, base_path: str = "."):
    """로컬에 S3 구조대로 저장 (테스트용)"""
    import os
    
    cluster_id = result.metadata.cluster_id
    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%S")
    
    # K8s 폴더
    k8s_dir = os.path.join(base_path, cluster_id, f"{timestamp}-k8s")
    os.makedirs(k8s_dir, exist_ok=True)
    
    k8s_data = {
        "metadata": result.metadata.__dict__ if hasattr(result.metadata, '__dict__') else result.metadata,
        "resources": result.k8s.__dict__ if hasattr(result.k8s, '__dict__') else result.k8s,
    }
    
    with open(os.path.join(k8s_dir, "resources.json"), 'w', encoding='utf-8') as f:
        json.dump(k8s_data, f, default=str, ensure_ascii=False, indent=2)
    
    logger.info(f"K8s saved: {k8s_dir}/resources.json")
    
    # Image 폴더 (이미지가 있을 때만)
    if result.images:
        image_dir = os.path.join(base_path, cluster_id, f"{timestamp}-image")
        os.makedirs(image_dir, exist_ok=True)
        
        image_data = {
            "metadata": result.metadata.__dict__ if hasattr(result.metadata, '__dict__') else result.metadata,
            "images": [img.__dict__ if hasattr(img, '__dict__') else img for img in result.images],
        }
        
        with open(os.path.join(image_dir, "vulnerabilities.json"), 'w', encoding='utf-8') as f:
            json.dump(image_data, f, default=str, ensure_ascii=False, indent=2)
        
        logger.info(f"Image saved: {image_dir}/vulnerabilities.json")
    
    return f"{cluster_id}/{timestamp}"