"""설정 관리 - 환경변수 기반"""
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Config:
    # 클러스터 식별
    cluster_id: str
    cluster_name: str
    
    # API 설정
    api_endpoint: str
    api_key: str
    
    # 스캔 설정
    scan_namespaces: list[str]
    exclude_namespaces: list[str]
    
    # 이미지 스캐너 설정
    enable_image_scan: bool
    trivy_severity: str
    trivy_timeout: int
    
    # 로컬 저장 (디버깅/백업용)
    save_local: bool
    local_output_dir: str
    
    # 재시도 설정
    api_retry_count: int
    api_timeout: int
    
    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            # 클러스터 식별
            cluster_id=os.environ.get("CLUSTER_ID", ""),
            cluster_name=os.environ.get("CLUSTER_NAME", "default"),
            
            # API 설정
            api_endpoint=os.environ.get("API_ENDPOINT", "https://api.deployguard.io").rstrip('/'),
            api_key=os.environ.get("API_KEY", ""),
            
            # 스캔 설정
            scan_namespaces=_parse_list(os.environ.get("SCAN_NAMESPACES", "")),
            exclude_namespaces=_parse_list(os.environ.get("EXCLUDE_NAMESPACES", "kube-system,kube-public,kube-node-lease")),
            
            # 이미지 스캐너 설정
            enable_image_scan=os.environ.get("ENABLE_IMAGE_SCAN", "true").lower() == "true",
            trivy_severity=os.environ.get("TRIVY_SEVERITY", "CRITICAL,HIGH,MEDIUM"),
            trivy_timeout=int(os.environ.get("TRIVY_TIMEOUT", "300")),
            
            # 로컬 저장
            save_local=os.environ.get("SAVE_LOCAL", "false").lower() == "true",
            local_output_dir=os.environ.get("LOCAL_OUTPUT_DIR", "/tmp/scan-results"),
            
            # 재시도 설정
            api_retry_count=int(os.environ.get("API_RETRY_COUNT", "3")),
            api_timeout=int(os.environ.get("API_TIMEOUT", "60")),
        )
    
    def validate(self) -> list[str]:
        """설정 검증"""
        errors = []
        
        if not self.cluster_id:
            errors.append("CLUSTER_ID is required")
        
        if not self.api_key:
            errors.append("API_KEY is required")
        
        if not self.api_endpoint:
            errors.append("API_ENDPOINT is required")
        
        if self.api_endpoint and not self.api_endpoint.startswith(('http://', 'https://')):
            errors.append("API_ENDPOINT must start with http:// or https://")
        
        return errors
    
    def to_dict(self) -> dict:
        """설정을 dict로 변환 (로깅용, API_KEY 마스킹)"""
        return {
            "cluster_id": self.cluster_id,
            "cluster_name": self.cluster_name,
            "api_endpoint": self.api_endpoint,
            "api_key": self._mask_key(self.api_key),
            "scan_namespaces": self.scan_namespaces,
            "exclude_namespaces": self.exclude_namespaces,
            "enable_image_scan": self.enable_image_scan,
            "trivy_severity": self.trivy_severity,
            "trivy_timeout": self.trivy_timeout,
            "save_local": self.save_local,
            "api_retry_count": self.api_retry_count,
            "api_timeout": self.api_timeout,
        }
    
    @staticmethod
    def _mask_key(key: str) -> str:
        """API 키 마스킹"""
        if not key:
            return ""
        if len(key) <= 8:
            return "****"
        return key[:4] + "****" + key[-4:]


def _parse_list(value: str) -> list[str]:
    """콤마 구분 문자열을 리스트로 변환"""
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]