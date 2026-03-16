import os
import subprocess
from dataclasses import dataclass, field
from typing import List, Optional


def _get_cluster_id() -> str:
    """
    클러스터 ID 가져오기
    
    우선순위:
    1. 환경변수 CLUSTER_ID (Helm에서 주입)
    2. 자동 탐지 (폴백)
    3. 기본값
    """
    # 1. Helm에서 주입한 환경변수 (최우선)
    env_cluster_id = os.getenv("CLUSTER_ID")
    if env_cluster_id:
        print(f"[INFO] Using cluster_id from env: {env_cluster_id}")
        return env_cluster_id
    
    # 2. 자동 탐지 (폴백)
    auto_detected = _auto_detect_cluster_id()
    if auto_detected and auto_detected != "unknown-cluster":
        print(f"[INFO] Auto-detected cluster_id: {auto_detected}")
        return auto_detected
    
    # 3. 기본값
    print("[WARN] Could not determine cluster_id, using 'unknown-cluster'")
    return "unknown-cluster"


def _auto_detect_cluster_id() -> Optional[str]:
    """
    자동 탐지 (폴백용)
    
    1. EC2 인스턴스 Name 태그
    2. kubectl context
    """
    # EC2 Name 태그 시도
    ec2_name = _get_ec2_instance_name()
    if ec2_name:
        return ec2_name
    
    # kubectl context 시도
    k8s_context = _get_k8s_context_name()
    if k8s_context:
        return k8s_context
    
    return None


def _get_ec2_instance_name() -> Optional[str]:
    """EC2 인스턴스 Name 태그 가져오기"""
    try:
        # IMDS v2 토큰
        token_result = subprocess.run(
            ["curl", "-s", "-X", "PUT",
             "http://169.254.169.254/latest/api/token",
             "-H", "X-aws-ec2-metadata-token-ttl-seconds: 21600"],
            capture_output=True, text=True, timeout=2
        )
        token = token_result.stdout.strip()
        
        # Instance ID
        instance_result = subprocess.run(
            ["curl", "-s",
             "http://169.254.169.254/latest/meta-data/instance-id",
             "-H", f"X-aws-ec2-metadata-token: {token}"],
            capture_output=True, text=True, timeout=2
        )
        instance_id = instance_result.stdout.strip()
        
        if not instance_id.startswith("i-"):
            return None
        
        # Name 태그 조회
        name_result = subprocess.run(
            ["aws", "ec2", "describe-tags",
             "--filters", f"Name=resource-id,Values={instance_id}",
             "Name=key,Values=Name",
             "--query", "Tags[0].Value", "--output", "text"],
            capture_output=True, text=True, timeout=5
        )
        name = name_result.stdout.strip()
        
        if name and name != "None":
            return name
    except:
        pass
    return None


def _get_k8s_context_name() -> Optional[str]:
    """kubectl context에서 클러스터 이름 추출"""
    try:
        result = subprocess.run(
            ["kubectl", "config", "current-context"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            context = result.stdout.strip()
            if "@" in context:
                return context.split("@")[-1]
            return context
    except:
        pass
    return None


def _get_cluster_name() -> str:
    """클러스터 표시 이름"""
    return os.getenv("CLUSTER_NAME") or _get_cluster_id()


@dataclass
class ScannerConfig:
    cluster_id: str = field(default_factory=_get_cluster_id)
    cluster_name: str = field(default_factory=_get_cluster_name)
    output_dir: str = field(default_factory=lambda: os.getenv("OUTPUT_DIR", "./output"))
    namespaces: List[str] = field(default_factory=list)
    exclude_namespaces: List[str] = field(default_factory=lambda: [
        "kube-system", "kube-public", "kube-node-lease"
    ])
    trivy_severity: str = field(default_factory=lambda: os.getenv("TRIVY_SEVERITY", "HIGH,CRITICAL"))
    trivy_timeout: str = field(default_factory=lambda: os.getenv("TRIVY_TIMEOUT", "5m"))
    max_images_per_scan: int = field(default_factory=lambda: int(os.getenv("MAX_IMAGES_PER_SCAN", "50")))