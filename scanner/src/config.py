from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional


def _get_bool(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def _get_csv_list(name: str, default: Optional[List[str]] = None) -> List[str]:
    value = os.getenv(name)
    if not value:
        return list(default or [])
    return [item.strip() for item in value.split(",") if item.strip()]


@dataclass(frozen=True)
class ScannerConfig:
    """
    K8s + Image Scanner 설정
    
    Fact Extractor와 호환되는 데이터 구조를 생성하기 위한 설정
    """

    # 필수 설정
    cluster_id: str
    api_url: str
    api_token: Optional[str] = None

    # 클러스터 정보
    cluster_name: Optional[str] = None
    cluster_type: str = "unknown"  # eks, self-managed, unknown

    # 스캐너 타입 설정
    scanner_type: str = "all"  # k8s, image, all
    upload_file_name: str = "scan.json"

    # 네임스페이스 필터링
    namespaces: List[str] = field(default_factory=list)
    exclude_namespaces: List[str] = field(default_factory=lambda: [
        "kube-system", "kube-public", "kube-node-lease"
    ])
    include_system_namespaces: bool = False  # kube-system 포함 여부

    # Trivy 설정 (Image 스캐너)
    trivy_enabled: bool = True
    trivy_severity: str = "CRITICAL,HIGH,MEDIUM,LOW"
    trivy_timeout: str = "5m"
    max_images_per_scan: int = 100

    # EPSS 설정
    epss_enabled: bool = True
    epss_cache_hours: int = 24

    # API 통신 설정
    http_timeout_seconds: int = 30
    upload_timeout_seconds: int = 300
    max_retries: int = 3
    backoff_seconds: int = 1

    # 로컬 저장 설정
    save_local_copy: bool = True
    output_dir: str = "./output"
    output_filename: Optional[str] = None

    # 권장 스케줄
    k8s_recommended_cron_schedule: str = "*/30 * * * *"
    image_recommended_cron_schedule: str = "0 */6 * * *"
    scan_poll_path: str = "/api/scans/poll"

    @staticmethod
    def from_env() -> "ScannerConfig":
        cluster_id = os.getenv("CLUSTER_ID") or os.getenv("DG_CLUSTER_ID")
        api_url = (
            os.getenv("DG_API_ENDPOINT")
            or os.getenv("API_URL")
            or os.getenv("DG_API_URL")
            or os.getenv("DG_ENGINE_URL")
        )

        if not cluster_id:
            raise ValueError("Missing required environment variable: CLUSTER_ID or DG_CLUSTER_ID")

        if not api_url:
            api_url = "https://analysis.deployguard.org"

        scanner_type = os.getenv("DG_SCANNER_TYPE", "all").strip().lower()
        if scanner_type not in {"k8s", "image", "all"}:
            raise ValueError("DG_SCANNER_TYPE must be one of: k8s, image, all")

        return ScannerConfig(
            cluster_id=cluster_id,
            api_url=api_url.rstrip("/"),
            api_token=os.getenv("DG_API_TOKEN") or os.getenv("API_TOKEN"),
            cluster_name=os.getenv("CLUSTER_NAME") or os.getenv("DG_CLUSTER_NAME") or cluster_id,
            cluster_type=os.getenv("DG_CLUSTER_TYPE", "unknown"),
            scanner_type=scanner_type,
            upload_file_name=os.getenv("DG_UPLOAD_FILE_NAME", "scan.json"),
            namespaces=_get_csv_list("DG_NAMESPACES"),
            exclude_namespaces=_get_csv_list(
                "DG_EXCLUDE_NAMESPACES",
                ["kube-public", "kube-node-lease"]
            ),
            include_system_namespaces=_get_bool("DG_INCLUDE_SYSTEM_NAMESPACES", False),
            trivy_enabled=_get_bool("DG_TRIVY_ENABLED", True),
            trivy_severity=os.getenv("DG_TRIVY_SEVERITY", "CRITICAL,HIGH,MEDIUM,LOW"),
            trivy_timeout=os.getenv("DG_TRIVY_TIMEOUT", "5m"),
            max_images_per_scan=int(os.getenv("DG_MAX_IMAGES_PER_SCAN", "100")),
            epss_enabled=_get_bool("DG_EPSS_ENABLED", True),
            epss_cache_hours=int(os.getenv("DG_EPSS_CACHE_HOURS", "24")),
            http_timeout_seconds=int(os.getenv("DG_HTTP_TIMEOUT_SECONDS", "30")),
            upload_timeout_seconds=int(os.getenv("DG_UPLOAD_TIMEOUT_SECONDS", "300")),
            max_retries=int(os.getenv("DG_MAX_RETRIES", "3")),
            backoff_seconds=int(os.getenv("DG_BACKOFF_SECONDS", "1")),
            save_local_copy=_get_bool("DG_SAVE_LOCAL_COPY", True),
            output_dir=os.getenv("DG_OUTPUT_DIR", "./output"),
            output_filename=os.getenv("DG_OUTPUT_FILENAME"),
            k8s_recommended_cron_schedule=os.getenv("DG_K8S_CRON_SCHEDULE", "*/30 * * * *"),
            image_recommended_cron_schedule=os.getenv("DG_IMAGE_CRON_SCHEDULE", "0 */6 * * *"),
            scan_poll_path=os.getenv("DG_SCAN_POLL_PATH", "/api/scans/poll"),
        )
