from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import List, Optional
from uuid import UUID

logger = logging.getLogger(__name__)


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


def _getenv_first(*names: str, default: Optional[str] = None) -> Optional[str]:
    """여러 환경변수 이름 중 처음 값이 있는 것을 반환 (alias 지원용)."""
    for name in names:
        value = os.getenv(name)
        if value:
            return value
    return default


def _validate_cluster_id(raw_value: str) -> str:
    cluster_id = raw_value.strip()
    if not cluster_id:
        raise ValueError("DG_CLUSTER_ID (or CLUSTER_ID) must not be empty")
    if "/" in cluster_id:
        raise ValueError("cluster_id must not contain '/'")
    try:
        UUID(cluster_id)
    except ValueError as exc:
        raise ValueError(
            "DG_CLUSTER_ID (or CLUSTER_ID) must be the exact cluster ID issued by the cluster registration API "
            "(UUID format), for example: f1e96491-a558-4403-b363-e0c68d9a8c22"
        ) from exc
    return cluster_id


def _validate_choice(name: str, value: str, allowed: set) -> str:
    normalized = value.strip()
    if normalized not in allowed:
        raise ValueError(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return normalized


def _resolve_iam_role_filter_mode(raw: str) -> str:
    """
    Backward compatibility:
    기존 환경에서 DG_IAM_ROLE_FILTER_MODE=k8s_related를 사용하던 경우
    "all"로 조용히 매핑한다.
    scanner는 raw 수집기이므로 추측 기반 필터링을 기본으로 두지 않는다.
    """
    normalized = raw.strip()
    if normalized == "k8s_related":
        logger.warning(
            "DG_IAM_ROLE_FILTER_MODE=k8s_related is deprecated. "
            "Treating as 'all'. Use 'all' or 'specified' instead."
        )
        return "all"
    return _validate_choice("DG_IAM_ROLE_FILTER_MODE", normalized, {"all", "specified"})


@dataclass(frozen=True)
class ScannerConfig:
    cluster_id: str
    region: str
    api_url: str
    api_token: Optional[str] = None

    role_arn: Optional[str] = None
    aws_account_id: Optional[str] = None
    external_id: Optional[str] = None
    session_name: str = "DeployGuardCloudScanner"
    assume_role_duration_seconds: int = 3600

    scanner_type: str = "aws"
    scan_type: str = "full"
    upload_file_name: str = "aws-snapshot.json"

    http_timeout_seconds: int = 30
    upload_timeout_seconds: int = 300
    max_retries: int = 3
    backoff_seconds: int = 1

    save_local_copy: bool = True
    output_dir: str = "./output"
    output_filename: Optional[str] = None

    # IAM User 수집 필터
    # "active_keys_only" (기본): Active Access Key가 있는 User만 (console-only 제외)
    # "all": 전체 User / "specified": specified_users에 지정된 User만
    iam_user_filter_mode: str = "active_keys_only"
    iam_user_specified_users: List[str] = field(default_factory=list)

    # IAM Role 수집 필터
    # "all" (기본): 전체 Role 수집
    # "specified": specified_roles에 지정된 Role만
    # (k8s_related는 deprecated → 자동으로 "all"로 처리)
    iam_role_filter_mode: str = "all"
    iam_role_specified_roles: List[str] = field(default_factory=list)

    # EC2 수집 필터
    # "tag_match" (기본) / "specified" / "all"
    ec2_filter_mode: str = "tag_match"
    # tag_patterns: config 호환성 유지용. worker 판별 자체에는 사용하지 않는다.
    ec2_tag_patterns: List[str] = field(default_factory=lambda: [
        "kubernetes.io/cluster/*",
        "k8s.io/*",
        "k8s-*",
    ])
    ec2_specified_instance_ids: List[str] = field(default_factory=list)

    rds_filter_mode: str = "all"
    rds_specified_identifiers: List[str] = field(default_factory=list)

    s3_filter_mode: str = "all"
    s3_specified_buckets: List[str] = field(default_factory=list)

    aws_recommended_cron_schedule: str = "22 */4 * * *"
    scan_poll_path: str = "/api/v1/scans/pending"

    @staticmethod
    def from_env() -> "ScannerConfig":
        raw_cluster_id = _getenv_first("DG_CLUSTER_ID", "CLUSTER_ID")
        region = _getenv_first("AWS_REGION", "DG_REGION")
        api_url = (
            _getenv_first(
                "API_BASE_URL", "DG_API_ENDPOINT", "API_URL",
                "DG_API_URL", "DG_ENGINE_URL",
            )
            or "https://analysis.deployguard.org"
        )

        missing = [
            name for name, value in {
                "DG_CLUSTER_ID or CLUSTER_ID": raw_cluster_id,
                "AWS_REGION or DG_REGION": region,
            }.items()
            if not value
        ]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

        cluster_id = _validate_cluster_id(raw_cluster_id)

        iam_user_filter_mode = _validate_choice(
            "DG_IAM_USER_FILTER_MODE",
            _getenv_first("DG_IAM_USER_FILTER_MODE", default="active_keys_only"),
            {"active_keys_only", "all", "specified"},
        )

        # backward compat: k8s_related → all
        iam_role_filter_mode = _resolve_iam_role_filter_mode(
            _getenv_first("DG_IAM_ROLE_FILTER_MODE", default="all")
        )

        ec2_filter_mode = _validate_choice(
            "DG_EC2_FILTER_MODE",
            _getenv_first("DG_EC2_FILTER_MODE", default="tag_match"),
            {"tag_match", "specified", "all"},
        )
        rds_filter_mode = _validate_choice(
            "DG_RDS_FILTER_MODE",
            _getenv_first("DG_RDS_FILTER_MODE", default="all"),
            {"all", "specified"},
        )
        s3_filter_mode = _validate_choice(
            "DG_S3_FILTER_MODE",
            _getenv_first("DG_S3_FILTER_MODE", default="all"),
            {"all", "specified"},
        )
        scan_type = _validate_choice(
            "DG_SCAN_TYPE",
            # DG_SCAN_TYPE 우선, 없으면 SCAN_TYPE(구형 alias) 수용
            _getenv_first("DG_SCAN_TYPE", "SCAN_TYPE", default="full"),
            {"full", "incremental"},
        )
        scanner_type = _validate_choice(
            "SCANNER_TYPE",
            # SCANNER_TYPE 우선, 없으면 DG_SCANNER_TYPE(구형 alias) 수용
            _getenv_first("SCANNER_TYPE", "DG_SCANNER_TYPE", default="aws"),
            {"aws"},
        )

        return ScannerConfig(
            cluster_id=cluster_id,
            region=region.strip(),
            api_url=api_url.rstrip("/"),
            api_token=_getenv_first("DG_API_TOKEN", "API_TOKEN"),
            role_arn=os.getenv("DG_ROLE_ARN"),
            aws_account_id=os.getenv("DG_AWS_ACCOUNT_ID"),
            external_id=os.getenv("DG_EXTERNAL_ID"),
            session_name=_getenv_first("DG_SESSION_NAME", default="DeployGuardCloudScanner"),
            assume_role_duration_seconds=int(
                _getenv_first("DG_ASSUME_ROLE_DURATION", default="3600")
            ),
            scanner_type=scanner_type,
            scan_type=scan_type,
            upload_file_name=_getenv_first("DG_UPLOAD_FILE_NAME", default="aws-snapshot.json"),
            http_timeout_seconds=int(_getenv_first("DG_HTTP_TIMEOUT_SECONDS", default="30")),
            upload_timeout_seconds=int(_getenv_first("DG_UPLOAD_TIMEOUT_SECONDS", default="300")),
            max_retries=int(_getenv_first("DG_MAX_RETRIES", default="3")),
            backoff_seconds=int(_getenv_first("DG_BACKOFF_SECONDS", default="1")),
            save_local_copy=_get_bool("DG_SAVE_LOCAL_COPY", True),
            output_dir=_getenv_first("DG_OUTPUT_DIR", default="./output"),
            output_filename=os.getenv("DG_OUTPUT_FILENAME"),
            iam_user_filter_mode=iam_user_filter_mode,
            iam_user_specified_users=_get_csv_list("DG_IAM_USER_SPECIFIED_USERS"),
            iam_role_filter_mode=iam_role_filter_mode,
            iam_role_specified_roles=_get_csv_list("DG_IAM_ROLE_SPECIFIED_ROLES"),
            ec2_filter_mode=ec2_filter_mode,
            ec2_tag_patterns=_get_csv_list(
                "DG_EC2_TAG_PATTERNS",
                ["kubernetes.io/cluster/*", "k8s.io/*", "k8s-*"],
            ),
            ec2_specified_instance_ids=_get_csv_list("DG_EC2_SPECIFIED_INSTANCE_IDS"),
            rds_filter_mode=rds_filter_mode,
            rds_specified_identifiers=_get_csv_list("DG_RDS_SPECIFIED_IDENTIFIERS"),
            s3_filter_mode=s3_filter_mode,
            s3_specified_buckets=_get_csv_list("DG_S3_SPECIFIED_BUCKETS"),
            aws_recommended_cron_schedule=_getenv_first(
                "DG_AWS_CRON_SCHEDULE", default="22 */4 * * *"
            ),
            scan_poll_path=_getenv_first(
                "DG_SCAN_POLL_PATH", default="/api/v1/scans/pending"
            ),
        )