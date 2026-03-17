from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Optional
from uuid import UUID


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


def _validate_choice(name: str, value: str, allowed: set[str]) -> str:
    normalized = value.strip()
    if normalized not in allowed:
        raise ValueError(f"{name} must be one of: {', '.join(sorted(allowed))}")
    return normalized


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

    iam_user_filter_mode: str = "active_keys_only"
    iam_user_specified_users: List[str] = field(default_factory=list)

    iam_role_filter_mode: str = "k8s_related"
    iam_role_specified_roles: List[str] = field(default_factory=list)

    ec2_filter_mode: str = "tag_match"
    ec2_tag_patterns: List[str] = field(default_factory=lambda: [
        "kubernetes.io/cluster/*",
        "eks:cluster-name",
        "aws:eks:cluster-name",
        "k8s.io/*",
        "k8s-*",
        "*kubernetes*",
        "*k8s*",
    ])
    ec2_specified_instance_ids: List[str] = field(default_factory=list)

    rds_filter_mode: str = "all"
    rds_specified_identifiers: List[str] = field(default_factory=list)

    s3_filter_mode: str = "all"
    s3_specified_buckets: List[str] = field(default_factory=list)

    eks_cluster_names: List[str] = field(default_factory=list)

    aws_recommended_cron_schedule: str = "22 */4 * * *"
    scan_poll_path: str = "/api/v1/scans/pending"

    @staticmethod
    def from_env() -> "ScannerConfig":
        raw_cluster_id = os.getenv("DG_CLUSTER_ID") or os.getenv("CLUSTER_ID")
        region = os.getenv("AWS_REGION") or os.getenv("DG_REGION")
        api_url = (
            os.getenv("API_BASE_URL")
            or os.getenv("DG_API_ENDPOINT")
            or os.getenv("API_URL")
            or os.getenv("DG_API_URL")
            or os.getenv("DG_ENGINE_URL")
            or "https://analysis.deployguard.org"
        )

        missing = [
            name for name, value in {
                "DG_CLUSTER_ID or CLUSTER_ID": raw_cluster_id,
                "AWS_REGION or DG_REGION": region,
                "API_BASE_URL or DG_API_ENDPOINT or API_URL or DG_API_URL or DG_ENGINE_URL": api_url,
            }.items()
            if not value
        ]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

        cluster_id = _validate_cluster_id(raw_cluster_id)

        iam_user_filter_mode = _validate_choice(
            "DG_IAM_USER_FILTER_MODE",
            os.getenv("DG_IAM_USER_FILTER_MODE", "active_keys_only"),
            {"active_keys_only", "all", "specified"},
        )
        iam_role_filter_mode = _validate_choice(
            "DG_IAM_ROLE_FILTER_MODE",
            os.getenv("DG_IAM_ROLE_FILTER_MODE", "k8s_related"),
            {"k8s_related", "all", "specified"},
        )
        ec2_filter_mode = _validate_choice(
            "DG_EC2_FILTER_MODE",
            os.getenv("DG_EC2_FILTER_MODE", "tag_match"),
            {"tag_match", "specified", "all"},
        )
        rds_filter_mode = _validate_choice(
            "DG_RDS_FILTER_MODE",
            os.getenv("DG_RDS_FILTER_MODE", "all"),
            {"all", "specified"},
        )
        s3_filter_mode = _validate_choice(
            "DG_S3_FILTER_MODE",
            os.getenv("DG_S3_FILTER_MODE", "all"),
            {"all", "specified"},
        )
        scan_type = _validate_choice(
            "DG_SCAN_TYPE",
            os.getenv("DG_SCAN_TYPE", "full"),
            {"full", "incremental"},
        )
        scanner_type = _validate_choice(
            "SCANNER_TYPE",
            os.getenv("SCANNER_TYPE", "aws"),
            {"aws"},
        )

        return ScannerConfig(
            cluster_id=cluster_id,
            region=region.strip(),
            api_url=api_url.rstrip("/"),
            api_token=os.getenv("DG_API_TOKEN") or os.getenv("API_TOKEN"),
            role_arn=os.getenv("DG_ROLE_ARN"),
            aws_account_id=os.getenv("DG_AWS_ACCOUNT_ID"),
            external_id=os.getenv("DG_EXTERNAL_ID"),
            session_name=os.getenv("DG_SESSION_NAME", "DeployGuardCloudScanner"),
            assume_role_duration_seconds=int(os.getenv("DG_ASSUME_ROLE_DURATION", "3600")),
            scanner_type=scanner_type,
            scan_type=scan_type,
            upload_file_name=os.getenv("DG_UPLOAD_FILE_NAME", "aws-snapshot.json"),
            http_timeout_seconds=int(os.getenv("DG_HTTP_TIMEOUT_SECONDS", "30")),
            upload_timeout_seconds=int(os.getenv("DG_UPLOAD_TIMEOUT_SECONDS", "300")),
            max_retries=int(os.getenv("DG_MAX_RETRIES", "3")),
            backoff_seconds=int(os.getenv("DG_BACKOFF_SECONDS", "1")),
            save_local_copy=_get_bool("DG_SAVE_LOCAL_COPY", True),
            output_dir=os.getenv("DG_OUTPUT_DIR", "./output"),
            output_filename=os.getenv("DG_OUTPUT_FILENAME"),
            iam_user_filter_mode=iam_user_filter_mode,
            iam_user_specified_users=_get_csv_list("DG_IAM_USER_SPECIFIED_USERS"),
            iam_role_filter_mode=iam_role_filter_mode,
            iam_role_specified_roles=_get_csv_list("DG_IAM_ROLE_SPECIFIED_ROLES"),
            ec2_filter_mode=ec2_filter_mode,
            ec2_tag_patterns=_get_csv_list(
                "DG_EC2_TAG_PATTERNS",
                [
                    "kubernetes.io/cluster/*",
                    "eks:cluster-name",
                    "aws:eks:cluster-name",
                    "k8s.io/*",
                    "k8s-*",
                    "*kubernetes*",
                    "*k8s*",
                ],
            ),
            ec2_specified_instance_ids=_get_csv_list("DG_EC2_SPECIFIED_INSTANCE_IDS"),
            rds_filter_mode=rds_filter_mode,
            rds_specified_identifiers=_get_csv_list("DG_RDS_SPECIFIED_IDENTIFIERS"),
            s3_filter_mode=s3_filter_mode,
            s3_specified_buckets=_get_csv_list("DG_S3_SPECIFIED_BUCKETS"),
            eks_cluster_names=_get_csv_list("DG_EKS_CLUSTER_NAMES"),
            aws_recommended_cron_schedule=os.getenv("DG_AWS_CRON_SCHEDULE", "22 */4 * * *"),
            scan_poll_path=os.getenv("DG_SCAN_POLL_PATH", "/api/v1/scans/pending"),
        )
