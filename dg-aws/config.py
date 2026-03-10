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
    cluster_id: str
    role_arn: str
    region: str
    engine_url: str

    aws_account_id: Optional[str] = None
    external_id: Optional[str] = None
    session_name: str = "DeployGuardCloudScanner"
    assume_role_duration_seconds: int = 3600

    scanner_type: str = "aws"
    upload_file_name: str = "scan.json"

    http_timeout_seconds: int = 30
    upload_timeout_seconds: int = 300
    max_retries: int = 3
    backoff_seconds: int = 1

    save_local_copy: bool = True
    output_dir: str = "./output"
    output_filename: Optional[str] = None

    iam_user_filter_mode: str = "active_keys_only"
    iam_user_specified_users: List[str] = field(default_factory=list)

    ec2_filter_mode: str = "tag_match"
    ec2_tag_patterns: List[str] = field(default_factory=lambda: [
        "kubernetes.io/cluster/*",
        "k8s-*",
        "*kubernetes*",
        "*k8s*",
    ])
    ec2_specified_instance_ids: List[str] = field(default_factory=list)

    @staticmethod
    def from_env() -> "ScannerConfig":
        cluster_id = os.getenv("DG_CLUSTER_ID")
        role_arn = os.getenv("DG_ROLE_ARN")
        region = os.getenv("AWS_REGION") or os.getenv("DG_REGION")
        engine_url = os.getenv("DG_ENGINE_URL")

        missing = [
            name for name, value in {
                "DG_CLUSTER_ID": cluster_id,
                "DG_ROLE_ARN": role_arn,
                "AWS_REGION or DG_REGION": region,
                "DG_ENGINE_URL": engine_url,
            }.items() if not value
        ]
        if missing:
            raise ValueError(f"Missing required environment variables: {', '.join(missing)}")

        iam_user_filter_mode = os.getenv("DG_IAM_USER_FILTER_MODE", "active_keys_only").strip()
        if iam_user_filter_mode not in {"active_keys_only", "all", "specified"}:
            raise ValueError("DG_IAM_USER_FILTER_MODE must be one of: active_keys_only, all, specified")

        ec2_filter_mode = os.getenv("DG_EC2_FILTER_MODE", "tag_match").strip()
        if ec2_filter_mode not in {"tag_match", "specified"}:
            raise ValueError("DG_EC2_FILTER_MODE must be one of: tag_match, specified")

        return ScannerConfig(
            cluster_id=cluster_id,
            role_arn=role_arn,
            region=region,
            engine_url=engine_url.rstrip("/"),
            aws_account_id=os.getenv("DG_AWS_ACCOUNT_ID"),
            external_id=os.getenv("DG_EXTERNAL_ID"),
            session_name=os.getenv("DG_SESSION_NAME", "DeployGuardCloudScanner"),
            assume_role_duration_seconds=int(os.getenv("DG_ASSUME_ROLE_DURATION", "3600")),
            scanner_type="aws",
            upload_file_name=os.getenv("DG_UPLOAD_FILE_NAME", "scan.json"),
            http_timeout_seconds=int(os.getenv("DG_HTTP_TIMEOUT_SECONDS", "30")),
            upload_timeout_seconds=int(os.getenv("DG_UPLOAD_TIMEOUT_SECONDS", "300")),
            max_retries=int(os.getenv("DG_MAX_RETRIES", "3")),
            backoff_seconds=int(os.getenv("DG_BACKOFF_SECONDS", "1")),
            save_local_copy=_get_bool("DG_SAVE_LOCAL_COPY", True),
            output_dir=os.getenv("DG_OUTPUT_DIR", "./output"),
            output_filename=os.getenv("DG_OUTPUT_FILENAME"),
            iam_user_filter_mode=iam_user_filter_mode,
            iam_user_specified_users=_get_csv_list("DG_IAM_USER_SPECIFIED_USERS"),
            ec2_filter_mode=ec2_filter_mode,
            ec2_tag_patterns=_get_csv_list(
                "DG_EC2_TAG_PATTERNS",
                ["kubernetes.io/cluster/*", "k8s-*", "*kubernetes*", "*k8s*"],
            ),
            ec2_specified_instance_ids=_get_csv_list("DG_EC2_SPECIFIED_INSTANCE_IDS"),
        )