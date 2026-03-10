from __future__ import annotations

from typing import Optional

import boto3
from botocore.exceptions import ClientError


class AssumeRoleProvider:
    def __init__(
        self,
        role_arn: str,
        region: str,
        session_name: str,
        external_id: Optional[str] = None,
        duration_seconds: int = 3600,
        base_session: Optional[boto3.Session] = None,
    ) -> None:
        self.role_arn = role_arn
        self.region = region
        self.session_name = session_name
        self.external_id = external_id
        self.duration_seconds = duration_seconds
        self.base_session = base_session or boto3.Session(region_name=region)

    def create_session(self) -> boto3.Session:
        sts = self.base_session.client("sts", region_name=self.region)

        params = {
            "RoleArn": self.role_arn,
            "RoleSessionName": self.session_name,
            "DurationSeconds": self.duration_seconds,
        }
        if self.external_id:
            params["ExternalId"] = self.external_id

        try:
            response = sts.assume_role(**params)
        except ClientError as exc:
            raise RuntimeError(f"AssumeRole failed for {self.role_arn}: {exc}") from exc

        creds = response["Credentials"]

        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
            region_name=self.region,
        )