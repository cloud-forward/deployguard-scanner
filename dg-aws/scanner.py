from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from .auth import AssumeRoleProvider
from .config import ScannerConfig
from .collectors import (
    EC2Collector,
    IAMCollector,
    RDSCollector,
    S3Collector,
    SecurityGroupCollector,
)


class CloudScanner:
    def __init__(self, config: ScannerConfig) -> None:
        self.config = config

        self.session = AssumeRoleProvider(
            role_arn=config.role_arn,
            region=config.region,
            session_name=config.session_name,
            external_id=config.external_id,
            duration_seconds=config.assume_role_duration_seconds,
        ).create_session()

        self.sts = self.session.client("sts", region_name=config.region)

    def run(self) -> Dict[str, Any]:
        scan_id = self._start_scan()
        aws_account_id = self._resolve_account_id()

        payload = self._collect_payload(scan_id=scan_id, aws_account_id=aws_account_id)

        local_output_file: Optional[str] = None
        if self.config.save_local_copy:
            local_output_file = self.save_json(payload)

        upload_info = self._upload_payload(scan_id=scan_id, payload=payload)
        engine_status = self._complete_scan(scan_id=scan_id, s3_keys=[upload_info["s3_key"]])

        return {
            "scan_id": scan_id,
            "engine_status": engine_status,
            "uploaded_files": [upload_info["s3_key"]],
            "local_output_file": local_output_file,
            "payload": payload,
        }

    def save_json(self, payload: Dict[str, Any]) -> str:
        os.makedirs(self.config.output_dir, exist_ok=True)
        filename = self.config.output_filename or f"{payload['scan_id']}.json"
        path = os.path.join(self.config.output_dir, filename)

        with open(path, "w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2, default=str)

        return path

    def _collect_payload(self, scan_id: str, aws_account_id: str) -> Dict[str, Any]:
        iam = IAMCollector(self.session)
        s3 = S3Collector(self.session)
        rds = RDSCollector(self.session, self.config.region)
        ec2 = EC2Collector(
            session=self.session,
            region=self.config.region,
            cluster_id=self.config.cluster_id,
            filter_mode=self.config.ec2_filter_mode,
            tag_patterns=self.config.ec2_tag_patterns,
            specified_instance_ids=self.config.ec2_specified_instance_ids,
        )
        sg = SecurityGroupCollector(self.session, self.config.region)

        iam_roles = iam.collect_roles()
        iam_users = iam.collect_users(
            mode=self.config.iam_user_filter_mode,
            specified_users=self.config.iam_user_specified_users,
        )
        s3_buckets = s3.collect()
        rds_instances, rds_sg_ids = rds.collect()
        ec2_instances, ec2_sg_ids = ec2.collect_instances()
        security_groups = sg.collect(sorted(rds_sg_ids | ec2_sg_ids))

        return {
            "scan_id": scan_id,
            "aws_account_id": aws_account_id,
            "region": self.config.region,
            "scanned_at": self._utc_now_iso(),
            "iam_roles": iam_roles,
            "iam_users": iam_users,
            "s3_buckets": s3_buckets,
            "rds_instances": rds_instances,
            "ec2_instances": ec2_instances,
            "security_groups": security_groups,
        }

    def _resolve_account_id(self) -> str:
        discovered = self.sts.get_caller_identity()["Account"]
        if self.config.aws_account_id and self.config.aws_account_id != discovered:
            return discovered
        return self.config.aws_account_id or discovered

    def _start_scan(self) -> str:
        response = self._request_with_retry(
            method="POST",
            url=f"{self.config.engine_url}/api/scans/start",
            json_body={
                "cluster_id": self.config.cluster_id,
                "scanner_type": self.config.scanner_type,
            },
        )
        data = response.json()
        return data["scan_id"]

    def _get_upload_url(self, scan_id: str, file_name: str) -> Dict[str, Any]:
        response = self._request_with_retry(
            method="POST",
            url=f"{self.config.engine_url}/api/scans/{scan_id}/upload-url",
            json_body={"file_name": file_name},
        )
        return response.json()

    def _complete_scan(self, scan_id: str, s3_keys: List[str]) -> str:
        response = self._request_with_retry(
            method="POST",
            url=f"{self.config.engine_url}/api/scans/{scan_id}/complete",
            json_body={"files": s3_keys},
        )
        return response.json().get("status", "accepted")

    def _upload_payload(self, scan_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        payload_bytes = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

        last_error: Optional[Exception] = None

        for attempt in range(self.config.max_retries):
            upload_meta = self._get_upload_url(scan_id, self.config.upload_file_name)
            upload_url = upload_meta["upload_url"]

            try:
                response = requests.put(
                    upload_url,
                    data=payload_bytes,
                    headers={"Content-Type": "application/json"},
                    timeout=self.config.upload_timeout_seconds,
                )

                if response.status_code == 200:
                    return upload_meta

                if response.status_code == 403:
                    last_error = RuntimeError("Presigned URL expired or invalid.")
                    self._sleep_before_retry(attempt)
                    continue

                if 500 <= response.status_code < 600:
                    last_error = RuntimeError(f"S3 upload failed with {response.status_code}: {response.text}")
                    self._sleep_before_retry(attempt)
                    continue

                raise RuntimeError(f"S3 upload failed with {response.status_code}: {response.text}")

            except requests.Timeout as exc:
                last_error = exc
                self._sleep_before_retry(attempt)
            except requests.RequestException as exc:
                last_error = exc
                self._sleep_before_retry(attempt)

        if last_error:
            raise RuntimeError(f"Upload failed after retries: {last_error}") from last_error

        raise RuntimeError("Upload failed after retries.")

    def _request_with_retry(
        self,
        method: str,
        url: str,
        json_body: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        last_error: Optional[Exception] = None

        for attempt in range(self.config.max_retries):
            try:
                response = requests.request(
                    method=method,
                    url=url,
                    json=json_body,
                    timeout=self.config.http_timeout_seconds,
                )

                if 200 <= response.status_code < 300:
                    return response

                if 500 <= response.status_code < 600:
                    last_error = RuntimeError(f"{method} {url} failed with {response.status_code}: {response.text}")
                    self._sleep_before_retry(attempt)
                    continue

                raise RuntimeError(f"{method} {url} failed with {response.status_code}: {response.text}")

            except requests.Timeout as exc:
                last_error = exc
                self._sleep_before_retry(attempt)
            except requests.RequestException as exc:
                last_error = exc
                self._sleep_before_retry(attempt)

        if last_error:
            raise RuntimeError(f"Request failed after retries: {last_error}") from last_error

        raise RuntimeError(f"Request failed after retries: {method} {url}")

    def _sleep_before_retry(self, attempt: int) -> None:
        if attempt >= self.config.max_retries - 1:
            return
        time.sleep(self.config.backoff_seconds * (2 ** attempt))

    @staticmethod
    def _utc_now_iso() -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")