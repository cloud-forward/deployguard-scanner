from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from .api_client import DeployGuardApiClient
from .auth import create_boto3_session, validate_credentials
from .config import ScannerConfig
from .collectors import (
    EC2Collector,
    EKSCollector,
    IAMCollector,
    RDSCollector,
    S3Collector,
    SecurityGroupCollector,
    VPCCollector,
    build_aws_payload,
)
from shared.orchestrator import ScanOrchestrator

logger = logging.getLogger(__name__)


class CloudScanner:
    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self.session = create_boto3_session(
            region=config.region,
            role_arn=config.role_arn,
            session_name=config.session_name,
            external_id=config.external_id,
            duration_seconds=config.assume_role_duration_seconds,
        )
        self.identity = validate_credentials(self.session, config.region)
        self.sts = self.session.client("sts", region_name=config.region)
        self.api_client = DeployGuardApiClient(config)

    def run_worker_scan(self, scan_id: str, trigger_mode: str = "scheduled") -> Dict[str, Any]:
        # poll_scan에서 이미 claim됐으므로 bind만 하고 바로 실행
        self.api_client.bind_scan(scan_id, self.config.scanner_type)
        return self._execute_scan(scan_id=scan_id, trigger_mode=trigger_mode)

    def _execute_scan(self, scan_id: str, trigger_mode: str) -> Dict[str, Any]:
        orchestrator = ScanOrchestrator(self.config, self.api_client)
        try:
            aws_account_id = self._resolve_account_id()
            payload = self._collect_all_resources(
                scan_id=scan_id,
                aws_account_id=aws_account_id,
                trigger_mode=trigger_mode,
            )

            local_output_file: Optional[str] = None
            if self.config.save_local_copy:
                local_output_file = self.save_json(payload)

            uploaded_files = [orchestrator.upload_result(payload, self.config.upload_file_name)]

            resource_counts = payload.get("resource_counts", {})

            complete_resp = orchestrator.complete_scan(
                resource_counts=resource_counts,
                meta={
                    "scanner_type": self.config.scanner_type,
                    "trigger_mode": trigger_mode,
                    "scan_type": self.config.scan_type,
                    "uploaded_file_name": self.config.upload_file_name,
                    "recommended_cron_schedule": self.config.aws_recommended_cron_schedule,
                },
            )

            return orchestrator.build_result(
                scan_id=scan_id,
                payload=payload,
                complete_result=complete_resp,
                uploaded_files=uploaded_files,
                local_file=local_output_file,
                extra={"resource_counts": resource_counts},
            )
        except KeyboardInterrupt:
            logger.warning("AWS scan interrupted", extra={"scan_id": scan_id})
            raise
        except Exception:
            logger.exception("AWS scan failed", extra={"scan_id": scan_id})
            raise

    def _collect_all_resources(
        self,
        scan_id: str,
        aws_account_id: str,
        trigger_mode: str,
    ) -> Dict[str, Any]:
        iam = IAMCollector(self.session)
        s3 = S3Collector(self.session)
        rds = RDSCollector(self.session, self.config.region)
        ec2 = EC2Collector(
            self.session,
            self.config.region,
            cluster_id=self.config.cluster_id,
            filter_mode=self.config.ec2_filter_mode,
            tag_patterns=self.config.ec2_tag_patterns,
            specified_instance_ids=self.config.ec2_specified_instance_ids,
        )
        eks = EKSCollector(
            self.session,
            self.config.region,
            cluster_names=self.config.eks_cluster_names,
        )
        vpc = VPCCollector(self.session, self.config.region)
        sg = SecurityGroupCollector(self.session, self.config.region)

        iam_roles = iam.collect_roles(
            mode=self.config.iam_role_filter_mode,
            specified_roles=self.config.iam_role_specified_roles,
        )
        iam_users = iam.collect_users(
            mode=self.config.iam_user_filter_mode,
            specified_users=self.config.iam_user_specified_users,
        )
        s3_buckets = s3.collect(
            mode=self.config.s3_filter_mode,
            specified_buckets=self.config.s3_specified_buckets,
        )
        rds_instances, rds_sg_ids = rds.collect(
            mode=self.config.rds_filter_mode,
            specified_identifiers=self.config.rds_specified_identifiers,
        )
        ec2_instances, ec2_sg_ids = ec2.collect_instances()
        eks_data = eks.collect()
        network = vpc.collect()

        eks_sg_ids: set[str] = set()
        for cluster in eks_data.get("clusters", []):
            cluster_sg_id = cluster.get("cluster_security_group_id")
            if cluster_sg_id:
                eks_sg_ids.add(cluster_sg_id)
            eks_sg_ids.update(cluster.get("security_group_ids", []))

        security_groups = sg.collect(sorted(rds_sg_ids | ec2_sg_ids | eks_sg_ids))

        return build_aws_payload(
            scan_id=scan_id,
            cluster_id=self.config.cluster_id,
            aws_account_id=aws_account_id,
            region=self.config.region,
            trigger_mode=trigger_mode,
            scan_type=self.config.scan_type,
            recommended_schedule=self.config.aws_recommended_cron_schedule,
            iam_roles=iam_roles,
            iam_users=iam_users,
            s3_buckets=s3_buckets,
            rds_instances=rds_instances,
            ec2_instances=ec2_instances,
            security_groups=security_groups,
            eks=eks_data,
            network=network,
        )

    def save_json(self, payload: Dict[str, Any]) -> str:
        os.makedirs(self.config.output_dir, exist_ok=True)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = self.config.output_filename or f"aws-scan-{timestamp}.json"
        filepath = os.path.join(self.config.output_dir, filename)

        with open(filepath, "w", encoding="utf-8") as file:
            json.dump(payload, file, ensure_ascii=False, indent=2, default=str)

        logger.info("Saved local copy: %s", filepath)
        return filepath

    def _resolve_account_id(self) -> str:
        if self.config.aws_account_id:
            return self.config.aws_account_id
        return str(self.identity.get("Account") or self.sts.get_caller_identity()["Account"])