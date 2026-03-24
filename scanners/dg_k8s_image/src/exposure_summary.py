from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

log = logging.getLogger(__name__)

_S3_BUCKET = os.environ.get("S3_BUCKET", "dg-raw-scans")
_S3_REGION = os.environ.get("S3_REGION", "ap-northeast-2")
_S3_PREFIX = os.environ.get("S3_PREFIX", "scans")


def build_summary_s3_key(cluster_id: str, scan_id: str) -> str:
    return f"{_S3_PREFIX}/{cluster_id}/{scan_id}/image/image_exposure_summary.json"


def build_latest_pointer_key(cluster_id: str) -> str:
    return f"{_S3_PREFIX}/{cluster_id}/image/latest.json"


def build_exposure_summary(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    """
    image_scanner payload에서 lightweight exposure summary를 만든다.
    raw를 다시 파싱하지 않고 payload['images']의 정규화된 필드만 사용한다.
    """
    payload: Dict[str, Any] = scan_result.get("payload", {})
    cluster_id: str = payload.get("cluster_id", "")
    scan_id: str = payload.get("scan_id", "")
    scanned_at: str = payload.get("scanned_at", "")

    images_out: List[Dict[str, Any]] = []
    for img in payload.get("images", []):
        if img.get("scan_status") != "completed":
            continue

        vs = img.get("vulnerability_summary") or {}
        vulns: List[Dict[str, Any]] = img.get("vulnerabilities", [])

        poc_cves = [v.get("cve_id") for v in vulns if v.get("is_known_exploitable") and v.get("cve_id")]
        other_cves = [
            v.get("cve_id")
            for v in vulns
            if v.get("severity") in ("CRITICAL", "HIGH")
            and not v.get("is_known_exploitable")
            and v.get("cve_id")
        ]
        sample_cves = (poc_cves + other_cves)[:5]

        images_out.append(
            {
                "image_ref": img.get("image_ref", ""),
                "image_digest": img.get("image_digest") or "",
                "critical_cve_count": vs.get("critical", 0),
                "high_cve_count": vs.get("high", 0),
                "fix_available": vs.get("fixable", 0) > 0,
                "poc_exists": bool(poc_cves),
                "sample_cves": sample_cves,
                "source": "trivy",
                "scanned_at": img.get("scanned_at", scanned_at),
            }
        )

    return {
        "cluster_id": cluster_id,
        "scan_id": scan_id,
        "scanned_at": scanned_at,
        "images": images_out,
    }


def build_latest_pointer(
    cluster_id: str,
    scan_id: str,
    summary_key: str,
    scanned_at: str,
) -> Dict[str, Any]:
    return {
        "cluster_id": cluster_id,
        "latest_scan_id": scan_id,
        "summary_key": summary_key,
        "scanned_at": scanned_at,
    }


def _s3_put(key: str, body: Dict[str, Any]) -> None:
    s3 = boto3.client("s3", region_name=_S3_REGION)
    s3.put_object(
        Bucket=_S3_BUCKET,
        Key=key,
        Body=json.dumps(body, ensure_ascii=False, indent=2, default=str).encode("utf-8"),
        ContentType="application/json",
    )


def upload_summary_to_s3(cluster_id: str, scan_id: str, summary: Dict[str, Any]) -> str:
    key = build_summary_s3_key(cluster_id, scan_id)
    _s3_put(key, summary)
    log.info("uploaded exposure summary to s3://%s/%s", _S3_BUCKET, key)
    return key


def upload_latest_pointer_to_s3(
    cluster_id: str,
    scan_id: str,
    summary_key: str,
    scanned_at: str,
) -> None:
    pointer = build_latest_pointer(cluster_id, scan_id, summary_key, scanned_at)
    key = build_latest_pointer_key(cluster_id)
    _s3_put(key, pointer)
    log.info("uploaded latest pointer to s3://%s/%s", _S3_BUCKET, key)