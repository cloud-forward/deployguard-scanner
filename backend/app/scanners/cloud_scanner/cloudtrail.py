from __future__ import annotations

from typing import Any, Dict, List


class CloudTrailCollector:
    """
    호환용 placeholder 모듈입니다.

    현재 이 cloud-scanner는 AWS Static Scanner 전용입니다.
    즉:
    - IAM / S3 / RDS / EC2 / Security Group 상태 스냅샷만 수집
    - CloudTrail runtime evidence는 포함하지 않음

    CloudTrail은 별도 이벤트 기반 파이프라인
    (예: S3 Event Notification -> Lambda -> /api/evidence/cloudtrail)
    으로 분리되어야 합니다.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs

    def collect(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "enabled": False,
            "reason": "CloudTrail collection is not part of AWS Static Scanner.",
            "events": [],
        }

    def collect_events(self, *args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        return []