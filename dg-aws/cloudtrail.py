from __future__ import annotations

from typing import Any, Dict, List


class CloudTrailCollector:
    """
    Runtime Scanner 전용 자리만 남겨둔 호환 모듈입니다.

    현재 AWS Static Scanner v2는
    - CloudTrail을 scan.json에 포함하지 않고
    - S3 Presigned URL 업로드 방식만 사용합니다.

    Runtime 이벤트는 별도 문서의 /api/evidence/ingest 경로로 분리되어야 하므로
    이 모듈은 정적 스캐너 실행 경로에서 사용하지 않습니다.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.args = args
        self.kwargs = kwargs

    def collect(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        return {
            "enabled": False,
            "reason": "CloudTrail collection is not used by AWS Static Scanner v2.",
            "events": [],
        }

    def collect_events(self, *args: Any, **kwargs: Any) -> List[Dict[str, Any]]:
        return []