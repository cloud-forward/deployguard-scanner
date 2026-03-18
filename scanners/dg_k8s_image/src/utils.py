import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict


def generate_scan_id() -> str:
    """UUID 기반 스캔 ID 생성"""
    return str(uuid.uuid4())


def get_timestamp() -> str:
    """현재 UTC 시간을 ISO 8601 형식으로 반환"""
    return datetime.now(timezone.utc).isoformat()


def save_json(data: Dict[str, Any], filepath: str) -> None:
    """JSON 파일 저장"""
    dir_path = os.path.dirname(filepath)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"[+] Saved: {filepath}")


def load_json(filepath: str) -> Dict[str, Any]:
    """JSON 파일 로드"""
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)