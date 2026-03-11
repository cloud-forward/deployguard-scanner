import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict

def generate_scan_id() -> str:
    return str(uuid.uuid4())

def get_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()

def save_json(data: Dict[str, Any], filepath: str) -> None:
    os.makedirs(os.path.dirname(filepath) if os.path.dirname(filepath) else '.', exist_ok=True)
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    print(f"[+] Saved: {filepath}")

def load_json(filepath: str) -> Dict[str, Any]:
    with open(filepath, 'r', encoding='utf-8') as f:
        return json.load(f)
