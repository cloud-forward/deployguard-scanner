from __future__ import annotations

import json
import sys

from .config import ScannerConfig
from .scanner import CloudScanner


def main() -> int:
    try:
        config = ScannerConfig.from_env()
        scanner = CloudScanner(config)
        result = scanner.run()

        payload = result["payload"]

        print(json.dumps({
            "status": "ok",
            "scan_id": result["scan_id"],
            "engine_status": result["engine_status"],
            "uploaded_files": result["uploaded_files"],
            "local_output_file": result.get("local_output_file"),
            "resource_counts": {
                "iam_roles": len(payload["iam_roles"]),
                "iam_users": len(payload["iam_users"]),
                "s3_buckets": len(payload["s3_buckets"]),
                "rds_instances": len(payload["rds_instances"]),
                "ec2_instances": len(payload["ec2_instances"]),
                "security_groups": len(payload["security_groups"]),
            },
        }, ensure_ascii=False, indent=2))
        return 0

    except Exception as exc:
        print(json.dumps({
            "status": "error",
            "message": str(exc),
        }, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())