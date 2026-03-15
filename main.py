from __future__ import annotations

import json
import logging
import sys

from .config import ScannerConfig
from .scanner import CloudScanner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def _format_result(result: dict, config: ScannerConfig, mode: str) -> dict:
    payload = result.get("payload", {})
    return {
        "status": result.get("status", "ok"),
        "mode": mode,
        "cluster_id": result["cluster_id"],
        "scan_id": result["scan_id"],
        "engine_status": result["engine_status"],
        "uploaded_files": result["uploaded_files"],
        "local_output_file": result.get("local_output_file"),
        "recommended_cron_schedule": config.aws_recommended_cron_schedule,
        "resource_counts": payload.get("resource_counts", {}),
    }


def main() -> int:
    try:
        if len(sys.argv) < 2:
            print("Usage: python -m cloud_scanner.main [manual|scheduled]", file=sys.stderr)
            return 1

        mode = sys.argv[1].strip().lower()
        if mode not in {"manual", "scheduled"}:
            print(f"Error: Unknown mode '{mode}'. Use 'manual' or 'scheduled'.", file=sys.stderr)
            return 1

        config = ScannerConfig.from_env()
        logger.info("Cluster ID: %s", config.cluster_id)
        logger.info("Region: %s", config.region)
        logger.info("Mode: %s", mode)

        scanner = CloudScanner(config)
        result = scanner.run_manual_scan() if mode == "manual" else scanner.run_scheduled_scan()

        print(json.dumps(_format_result(result, config, mode), ensure_ascii=False, indent=2))
        return 0

    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user")
        return 130
    except Exception as exc:
        logger.exception("Scan failed")
        print(json.dumps({"status": "error", "error": str(exc)}, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())