from __future__ import annotations

import json
import logging
import sys

from .config import ScannerConfig
from .scanner import CloudScanner
from shared.config import load_config
from shared.orchestrator import run_polling_loop

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


def _format_result(result: dict, config: ScannerConfig) -> dict:
    payload = result.get("payload", {})
    return {
        "status": result.get("status", "ok"),
        "cluster_id": config.cluster_id,
        "scan_id": result["scan_id"],
        "engine_status": result.get("status", "unknown"),
        "uploaded_files": result.get("uploaded_files", []),
        "local_output_file": result.get("local_file"),
        "recommended_cron_schedule": config.aws_recommended_cron_schedule,
        "resource_counts": result.get("resource_counts", payload.get("resource_counts", {})),
    }


def main() -> int:
    try:
        config = load_config(ScannerConfig)
        logger.info("Cluster ID: %s", config.cluster_id)
        logger.info("Region: %s", config.region)

        scanner = CloudScanner(config)

        def poll_once() -> bool:
            pending = scanner.api_client.poll_scan()
            if not pending:
                return False

            trigger_mode = str(pending.get("trigger_mode", "scheduled"))
            result = scanner.run_worker_scan(str(pending["scan_id"]), trigger_mode=trigger_mode)
            print(json.dumps(_format_result(result, config), ensure_ascii=False, indent=2))
            return True

        run_polling_loop(poll_once)
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