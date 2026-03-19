#!/usr/bin/env python3
"""
DeployGuard Scanner - K8s + Image 통합 스캔

사용 예시:
    python -m scanners.dg_k8s_image.scan worker           # 상주 워커 (기본)
    python -m scanners.dg_k8s_image.scan scheduled        # worker alias
    python -m scanners.dg_k8s_image.scan manual           # 수동 스캔
    
    DG_SCANNER_TYPE=k8s python -m scanners.dg_k8s_image.scan worker       # K8s만
    DG_SCANNER_TYPE=image python -m scanners.dg_k8s_image.scan worker     # Image만
"""
from __future__ import annotations

import argparse
import json
import os
import signal
import sys

from shared.config import load_config
from shared.orchestrator import ScanOrchestrator, run_polling_loop
from scanners.dg_k8s_image.src.api_client import DeployGuardAPIClient
from scanners.dg_k8s_image.src.config import ScannerConfig
from scanners.dg_k8s_image.src.image_scanner import ImageScanner
from scanners.dg_k8s_image.src.k8s_scanner import K8sScanner


def _log_worker_event(action: str, **fields: object) -> None:
    event = {"action": action}
    event.update({key: value for key, value in fields.items() if value is not None})
    print(json.dumps(event, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser(description='DeployGuard Scanner v3.0.0')
    parser.add_argument(
        'mode',
        nargs='?',
        default='worker',
        choices=['manual', 'scheduled', 'worker'],
        help='스캔 모드'
    )
    parser.add_argument('--cluster-id', help='클러스터 ID')
    parser.add_argument('--api-url', help='API URL')
    parser.add_argument('--scan-type', choices=['k8s', 'image', 'all'], help='스캔 타입')
    parser.add_argument('--output-dir', help='출력 디렉토리')
    parser.add_argument('--max-images', type=int, help='최대 이미지 수')
    args = parser.parse_args()

    try:
        # 환경변수 오버라이드
        if args.cluster_id:
            os.environ['CLUSTER_ID'] = args.cluster_id
        if args.api_url:
            os.environ['DG_API_ENDPOINT'] = args.api_url
            os.environ['API_URL'] = args.api_url
        if args.scan_type:
            os.environ['DG_SCANNER_TYPE'] = args.scan_type
        if args.output_dir:
            os.environ['DG_OUTPUT_DIR'] = args.output_dir
        if args.max_images:
            os.environ['DG_MAX_IMAGES_PER_SCAN'] = str(args.max_images)

        # 설정 로드
        config = load_config(ScannerConfig)

        print(f"\n{'='*60}")
        print(f"DeployGuard Scanner v3.0.0")
        print(f"{'='*60}")
        print(f"Cluster ID: {config.cluster_id}")
        print(f"API URL: {config.api_url}")
        print(f"Scanner Type: {config.scanner_type}")
        runtime_mode = 'scheduled' if args.mode == 'worker' else args.mode

        print(f"Mode: {args.mode}")
        print(f"{'='*60}\n")

        results = {}
        k8s_result = None

        if runtime_mode == 'manual':
            if config.scanner_type in ['k8s', 'all']:
                scanner = K8sScanner(config)
                k8s_result = scanner.run_manual_scan()
                results['k8s'] = k8s_result
                _print_k8s_summary(k8s_result)

            if config.scanner_type in ['image', 'all']:
                k8s_scan_data = None
                if k8s_result:
                    k8s_scan_data = k8s_result.get('payload')
                elif config.scanner_type == 'image':
                    print("[*] Collecting K8s data for image scanning...")
                    temp_scanner = K8sScanner(config)
                    k8s_scan_data = temp_scanner.scan()

                scanner = ImageScanner(config, k8s_scan_data)
                image_result = scanner.run_manual_scan()
                results['image'] = image_result
                _print_image_summary(image_result)
        else:
            stop_requested = False

            def handle_shutdown(signum: int, _frame: object) -> None:
                nonlocal stop_requested
                if stop_requested:
                    return
                stop_requested = True
                signal_name = signal.Signals(signum).name
                _log_worker_event(
                    "worker.shutdown_requested",
                    cluster_id=config.cluster_id,
                    scanner_type=config.scanner_type,
                    mode=args.mode,
                    signal=signal_name,
                )

            previous_sigterm_handler = signal.getsignal(signal.SIGTERM)
            signal.signal(signal.SIGTERM, handle_shutdown)
            _log_worker_event(
                "worker.start",
                cluster_id=config.cluster_id,
                scanner_type=config.scanner_type,
                mode=args.mode,
            )

            def poll_once() -> bool:
                try:
                    if stop_requested:
                        return False
                    local_results = {}
                    local_k8s_result = None

                    if config.scanner_type in ['k8s', 'all']:
                        k8s_config = ScannerConfig(
                            **{**config.__dict__, 'scanner_type': 'k8s'}
                        ) if config.scanner_type == 'all' else config
                        k8s_api_client = DeployGuardAPIClient(k8s_config)
                        _log_worker_event(
                            "worker.poll",
                            cluster_id=k8s_config.cluster_id,
                            scanner_type="k8s",
                        )
                        pending = ScanOrchestrator(k8s_config, k8s_api_client).poll_scan()
                        if pending:
                            _log_worker_event(
                                "worker.claimed",
                                cluster_id=k8s_config.cluster_id,
                                scanner_type="k8s",
                                scan_id=pending.get("scan_id"),
                                claimed_by=pending.get("claimed_by"),
                                trigger_mode=pending.get("trigger_mode"),
                            )
                            scanner = K8sScanner(config)
                            trigger_mode = str(pending.get('trigger_mode', 'scheduled'))
                            local_k8s_result = scanner.run_worker_scan(str(pending['scan_id']), trigger_mode=trigger_mode)
                            local_results['k8s'] = local_k8s_result
                            _print_k8s_summary(local_k8s_result)

                    if config.scanner_type in ['image', 'all']:
                        image_config = ScannerConfig(
                            **{**config.__dict__, 'scanner_type': 'image'}
                        ) if config.scanner_type == 'all' else config
                        image_api_client = DeployGuardAPIClient(image_config)
                        _log_worker_event(
                            "worker.poll",
                            cluster_id=image_config.cluster_id,
                            scanner_type="image",
                        )
                        pending = ScanOrchestrator(image_config, image_api_client).poll_scan()
                        if pending:
                            _log_worker_event(
                                "worker.claimed",
                                cluster_id=image_config.cluster_id,
                                scanner_type="image",
                                scan_id=pending.get("scan_id"),
                                claimed_by=pending.get("claimed_by"),
                                trigger_mode=pending.get("trigger_mode"),
                            )
                            k8s_scan_data = None
                            if local_k8s_result:
                                k8s_scan_data = local_k8s_result.get('payload')
                            else:
                                print("[*] Collecting K8s data for image scanning...")
                                temp_scanner = K8sScanner(config)
                                k8s_scan_data = temp_scanner.scan()

                            scanner = ImageScanner(config, k8s_scan_data)
                            trigger_mode = str(pending.get('trigger_mode', 'scheduled'))
                            image_result = scanner.run_worker_scan(str(pending['scan_id']), trigger_mode=trigger_mode)
                            local_results['image'] = image_result
                            _print_image_summary(image_result)

                    if not local_results:
                        _log_worker_event(
                            "worker.idle",
                            cluster_id=config.cluster_id,
                            scanner_type=config.scanner_type,
                            sleep_seconds=30,
                        )
                        return False

                    print(f"\n{'='*60}")
                    print("SCAN COMPLETE")
                    print(f"{'='*60}")
                    print(json.dumps({
                        "status": "success",
                        "cluster_id": config.cluster_id,
                        "mode": args.mode,
                        "scanner_type": config.scanner_type,
                        "k8s_scan_id": local_results.get("k8s", {}).get("scan_id"),
                        "image_scan_id": local_results.get("image", {}).get("scan_id"),
                    }, indent=2))
                    return True
                except KeyboardInterrupt:
                    raise
                except Exception as exc:
                    print(json.dumps({
                        "action": "worker.retry",
                        "cluster_id": config.cluster_id,
                        "scanner_type": config.scanner_type,
                        "mode": args.mode,
                        "message": str(exc),
                    }, ensure_ascii=False), file=sys.stderr)
                    return False

            try:
                run_polling_loop(poll_once, should_stop=lambda: stop_requested)
            finally:
                signal.signal(signal.SIGTERM, previous_sigterm_handler)
            if stop_requested:
                _log_worker_event(
                    "worker.stopped",
                    cluster_id=config.cluster_id,
                    scanner_type=config.scanner_type,
                    mode=args.mode,
                    reason="signal",
                )
            return 0

        # 최종 결과
        print(f"\n{'='*60}")
        print("SCAN COMPLETE")
        print(f"{'='*60}")
        print(json.dumps({
            "status": "success",
            "cluster_id": config.cluster_id,
            "mode": args.mode,
            "scanner_type": config.scanner_type,
            "k8s_scan_id": results.get("k8s", {}).get("scan_id"),
            "image_scan_id": results.get("image", {}).get("scan_id"),
        }, indent=2))

        return 0

    except KeyboardInterrupt:
        print(json.dumps({
            "status": "interrupted",
            "mode": args.mode,
        }, indent=2), file=sys.stderr)
        return 130
    except Exception as e:
        print(json.dumps({
            "status": "error",
            "message": str(e),
        }, indent=2), file=sys.stderr)
        return 1


def _print_k8s_summary(result: dict) -> None:
    """K8s 스캔 요약 — canonical payload의 11개 배열에서 직접 카운트 계산."""
    payload = result.get("payload", {})

    # canonical payload의 11개 배열
    _CANONICAL_ARRAYS = [
        "namespaces", "pods", "service_accounts", "roles", "cluster_roles",
        "role_bindings", "cluster_role_bindings", "secrets",
        "services", "ingresses", "network_policies",
    ]
    by_type = {k: len(payload.get(k) or []) for k in _CANONICAL_ARRAYS}
    total = sum(by_type.values())

    print(f"\n{'='*50}")
    print("K8s Scan Summary")
    print(f"{'='*50}")
    print(f"Scan ID: {result.get('scan_id')}")
    print(f"Status:  {result.get('status')}")
    print(f"Total Resources: {total}")

    print("\nResources by Type:")
    for rtype, count in sorted(by_type.items()):
        if count > 0:
            print(f"  {rtype}: {count}")


def _print_image_summary(result: dict) -> None:
    """Image 스캔 요약"""
    payload = result.get("payload", {})
    summary = payload.get("summary", {})

    print(f"\n{'='*50}")
    print("Image Scan Summary")
    print(f"{'='*50}")
    print(f"Scan ID: {result.get('scan_id')}")
    print(f"Status: {result.get('status')}")
    print(f"Total Images: {summary.get('total_images', 0)}")
    print(f"Scanned: {summary.get('scanned_images', 0)}")
    print(f"Skipped: {summary.get('skipped_images', 0)}")

    by_severity = summary.get('by_severity', {})
    if any(v > 0 for v in by_severity.values()):
        print("\nVulnerabilities:")
        for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = by_severity.get(sev, 0)
            if count > 0:
                print(f"  {sev}: {count}")

    if summary.get('images_with_exploitable_cve', 0) > 0:
        print(f"\n🔴 Images with Exploitable CVE: {summary['images_with_exploitable_cve']}")

    top = summary.get('top_vulnerable_images', [])
    if top:
        print("\nTop Vulnerable Images:")
        for img in top[:5]:
            print(f"  {img['image'][:50]}... C={img['critical']} H={img['high']}")


if __name__ == "__main__":
    sys.exit(main())