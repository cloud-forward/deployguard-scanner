#!/usr/bin/env python3
"""
DeployGuard Scanner - K8s + Image 통합 스캔

사용 예시:
    python -m scanners.dg_k8s_image.scan scheduled        # 정기 스캔 (기본)
    python -m scanners.dg_k8s_image.scan manual           # 수동 스캔
    
    DG_SCANNER_TYPE=k8s python -m scanners.dg_k8s_image.scan scheduled    # K8s만
    DG_SCANNER_TYPE=image python -m scanners.dg_k8s_image.scan scheduled  # Image만
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from shared.config import load_config
from shared.orchestrator import ScanOrchestrator, run_polling_loop
from scanners.dg_k8s_image.src.api_client import DeployGuardAPIClient
from scanners.dg_k8s_image.src.config import ScannerConfig
from scanners.dg_k8s_image.src.image_scanner import ImageScanner
from scanners.dg_k8s_image.src.k8s_scanner import K8sScanner


def main() -> int:
    parser = argparse.ArgumentParser(description='DeployGuard Scanner v3.0.0')
    parser.add_argument(
        'mode',
        nargs='?',
        default='scheduled',
        choices=['manual', 'scheduled'],
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
        print(f"Mode: {args.mode}")
        print(f"{'='*60}\n")

        results = {}
        k8s_result = None

        if args.mode == 'manual':
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
            def poll_once() -> bool:
                local_results = {}
                local_k8s_result = None

                if config.scanner_type in ['k8s', 'all']:
                    k8s_config = ScannerConfig(
                        **{**config.__dict__, 'scanner_type': 'k8s'}
                    ) if config.scanner_type == 'all' else config
                    k8s_api_client = DeployGuardAPIClient(k8s_config)
                    pending = ScanOrchestrator(k8s_config, k8s_api_client).poll_scan()
                    if pending:
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
                    pending = ScanOrchestrator(image_config, image_api_client).poll_scan()
                    if pending:
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

            run_polling_loop(poll_once)
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
    """K8s 스캔 요약"""
    payload = result.get("payload", {})
    summary = payload.get("summary", {})

    print(f"\n{'='*50}")
    print("K8s Scan Summary")
    print(f"{'='*50}")
    print(f"Scan ID: {result.get('scan_id')}")
    print(f"Status: {result.get('status')}")
    print(f"Total Resources: {summary.get('total_resources', 0)}")

    print("\nResources by Type:")
    for rtype, count in sorted(summary.get('by_type', {}).items()):
        if count > 0:
            print(f"  {rtype}: {count}")

    sec = summary.get('security_indicators', {})
    warnings = [(k, v) for k, v in sec.items() if v > 0]
    if warnings:
        print("\n⚠️  Security Indicators:")
        for indicator, value in warnings:
            print(f"  {indicator}: {value}")


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
