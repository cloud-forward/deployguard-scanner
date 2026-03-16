#!/usr/bin/env python3
"""
DeployGuard Scanner - K8s + Image 통합 스캔

사용 예시:
    python scan.py scheduled        # 정기 스캔 (기본)
    python scan.py manual           # 수동 스캔
    
    DG_SCANNER_TYPE=k8s python scan.py scheduled    # K8s만
    DG_SCANNER_TYPE=image python scan.py scheduled  # Image만
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import ScannerConfig
from src.k8s_scanner import K8sScanner
from src.image_scanner import ImageScanner


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
            os.environ['API_URL'] = args.api_url
        if args.scan_type:
            os.environ['DG_SCANNER_TYPE'] = args.scan_type
        if args.output_dir:
            os.environ['DG_OUTPUT_DIR'] = args.output_dir
        if args.max_images:
            os.environ['DG_MAX_IMAGES_PER_SCAN'] = str(args.max_images)

        # 설정 로드
        config = ScannerConfig.from_env()

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

        # K8s 스캔
        if config.scanner_type in ['k8s', 'all']:
            scanner = K8sScanner(config)
            
            if args.mode == 'manual':
                k8s_result = scanner.run_manual_scan()
            else:
                k8s_result = scanner.run_scheduled_scan()
            
            results['k8s'] = k8s_result
            _print_k8s_summary(k8s_result)

        # Image 스캔
        if config.scanner_type in ['image', 'all']:
            # K8s 결과에서 리소스 추출
            k8s_scan_data = None
            if k8s_result:
                k8s_scan_data = k8s_result.get('payload')
            elif config.scanner_type == 'image':
                # Image만 스캔하는 경우, K8s 데이터 먼저 수집
                print("[*] Collecting K8s data for image scanning...")
                temp_scanner = K8sScanner(config)
                k8s_scan_data = temp_scanner.scan()

            scanner = ImageScanner(config, k8s_scan_data)
            
            if args.mode == 'manual':
                image_result = scanner.run_manual_scan()
            else:
                image_result = scanner.run_scheduled_scan()
            
            results['image'] = image_result
            _print_image_summary(image_result)

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