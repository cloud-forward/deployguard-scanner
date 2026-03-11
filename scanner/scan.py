#!/usr/bin/env python3
"""DeployGuard Scanner - K8s + Image 스캔"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.config import ScannerConfig
from src.k8s_scanner import K8sScanner
from src.image_scanner import ImageScanner
from src.api_client import DeployGuardAPIClient
from src.utils import save_json


def main():
    parser = argparse.ArgumentParser(description='DeployGuard Scanner')
    parser.add_argument('--cluster-id', required=True, help='클러스터 ID')
    parser.add_argument('--cluster-name', default=None, help='클러스터 이름')
    parser.add_argument('--output-dir', default='./output', help='출력 디렉토리')
    parser.add_argument('--api-url', default=None, help='DeployGuard API URL')
    parser.add_argument('--scan-type', default='all', choices=['k8s', 'image', 'all'], help='스캔 타입')
    parser.add_argument('--max-images', type=int, default=10, help='스캔할 최대 이미지 수')
    args = parser.parse_args()

    cluster_name = args.cluster_name or args.cluster_id
    
    config = ScannerConfig(
        cluster_id=args.cluster_id,
        cluster_name=cluster_name,
        output_dir=args.output_dir,
        max_images_per_scan=args.max_images,
    )

    os.makedirs(config.output_dir, exist_ok=True)

    k8s_result = None
    image_result = None

    # K8s 스캔
    if args.scan_type in ['k8s', 'all']:
        print("\n" + "="*50)
        print("DeployGuard K8s Scanner")
        print("="*50)
        
        scanner = K8sScanner(config)
        k8s_result = scanner.scan()
        
        output_file = f"{config.output_dir}/k8s_scan_{k8s_result['scan_id']}.json"
        save_json(k8s_result, output_file)

        # API 업로드
        if args.api_url:
            _upload_to_api(args.api_url, args.cluster_id, "k8s", k8s_result)

        _print_k8s_summary(k8s_result)

    # Image 스캔
    if args.scan_type in ['image', 'all']:
        print("\n" + "="*50)
        print("DeployGuard Image Scanner")
        print("="*50)
        
        scanner = ImageScanner(config, k8s_result)
        image_result = scanner.scan()
        
        output_file = f"{config.output_dir}/image_scan_{image_result['scan_id']}.json"
        save_json(image_result, output_file)

        # API 업로드
        if args.api_url:
            _upload_to_api(args.api_url, args.cluster_id, "image", image_result)

        _print_image_summary(image_result)


def _upload_to_api(api_url: str, cluster_id: str, scanner_type: str, result: dict):
    """API 서버로 업로드"""
    print(f"\n[*] Uploading {scanner_type} scan to API...")
    
    try:
        from src.api_client import DeployGuardAPIClient
        client = DeployGuardAPIClient(api_url)
        
        health = client.health_check()
        print(f"[+] API Server: {health['status']}")
        
        client.upload_scan_result(cluster_id, scanner_type, result)
        print(f"[+] {scanner_type} scan uploaded successfully!")
        
    except Exception as e:
        print(f"[-] Upload failed: {e}")


def _print_k8s_summary(result: dict):
    """K8s 스캔 요약 출력"""
    print("\n" + "="*50)
    print("K8s Scan Complete!")
    print("="*50)
    print(f"Total Resources: {result['summary']['total_resources']}")
    print("\nBy Type:")
    for rtype, count in result['summary']['by_type'].items():
        if count > 0:
            print(f"  {rtype}: {count}")
    print("\nSecurity Indicators:")
    for indicator, value in result['summary']['security_indicators'].items():
        if value > 0:
            print(f"  ⚠️  {indicator}: {value}")


def _print_image_summary(result: dict):
    """Image 스캔 요약 출력"""
    print("\n" + "="*50)
    print("Image Scan Complete!")
    print("="*50)
    print(f"Total Images: {result['summary']['total_images']}")
    print(f"Scanned: {result['summary']['scanned_images']}")
    print(f"Skipped: {result['summary']['skipped_images']}")
    print(f"\nVulnerabilities:")
    for sev, count in result['summary']['by_severity'].items():
        if count > 0:
            print(f"  {sev.upper()}: {count}")
    if result['summary']['top_vulnerable_images']:
        print("\nTop Vulnerable Images:")
        for img in result['summary']['top_vulnerable_images'][:3]:
            print(f"  {img['image']}: C={img['critical']} H={img['high']}")


if __name__ == "__main__":
    main()
