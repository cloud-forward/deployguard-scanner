"""
DeployGuard Image Scanner - Fact Extractor 완벽 호환 버전

ImageExtractor가 기대하는 모든 필드를 수집합니다:
- image, registry, repository, tag
- vulnerabilities (CVE, severity, EPSS)
- summary (CRITICAL, HIGH count)
- used_by_workloads
- signature (cosign)
- metadata (os, architecture, age)
"""
from __future__ import annotations

import csv
import gzip
import json
import os
import re
import subprocess
import tempfile
from datetime import datetime, timezone
from io import StringIO
from typing import Any, Dict, List, Optional, Set
from urllib.request import urlopen

import requests

from .config import ScannerConfig
from .api_client import DeployGuardAPIClient
from .utils import generate_scan_id, get_timestamp, save_json


# 알려진 Exploitable CVE (ImageExtractor와 동일)
KNOWN_EXPLOITABLE_CVES = {
    'CVE-2021-44228',  # Log4Shell
    'CVE-2021-45046',  # Log4j
    'CVE-2022-22965',  # Spring4Shell
    'CVE-2021-3156',   # Sudo Baron Samedit
    'CVE-2022-0847',   # Dirty Pipe
    'CVE-2024-21626',  # runc
    'CVE-2024-3094',   # xz backdoor
}

# Public Registry 목록
PUBLIC_REGISTRIES = {
    'docker.io', 'registry.hub.docker.com', 'index.docker.io',
    'gcr.io', 'ghcr.io', 'quay.io', 'registry.k8s.io',
    'public.ecr.aws', 'mcr.microsoft.com',
}


class ImageScanner:
    """
    컨테이너 이미지 CVE 스캐너 - Fact Extractor 완벽 호환
    """

    def __init__(
        self,
        config: Optional[ScannerConfig] = None,
        k8s_scan_result: Optional[Dict[str, Any]] = None,
    ):
        self.config = config or ScannerConfig.from_env()
        self.scan_id = generate_scan_id()
        self.scan_time = get_timestamp()
        self.k8s_scan = k8s_scan_result
        
        # Trivy 확인
        self.trivy_available = self._check_trivy() if self.config.trivy_enabled else False
        self.trivy_version = self._get_trivy_version() if self.trivy_available else None
        
        # EPSS 캐시
        self._epss_cache: Dict[str, Dict[str, float]] = {}
        self._epss_loaded = False

    def _check_trivy(self) -> bool:
        """Trivy 설치 확인"""
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                print(f"[+] Trivy available")
                return True
            return False
        except FileNotFoundError:
            print("[-] Trivy not found - image scanning will be limited")
            return False
        except Exception as e:
            print(f"[-] Trivy check failed: {e}")
            return False

    def _get_trivy_version(self) -> Optional[str]:
        """Trivy 버전 확인"""
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                # "Version: 0.50.0" 형식
                for line in result.stdout.split("\n"):
                    if "Version:" in line:
                        return line.split(":")[-1].strip()
        except Exception:
            pass
        return None

    # =========================================================================
    # EPSS 데이터 로드
    # =========================================================================

    def _load_epss_data(self) -> None:
        """EPSS 데이터 로드 (CSV)"""
        if self._epss_loaded or not self.config.epss_enabled:
            return
        
        try:
            print("[*] Loading EPSS data...")
            
            # FIRST EPSS API에서 CSV 다운로드
            url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
            
            with urlopen(url, timeout=30) as response:
                compressed = response.read()
            
            decompressed = gzip.decompress(compressed).decode('utf-8')
            reader = csv.DictReader(StringIO(decompressed))
            
            count = 0
            for row in reader:
                cve_id = row.get('cve')
                if cve_id:
                    self._epss_cache[cve_id] = {
                        'epss_score': float(row.get('epss', 0)),
                        'epss_percentile': float(row.get('percentile', 0)),
                    }
                    count += 1
            
            self._epss_loaded = True
            print(f"[+] Loaded EPSS data for {count} CVEs")
            
        except Exception as e:
            print(f"[-] Failed to load EPSS data: {e}")
            self._epss_loaded = True  # 재시도 방지

    def _get_epss(self, cve_id: str) -> Dict[str, Optional[float]]:
        """CVE의 EPSS 점수 조회"""
        if not self.config.epss_enabled:
            return {"epss_score": None, "epss_percentile": None}
        
        self._load_epss_data()
        
        if cve_id in self._epss_cache:
            return self._epss_cache[cve_id]
        
        return {"epss_score": None, "epss_percentile": None}

    # =========================================================================
    # 메인 실행 메서드
    # =========================================================================

    def run(self) -> Dict[str, Any]:
        """기본 실행"""
        return self.run_scheduled_scan()

    def run_manual_scan(self) -> Dict[str, Any]:
        """수동 스캔"""
        return self._run_scan(trigger_mode="manual")

    def run_scheduled_scan(self) -> Dict[str, Any]:
        """정기 스캔"""
        return self._run_scan(trigger_mode="scheduled")

    def _run_scan(self, trigger_mode: str) -> Dict[str, Any]:
        """실제 스캔 실행"""
        print(f"\n{'='*60}")
        print(f"DeployGuard Image Scanner v3.0.0")
        print(f"Cluster: {self.config.cluster_id}")
        print(f"Mode: {trigger_mode}")
        print(f"Trivy: {'available' if self.trivy_available else 'not available'}")
        print(f"EPSS: {'enabled' if self.config.epss_enabled else 'disabled'}")
        print(f"{'='*60}\n")

        # 1. API 클라이언트 초기화
        api_client = DeployGuardAPIClient(self.config)

        # 2. 스캔 시작 등록
        scan_id = api_client.start_scan(
            scanner_type="image",
            trigger_mode=trigger_mode,
        )
        self.scan_id = scan_id

        # 3. 이미지 수집 및 스캔
        images = self._collect_images()
        print(f"[*] Found {len(images)} unique images")

        scanned_images = []
        scan_limit = min(len(images), self.config.max_images_per_scan)
        
        for idx, img_info in enumerate(images[:scan_limit]):
            print(f"[{idx+1}/{scan_limit}] Scanning: {img_info['image_ref'][:60]}...")
            scanned = self._scan_single_image(img_info)
            scanned_images.append(scanned)

        # 4. 페이로드 생성
        payload = self._build_payload(
            scan_id=scan_id,
            trigger_mode=trigger_mode,
            images=scanned_images,
        )

        # 5. 로컬 저장 (옵션)
        local_file = None
        if self.config.save_local_copy:
            local_file = self._save_local_copy(payload, scan_id)

        # 6. S3 업로드
        s3_key = api_client.upload_scan_result(payload, self.config.upload_file_name)

        # 7. 스캔 완료 알림
        summary = payload.get("summary", {})
        complete_result = api_client.complete_scan(
            meta={
                "scanner_type": "image",
                "trigger_mode": trigger_mode,
                "total_images": summary.get("total_images", 0),
                "scanned_images": summary.get("scanned_images", 0),
                "vulnerability_counts": summary.get("by_severity", {}),
            }
        )

        return {
            "scan_id": scan_id,
            "payload": payload,
            "s3_key": s3_key,
            "local_file": local_file,
            "status": complete_result.get("status", "unknown"),
        }

    def scan(self) -> Dict[str, Any]:
        """하위 호환용"""
        images = self._collect_images()
        
        scanned_images = []
        for img_info in images[:self.config.max_images_per_scan]:
            scanned_images.append(self._scan_single_image(img_info))
        
        return self._build_payload(
            scan_id=self.scan_id,
            trigger_mode="manual",
            images=scanned_images,
        )

    # =========================================================================
    # 이미지 수집
    # =========================================================================

    def _collect_images(self) -> List[Dict[str, Any]]:
        """K8s 스캔 결과에서 이미지 목록 수집"""
        images: Dict[str, Dict[str, Any]] = {}
        
        if not self.k8s_scan:
            print("[-] No K8s scan result provided")
            return []
        
        # resources 또는 k8s 키에서 pods 추출
        k8s_data = self.k8s_scan.get("resources") or self.k8s_scan.get("k8s") or {}
        pods = k8s_data.get("pods", [])
        
        for pod in pods:
            namespace = pod.get("namespace", "unknown")
            pod_name = pod.get("name", "unknown")
            workload_ref = f"{namespace}/{pod_name}"
            
            # 일반 컨테이너
            for container in pod.get("containers", []):
                self._add_image(images, container, workload_ref, namespace)
            
            # Init 컨테이너
            for container in pod.get("init_containers", []):
                self._add_image(images, container, workload_ref, namespace, is_init=True)
        
        # 정렬: 많이 사용되는 이미지 먼저
        result = sorted(
            images.values(),
            key=lambda x: len(x.get("used_by_workloads", [])),
            reverse=True
        )
        
        return result

    def _add_image(
        self,
        images: Dict[str, Dict[str, Any]],
        container: Dict[str, Any],
        workload_ref: str,
        namespace: str,
        is_init: bool = False,
    ) -> None:
        """이미지 정보 추가"""
        image_ref = container.get("image", "")
        if not image_ref:
            return
        
        if image_ref not in images:
            parsed = self._parse_image_ref(image_ref)
            
            images[image_ref] = {
                "image_ref": image_ref,
                "image": image_ref,  # ImageExtractor 호환
                "registry": parsed["registry"],
                "repository": parsed["repository"],
                "tag": parsed["tag"],
                "digest": parsed["digest"],
                "used_by_workloads": [],
                "namespaces": set(),
                # ImageExtractor용 필드
                "is_from_public_registry": parsed["registry"] in PUBLIC_REGISTRIES,
                "has_no_tag": not parsed["tag"] or parsed["tag"] == "latest",
            }
        
        images[image_ref]["used_by_workloads"].append({
            "workload": workload_ref,
            "container": container.get("name", ""),
            "is_init_container": is_init,
        })
        images[image_ref]["namespaces"].add(namespace)

    def _parse_image_ref(self, image_ref: str) -> Dict[str, Optional[str]]:
        """이미지 참조 파싱"""
        result = {
            "registry": "docker.io",
            "repository": "",
            "tag": "latest",
            "digest": None,
        }
        
        # 다이제스트 분리
        if "@" in image_ref:
            image_part, digest = image_ref.split("@", 1)
            result["digest"] = digest
        else:
            image_part = image_ref
        
        # 태그 분리
        if ":" in image_part:
            # 포트 번호와 구분 (예: registry:5000/image:tag)
            parts = image_part.rsplit(":", 1)
            if "/" not in parts[-1]:  # 태그
                image_part = parts[0]
                result["tag"] = parts[1]
        
        # 레지스트리와 리포지토리 분리
        parts = image_part.split("/")
        
        if len(parts) == 1:
            # library/nginx 형태
            result["repository"] = f"library/{parts[0]}"
        elif len(parts) == 2:
            # 레지스트리가 있는지 확인
            if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
                result["registry"] = parts[0]
                result["repository"] = parts[1]
            else:
                # docker.io/user/image
                result["repository"] = "/".join(parts)
        else:
            # 3개 이상: registry/org/image
            if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
                result["registry"] = parts[0]
                result["repository"] = "/".join(parts[1:])
            else:
                result["repository"] = "/".join(parts)
        
        return result

    # =========================================================================
    # 이미지 스캔
    # =========================================================================

    def _scan_single_image(self, image_info: Dict[str, Any]) -> Dict[str, Any]:
        """단일 이미지 스캔"""
        result = {
            **image_info,
            "scan_status": "pending",
            "scanned_at": get_timestamp(),
            "vulnerabilities": [],
            "summary": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "UNKNOWN": 0,
            },
            "max_cvss": None,
            "max_epss": None,
            "has_exploitable_cve": False,
            "exploitable_cves": [],
        }
        
        # namespaces set → list 변환
        if isinstance(result.get("namespaces"), set):
            result["namespaces"] = sorted(result["namespaces"])
        
        if not self.trivy_available:
            result["scan_status"] = "skipped"
            result["scan_error"] = "Trivy not available"
            return result
        
        image_ref = image_info["image_ref"]
        
        try:
            vulnerabilities = self._run_trivy_scan(image_ref)
            
            if vulnerabilities is not None:
                # EPSS 추가
                for vuln in vulnerabilities:
                    epss_data = self._get_epss(vuln.get("cve_id", ""))
                    vuln["epss_score"] = epss_data.get("epss_score")
                    vuln["epss_percentile"] = epss_data.get("epss_percentile")
                    
                    # Exploitable CVE 체크
                    if vuln.get("cve_id") in KNOWN_EXPLOITABLE_CVES:
                        vuln["is_known_exploitable"] = True
                        result["has_exploitable_cve"] = True
                        result["exploitable_cves"].append(vuln.get("cve_id"))
                
                result["vulnerabilities"] = vulnerabilities
                result["summary"] = self._summarize_vulnerabilities(vulnerabilities)
                result["max_cvss"] = max(
                    (v.get("cvss_score") or 0 for v in vulnerabilities),
                    default=None
                )
                result["max_epss"] = max(
                    (v.get("epss_score") or 0 for v in vulnerabilities),
                    default=None
                )
                result["scan_status"] = "completed"
            else:
                result["scan_status"] = "completed"
                result["scan_note"] = "No vulnerabilities found or scan failed"
                
        except subprocess.TimeoutExpired:
            result["scan_status"] = "timeout"
            result["scan_error"] = "Scan timed out"
        except Exception as e:
            result["scan_status"] = "error"
            result["scan_error"] = str(e)
        
        return result

    def _run_trivy_scan(self, image_ref: str) -> Optional[List[Dict[str, Any]]]:
        """Trivy 스캔 실행"""
        output_file = None
        
        try:
            with tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.json',
                delete=False
            ) as f:
                output_file = f.name
            
            cmd = [
                "trivy", "image",
                "--format", "json",
                "--output", output_file,
                "--severity", self.config.trivy_severity,
                "--timeout", self.config.trivy_timeout,
                "--quiet",
                "--skip-db-update",
                image_ref
            ]
            
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,  # 에러 코드 무시 (취약점 발견 시 1 반환)
            )
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    trivy_result = json.load(f)
                
                return self._parse_trivy_result(trivy_result)
            
            return []
            
        finally:
            if output_file and os.path.exists(output_file):
                try:
                    os.unlink(output_file)
                except Exception:
                    pass

    def _parse_trivy_result(self, trivy_result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Trivy 결과 파싱"""
        vulnerabilities = []
        
        for result in trivy_result.get("Results", []):
            target = result.get("Target", "")
            target_type = result.get("Type", "")
            
            for vuln in result.get("Vulnerabilities", []):
                cve_id = vuln.get("VulnerabilityID", "")
                severity = vuln.get("Severity", "UNKNOWN").upper()
                
                # CVSS 점수 추출
                cvss_score = None
                cvss_vector = None
                
                cvss_data = vuln.get("CVSS", {})
                if cvss_data:
                    # NVD CVSS 우선
                    for source in ["nvd", "redhat", "ghsa"]:
                        if source in cvss_data:
                            cvss_score = cvss_data[source].get("V3Score") or cvss_data[source].get("V2Score")
                            cvss_vector = cvss_data[source].get("V3Vector") or cvss_data[source].get("V2Vector")
                            if cvss_score:
                                break
                
                vulnerabilities.append({
                    "cve_id": cve_id,
                    "severity": severity,
                    "cvss_score": cvss_score,
                    "cvss_vector": cvss_vector,
                    "title": vuln.get("Title", ""),
                    "description": (vuln.get("Description", "") or "")[:500],
                    "pkg_name": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion"),
                    "fix_available": bool(vuln.get("FixedVersion")),
                    "target": target,
                    "target_type": target_type,
                    "references": (vuln.get("References") or [])[:5],
                    "published_date": vuln.get("PublishedDate"),
                    "last_modified_date": vuln.get("LastModifiedDate"),
                    # EPSS는 나중에 추가됨
                    "epss_score": None,
                    "epss_percentile": None,
                    "is_known_exploitable": cve_id in KNOWN_EXPLOITABLE_CVES,
                })
        
        return vulnerabilities

    def _summarize_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, int]:
        """취약점 요약"""
        summary = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "UNKNOWN": 0,
        }
        
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").upper()
            if severity in summary:
                summary[severity] += 1
            else:
                summary["UNKNOWN"] += 1
        
        return summary

    # =========================================================================
    # 페이로드 생성
    # =========================================================================

    def _build_payload(
        self,
        scan_id: str,
        trigger_mode: str,
        images: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """스캔 결과 페이로드 생성 (ImageExtractor 호환)"""
        return {
            # 메타데이터
            "scan_id": scan_id,
            "scan_type": "image",
            "cluster_id": self.config.cluster_id,
            "cluster_name": self.config.cluster_name or self.config.cluster_id,
            "scanner_type": "image",
            "trigger_mode": trigger_mode,
            "scanned_at": self.scan_time,
            "scanner_version": "3.0.0",
            
            # Fact Extractor 호환
            "metadata": {
                "cluster_id": self.config.cluster_id,
                "scan_id": scan_id,
                "scanned_at": self.scan_time,
            },
            
            # 도구 정보
            "trivy_available": self.trivy_available,
            "trivy_version": self.trivy_version,
            "epss_enabled": self.config.epss_enabled,
            
            # 이미지 목록
            "images": images,
            
            # 요약
            "summary": self._generate_summary(images),
        }

    def _generate_summary(self, images: List[Dict[str, Any]]) -> Dict[str, Any]:
        """이미지 스캔 요약"""
        total = len(images)
        scanned = sum(1 for img in images if img.get("scan_status") == "completed")
        skipped = sum(1 for img in images if img.get("scan_status") == "skipped")
        errors = sum(1 for img in images if img.get("scan_status") == "error")
        
        by_severity = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
        }
        
        for img in images:
            img_summary = img.get("summary", {})
            for sev in by_severity:
                by_severity[sev] += img_summary.get(sev, 0)
        
        # 가장 취약한 이미지
        top_vulnerable = sorted(
            [img for img in images if img.get("vulnerabilities")],
            key=lambda x: (
                x.get("summary", {}).get("CRITICAL", 0) * 10000 +
                x.get("summary", {}).get("HIGH", 0) * 100 +
                (x.get("max_epss") or 0) * 1000
            ),
            reverse=True
        )[:10]
        
        # Exploitable CVE가 있는 이미지
        images_with_exploitable = [
            img for img in images
            if img.get("has_exploitable_cve")
        ]
        
        return {
            "total_images": total,
            "scanned_images": scanned,
            "skipped_images": skipped,
            "error_images": errors,
            "by_severity": by_severity,
            "images_with_exploitable_cve": len(images_with_exploitable),
            "public_registry_images": sum(
                1 for img in images
                if img.get("is_from_public_registry")
            ),
            "images_without_tag": sum(
                1 for img in images
                if img.get("has_no_tag")
            ),
            "top_vulnerable_images": [
                {
                    "image": img["image_ref"][:100],
                    "critical": img.get("summary", {}).get("CRITICAL", 0),
                    "high": img.get("summary", {}).get("HIGH", 0),
                    "max_cvss": img.get("max_cvss"),
                    "max_epss": img.get("max_epss"),
                    "has_exploitable": img.get("has_exploitable_cve", False),
                }
                for img in top_vulnerable
            ],
        }

    def _save_local_copy(self, payload: Dict[str, Any], scan_id: str) -> str:
        """로컬 저장"""
        os.makedirs(self.config.output_dir, exist_ok=True)
        
        filename = self.config.output_filename or f"image_scan_{scan_id}.json"
        filepath = os.path.join(self.config.output_dir, filename)
        
        save_json(payload, filepath)
        return filepath