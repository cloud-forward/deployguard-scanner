"""DeployGuard Image Scanner - 컨테이너 이미지 CVE 스캔"""

import json
import subprocess
import os
import tempfile
from typing import Any, Dict, List
from .config import ScannerConfig
from .utils import generate_scan_id, get_timestamp


class ImageScanner:
    """컨테이너 이미지 CVE 스캐너 (Trivy 사용)"""
    
    def __init__(self, scanner_config: ScannerConfig = None, k8s_scan_result: Dict = None):
        self.config = scanner_config or ScannerConfig()
        self.scan_id = generate_scan_id()
        self.scan_time = get_timestamp()
        self.k8s_scan = k8s_scan_result
        self.trivy_available = self._check_trivy()

    def _check_trivy(self) -> bool:
        """Trivy 설치 확인"""
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            print(f"[+] Trivy: {result.stdout.strip().split()[0] if result.stdout else 'found'}")
            return True
        except FileNotFoundError:
            print("[-] Trivy not found - will collect image list only")
            return False
        except Exception as e:
            print(f"[-] Trivy check failed: {e}")
            return False

    def scan(self) -> Dict[str, Any]:
        """이미지 스캔 실행"""
        print(f"\n[*] Starting Image scan: {self.scan_id}")
        
        result = {
            "scan_id": self.scan_id,
            "scan_type": "image",
            "cluster_id": self.config.cluster_id,
            "cluster_name": self.config.cluster_name,
            "scanned_at": self.scan_time,
            "scanner_version": "1.0.0",
            "trivy_available": self.trivy_available,
            "images": [],
            "summary": {},
            "errors": []
        }
        
        # K8s 스캔 결과에서 이미지 목록 추출
        images = self._collect_images()
        print(f"[*] Found {len(images)} unique images")
        
        # 각 이미지 스캔
        for img_info in images[:self.config.max_images_per_scan]:
            print(f"[*] Scanning: {img_info['image_ref'][:60]}...")
            scanned = self._scan_single_image(img_info)
            result["images"].append(scanned)
        
        # 요약 생성
        result["summary"] = self._generate_summary(result["images"])
        
        return result

    def _collect_images(self) -> List[Dict]:
        """K8s 스캔 결과에서 이미지 목록 수집"""
        images = {}
        
        if not self.k8s_scan:
            print("[-] No K8s scan result provided")
            return []
        
        pods = self.k8s_scan.get("resources", {}).get("pods", [])
        
        for pod in pods:
            namespace = pod.get("namespace", "unknown")
            pod_name = pod.get("name", "unknown")
            
            for container in pod.get("containers", []):
                image_ref = container.get("image", "")
                if not image_ref:
                    continue
                
                if image_ref not in images:
                    images[image_ref] = {
                        "image_ref": image_ref,
                        "registry": self._parse_registry(image_ref),
                        "repository": self._parse_repository(image_ref),
                        "tag": self._parse_tag(image_ref),
                        "pods": [],
                        "namespaces": set(),
                    }
                
                images[image_ref]["pods"].append({
                    "namespace": namespace,
                    "name": pod_name,
                    "container": container.get("name", ""),
                })
                images[image_ref]["namespaces"].add(namespace)
        
        # set을 list로 변환
        for img in images.values():
            img["namespaces"] = list(img["namespaces"])
            img["pod_count"] = len(img["pods"])
        
        return list(images.values())

    def _parse_registry(self, image_ref: str) -> str:
        if "/" not in image_ref:
            return "docker.io"
        first_part = image_ref.split("/")[0]
        if "." in first_part or ":" in first_part:
            return first_part
        return "docker.io"

    def _parse_repository(self, image_ref: str) -> str:
        ref = image_ref.split(":")[0].split("@")[0]
        parts = ref.split("/")
        if len(parts) == 1:
            return f"library/{parts[0]}"
        elif len(parts) == 2 and "." not in parts[0]:
            return "/".join(parts)
        else:
            return "/".join(parts[1:])

    def _parse_tag(self, image_ref: str) -> str:
        if "@" in image_ref:
            return image_ref.split("@")[1][:12]
        if ":" in image_ref.split("/")[-1]:
            return image_ref.split(":")[-1]
        return "latest"

    def _scan_single_image(self, image_info: Dict) -> Dict:
        """단일 이미지 스캔"""
        result = {
            **image_info,
            "scan_status": "pending",
            "scanned_at": get_timestamp(),
            "vulnerabilities": [],
            "vulnerability_summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
            },
        }
        
        if not self.trivy_available:
            result["scan_status"] = "skipped"
            result["scan_error"] = "Trivy not available"
            return result
        
        image_ref = image_info["image_ref"]
        
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                output_file = f.name
            
            cmd = [
                "trivy", "image",
                "--format", "json",
                "--output", output_file,
                "--severity", "HIGH,CRITICAL",
                "--timeout", "3m",
                "--quiet",
                image_ref
            ]
            
            process = subprocess.run(cmd, capture_output=True, text=True, timeout=240)
            
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                with open(output_file, 'r') as f:
                    trivy_result = json.load(f)
                
                vulnerabilities = self._parse_trivy_result(trivy_result)
                result["vulnerabilities"] = vulnerabilities
                result["scan_status"] = "completed"
                
                for vuln in vulnerabilities:
                    sev = vuln.get("severity", "").lower()
                    if sev in result["vulnerability_summary"]:
                        result["vulnerability_summary"][sev] += 1
            else:
                result["scan_status"] = "completed"
            
            if os.path.exists(output_file):
                os.remove(output_file)
                
        except subprocess.TimeoutExpired:
            result["scan_status"] = "timeout"
        except Exception as e:
            result["scan_status"] = "error"
            result["scan_error"] = str(e)
        
        return result

    def _parse_trivy_result(self, trivy_result: Dict) -> List[Dict]:
        """Trivy 결과 파싱"""
        vulnerabilities = []
        
        for target in trivy_result.get("Results", []):
            for vuln in target.get("Vulnerabilities", []):
                vulnerabilities.append({
                    "cve_id": vuln.get("VulnerabilityID", ""),
                    "severity": vuln.get("Severity", "UNKNOWN"),
                    "title": vuln.get("Title", ""),
                    "pkg_name": vuln.get("PkgName", ""),
                    "installed_version": vuln.get("InstalledVersion", ""),
                    "fixed_version": vuln.get("FixedVersion", ""),
                    "cvss_score": self._get_cvss(vuln),
                })
        
        return vulnerabilities

    def _get_cvss(self, vuln: Dict) -> float:
        cvss = vuln.get("CVSS", {})
        for source in ["nvd", "redhat", "ghsa"]:
            if source in cvss and "V3Score" in cvss[source]:
                return cvss[source]["V3Score"]
        return 0.0

    def _generate_summary(self, images: List[Dict]) -> Dict:
        summary = {
            "total_images": len(images),
            "scanned_images": 0,
            "skipped_images": 0,
            "total_vulnerabilities": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "top_vulnerable_images": [],
        }
        
        vuln_counts = []
        
        for img in images:
            if img.get("scan_status") == "completed":
                summary["scanned_images"] += 1
            else:
                summary["skipped_images"] += 1
            
            vulns = img.get("vulnerabilities", [])
            summary["total_vulnerabilities"] += len(vulns)
            
            vuln_counts.append({
                "image": img.get("image_ref", "")[:50],
                "critical": img.get("vulnerability_summary", {}).get("critical", 0),
                "high": img.get("vulnerability_summary", {}).get("high", 0),
            })
            
            for vuln in vulns:
                sev = vuln.get("severity", "").lower()
                if sev in summary["by_severity"]:
                    summary["by_severity"][sev] += 1
        
        vuln_counts.sort(key=lambda x: (x["critical"], x["high"]), reverse=True)
        summary["top_vulnerable_images"] = vuln_counts[:5]
        
        return summary
