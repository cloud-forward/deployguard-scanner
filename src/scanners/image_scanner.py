"""이미지 취약점 스캐너 - Trivy 사용"""
import subprocess
import json
import logging
import re
from typing import Optional
from datetime import datetime

from ..config import Config
from ..models.schemas import ImageScanResult, ImageVulnerability

logger = logging.getLogger(__name__)


class ImageScanner:
    """Trivy 기반 이미지 취약점 스캐너"""
    
    PUBLIC_REGISTRIES = {
        'docker.io', 'registry.hub.docker.com', 'index.docker.io',
        'gcr.io', 'ghcr.io', 'quay.io', 'registry.k8s.io',
        'public.ecr.aws', 'mcr.microsoft.com'
    }
    
    def __init__(self, cfg: Config):
        self.config = cfg
        self.scanned_images: dict[str, ImageScanResult] = {}
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
            if result.returncode == 0:
                version = result.stdout.strip().split('\n')[0]
                logger.info(f"Trivy available: {version}")
                return True
        except FileNotFoundError:
            logger.warning("Trivy not found - image scanning disabled")
        except Exception as e:
            logger.warning(f"Trivy check failed: {e}")
        return False
    
    def scan_images(self, images: list[str], image_to_workloads: dict[str, list[str]]) -> list[ImageScanResult]:
        """
        이미지 목록 스캔
        
        Args:
            images: 스캔할 이미지 목록
            image_to_workloads: 이미지별 사용 워크로드 매핑
        """
        if not self.config.enable_image_scan:
            logger.info("Image scanning disabled by config")
            return []
        
        if not self.trivy_available:
            logger.warning("Trivy not available - skipping image scan")
            return []
        
        results = []
        unique_images = list(set(images))
        logger.info(f"Scanning {len(unique_images)} unique images")
        
        for i, image in enumerate(unique_images):
            logger.info(f"[{i+1}/{len(unique_images)}] Scanning: {image}")
            
            # 캐시 확인
            if image in self.scanned_images:
                result = self.scanned_images[image]
                logger.info(f"  Using cached result")
            else:
                result = self._scan_single_image(image)
                if result:
                    self.scanned_images[image] = result
            
            if result:
                result.used_by_pods = image_to_workloads.get(image, [])
                result.used_by_workloads = image_to_workloads.get(image, [])
                results.append(result)
        
        logger.info(f"Image scan complete: {len(results)} images scanned")
        return results
    
    def _scan_single_image(self, image: str) -> Optional[ImageScanResult]:
        """단일 이미지 스캔"""
        try:
            cmd = [
                "trivy", "image",
                "--format", "json",
                "--severity", self.config.trivy_severity,
                "--quiet",
                "--timeout", "5m",
                image
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=360
            )
            
            if result.returncode != 0:
                logger.warning(f"  Trivy scan failed: {result.stderr[:200]}")
                return self._create_error_result(image, result.stderr)
            
            return self._parse_trivy_output(image, result.stdout)
            
        except subprocess.TimeoutExpired:
            logger.error(f"  Trivy scan timeout for {image}")
            return self._create_error_result(image, "Scan timeout")
        except Exception as e:
            logger.error(f"  Error scanning {image}: {e}")
            return self._create_error_result(image, str(e))
    
    def _parse_trivy_output(self, image: str, output: str) -> Optional[ImageScanResult]:
        """Trivy JSON 출력 파싱"""
        try:
            data = json.loads(output)
        except json.JSONDecodeError as e:
            logger.error(f"  Failed to parse Trivy output: {e}")
            return None
        
        vulnerabilities = []
        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        os_family = "unknown"
        os_name = None
        
        # Metadata
        metadata = data.get("Metadata", {})
        
        # Results 배열 처리
        for result in data.get("Results", []):
            result_class = result.get("Class", "")
            result_type = result.get("Type", "")
            
            # OS 정보
            if result_class == "os-pkgs":
                os_family = result_type
                os_name = result.get("Target", "")
            
            # 취약점
            for vuln in result.get("Vulnerabilities", []):
                severity = vuln.get("Severity", "UNKNOWN").upper()
                if severity in summary:
                    summary[severity] += 1
                else:
                    summary["UNKNOWN"] += 1
                
                vulnerabilities.append(ImageVulnerability(
                    cve_id=vuln.get("VulnerabilityID", ""),
                    severity=severity,
                    package=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion"),
                    title=vuln.get("Title", ""),
                    description=(vuln.get("Description", "") or "")[:1000],
                    cvss_score=self._get_cvss_score(vuln),
                    cvss_vector=self._get_cvss_vector(vuln),
                    published_date=vuln.get("PublishedDate"),
                    last_modified_date=vuln.get("LastModifiedDate"),
                    references=vuln.get("References", [])[:5],
                ))
        
        # 이미지 정보 파싱
        registry, repository, tag = self._parse_image_name(image)
        
        logger.info(f"  Found {sum(summary.values())} vulnerabilities: "
                   f"C={summary['CRITICAL']}, H={summary['HIGH']}, "
                   f"M={summary['MEDIUM']}, L={summary['LOW']}")
        
        return ImageScanResult(
            image=image,
            digest=self._get_digest(metadata),
            scan_timestamp=datetime.utcnow().isoformat() + "Z",
            registry=registry,
            repository=repository,
            tag=tag,
            os_family=os_family,
            os_name=os_name,
            size_bytes=metadata.get("Size"),
            vulnerabilities=vulnerabilities,
            summary=summary,
            is_from_public_registry=self._is_public_registry(registry),
            has_no_tag=tag in (None, "latest", ""),
        )
    
    def _create_error_result(self, image: str, error: str) -> ImageScanResult:
        """스캔 실패 시 에러 결과 생성"""
        registry, repository, tag = self._parse_image_name(image)
        return ImageScanResult(
            image=image,
            digest=None,
            scan_timestamp=datetime.utcnow().isoformat() + "Z",
            registry=registry,
            repository=repository,
            tag=tag,
            os_family="unknown",
            os_name=None,
            size_bytes=None,
            vulnerabilities=[],
            summary={"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "ERROR": 1},
            is_from_public_registry=self._is_public_registry(registry),
            has_no_tag=tag in (None, "latest", ""),
        )
    
    def _parse_image_name(self, image: str) -> tuple[Optional[str], Optional[str], Optional[str]]:
        """이미지 이름 파싱 -> (registry, repository, tag)"""
        # 예: nginx:1.19 -> (docker.io, library/nginx, 1.19)
        # 예: gcr.io/project/app:v1 -> (gcr.io, project/app, v1)
        
        # 태그/다이제스트 분리
        if "@sha256:" in image:
            image_part, digest = image.rsplit("@", 1)
            tag = f"@{digest}"
        elif ":" in image.rsplit("/", 1)[-1]:
            image_part, tag = image.rsplit(":", 1)
        else:
            image_part = image
            tag = "latest"
        
        # Registry 분리
        parts = image_part.split("/")
        if len(parts) == 1:
            # nginx -> docker.io/library/nginx
            return "docker.io", f"library/{parts[0]}", tag
        elif len(parts) == 2:
            if "." in parts[0] or ":" in parts[0]:
                # gcr.io/nginx or localhost:5000/nginx
                return parts[0], parts[1], tag
            else:
                # username/repo -> docker.io/username/repo
                return "docker.io", image_part, tag
        else:
            # gcr.io/project/app
            return parts[0], "/".join(parts[1:]), tag
    
    def _is_public_registry(self, registry: Optional[str]) -> bool:
        """공개 레지스트리 여부"""
        if not registry:
            return True
        return registry.lower() in self.PUBLIC_REGISTRIES
    
    def _get_cvss_score(self, vuln: dict) -> Optional[float]:
        """CVSS 점수 추출"""
        cvss = vuln.get("CVSS", {})
        # NVD 우선, 그 다음 다른 소스
        for source in ["nvd", "redhat", "ghsa"]:
            if source in cvss:
                return cvss[source].get("V3Score") or cvss[source].get("V2Score")
        return None
    
    def _get_cvss_vector(self, vuln: dict) -> Optional[str]:
        """CVSS 벡터 추출"""
        cvss = vuln.get("CVSS", {})
        for source in ["nvd", "redhat", "ghsa"]:
            if source in cvss:
                return cvss[source].get("V3Vector") or cvss[source].get("V2Vector")
        return None
    
    def _get_digest(self, metadata: dict) -> Optional[str]:
        """이미지 다이제스트 추출"""
        digests = metadata.get("RepoDigests", [])
        if digests:
            # sha256:xxx 부분만 추출
            for d in digests:
                if "@sha256:" in d:
                    return d.split("@")[-1]
        return None