"""
DeployGuard Image Scanner - Canonical Raw Contract v3.1

출력 계약(canonical contract):
  top-level: scan_id, cluster_id, scanned_at, scanner_version,
             total_images, images
  per-image: image_ref, image_digest, registry, repository, tag,
             signature, metadata, scan_status, vulnerability_summary,
             vulnerabilities, used_by_pods

불변 원칙:
  - scanner는 raw evidence만 수집/정규화한다.
  - Risk 계산 / 공격경로 해석 / 랭킹은 scanner 책임이 아니다.
  - 모든 discovered image는 payload에 포함된다 (scan limit 초과 시 skipped).
  - 필드 누락 금지: 수집 불가한 값은 빈 문자열/0/기본 구조로 채운다.
  - scanner_version: scan tool(trivy) 버전. "trivy-X.Y.Z" 형식.
    trivy 버전 미확인 시 "trivy-unknown".
  - scan_status: completed | skipped | timeout | failed
  - image_digest: string. 조회 실패 시 빈 문자열("").
  - used_by_pods: [{"namespace": "...", "pod_name": "..."}] 정렬됨
  - vulnerabilities: cve_id 오름차순 stable sort
  - EPSS 데이터가 없으면 epss_score=0.0, epss_percentile=None
    (epss_enabled=False, cache miss 모두 동일)
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
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import urlopen

from .config import ScannerConfig
from .api_client import DeployGuardAPIClient
from .utils import generate_scan_id, get_timestamp, save_json
from shared.orchestrator import ScanOrchestrator


# ---------------------------------------------------------------------------
# 알려진 Exploitable CVE (Analysis Engine과 동기화)
# ---------------------------------------------------------------------------
KNOWN_EXPLOITABLE_CVES: frozenset = frozenset({
    'CVE-2021-44228',  # Log4Shell
    'CVE-2021-45046',  # Log4j
    'CVE-2022-22965',  # Spring4Shell
    'CVE-2021-3156',   # Sudo Baron Samedit
    'CVE-2022-0847',   # Dirty Pipe
    'CVE-2024-21626',  # runc
    'CVE-2024-3094',   # xz backdoor
})

# Public Registry 목록
PUBLIC_REGISTRIES: frozenset = frozenset({
    'docker.io', 'registry.hub.docker.com', 'index.docker.io',
    'gcr.io', 'ghcr.io', 'quay.io', 'registry.k8s.io',
    'public.ecr.aws', 'mcr.microsoft.com',
})

# ---------------------------------------------------------------------------
# Trivy DB 경로 — initContainer가 채우는 경로와 일치해야 한다
# ---------------------------------------------------------------------------
_TRIVY_DB_PATHS = [
    os.path.expanduser("~/.cache/trivy/db/trivy.db"),
    "/root/.cache/trivy/db/trivy.db",
    "/home/scanner/.cache/trivy/db/trivy.db",
]


def _trivy_db_exists() -> bool:
    """
    Trivy vulnerability DB 파일이 실제로 존재하는지 확인.

    [FIX] --skip-db-update는 DB가 이미 존재할 때만 사용할 수 있다.
    첫 실행(DB 없음)에서 이 플래그를 붙이면
    'cannot be specified on the first run' 오류가 발생한다.

    initContainer(trivy-db-init)가 /root/.cache/trivy에 DB를 미리 채우면
    이 함수는 True를 반환하고 --skip-db-update가 활성화된다.
    """
    return any(os.path.exists(p) for p in _TRIVY_DB_PATHS)


# ---------------------------------------------------------------------------
# 기본(default) 구조체 팩토리
# ---------------------------------------------------------------------------

def _default_signature() -> Dict[str, Any]:
    return {"signed": False, "signer": None, "signature_type": None}


def _default_metadata() -> Dict[str, Any]:
    return {
        "os": None,
        "architecture": None,
        "has_healthcheck": None,
        "created_at": None,
        "image_age_days": None,
        "total_layers": None,
        "image_size_mb": None,
    }


def _default_vulnerability_summary() -> Dict[str, Any]:
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
        "total": 0,
        "max_cvss": None,
        "max_epss": None,
        "fixable": 0,
        "has_known_exploitable_cve": False,
    }


# ---------------------------------------------------------------------------
# ImageScanner
# ---------------------------------------------------------------------------

class ImageScanner:
    """
    컨테이너 이미지 CVE 스캐너 — Canonical Raw Contract v3.1

    책임:
      - 이미지 수집 (K8s scan 결과 활용)
      - Trivy CVE 스캔
      - EPSS enrichment
      - signature 확인 (cosign)
      - image metadata 수집 (docker inspect / trivy)
      - canonical payload 생성

    비책임 (downstream Analysis Engine 역할):
      - Risk 점수 계산
      - 공격경로 분석
      - 취약 이미지 랭킹
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

        # 도구 가용성
        self.trivy_available = self._check_tool("trivy") if self.config.trivy_enabled else False
        self.trivy_version = self._get_trivy_version() if self.trivy_available else None
        self.cosign_available = self._check_tool("cosign")
        self.docker_available = self._check_tool("docker")

        # [FIX] 스캐너 시작 시점에 DB 존재 여부를 한 번 확인하고 캐시
        # 매 이미지 스캔마다 stat() 호출을 피하기 위해 인스턴스 변수로 저장
        self._trivy_db_ready = _trivy_db_exists()
        if self.trivy_available:
            db_status = "ready" if self._trivy_db_ready else "not found (will download on first scan)"
            print(f"[*] Trivy DB: {db_status}")

        # EPSS 캐시
        self._epss_cache: Dict[str, Dict[str, Optional[float]]] = {}
        self._epss_loaded = False

    # =========================================================================
    # 도구 확인
    # =========================================================================

    def _check_tool(self, name: str) -> bool:
        try:
            result = subprocess.run(
                [name, "--version"],
                capture_output=True, text=True, timeout=10,
            )
            available = result.returncode == 0
            status = "available" if available else "not available"
            print(f"[{'+'if available else '-'}] {name}: {status}")
            return available
        except FileNotFoundError:
            print(f"[-] {name}: not found")
            return False
        except Exception as e:
            print(f"[-] {name}: check failed ({e})")
            return False

    def _get_trivy_version(self) -> Optional[str]:
        try:
            result = subprocess.run(
                ["trivy", "--version"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.splitlines():
                if "Version:" in line:
                    return line.split(":")[-1].strip()
        except Exception:
            pass
        return None

    # =========================================================================
    # EPSS 데이터 로드
    # =========================================================================

    def _load_epss_data(self) -> None:
        """EPSS CSV 다운로드 및 캐시 구축."""
        if self._epss_loaded or not self.config.epss_enabled:
            return
        try:
            print("[*] Loading EPSS data...")
            url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
            with urlopen(url, timeout=30) as resp:
                compressed = resp.read()
            decompressed = gzip.decompress(compressed).decode("utf-8")
            reader = csv.DictReader(StringIO(decompressed))
            count = 0
            for row in reader:
                cve_id = row.get("cve")
                if cve_id:
                    self._epss_cache[cve_id] = {
                        "epss_score": float(row.get("epss", 0) or 0),
                        "epss_percentile": float(row.get("percentile", 0) or 0),
                    }
                    count += 1
            self._epss_loaded = True
            print(f"[+] Loaded EPSS data for {count} CVEs")
        except Exception as e:
            print(f"[-] Failed to load EPSS data: {e}")
            self._epss_loaded = True  # 재시도 방지

    def _get_epss(self, cve_id: str) -> Dict[str, Optional[float]]:
        """CVE의 EPSS 조회.
        - cache hit  → 실제 값 반환
        - cache miss → {"epss_score": 0.0, "epss_percentile": None}
        - epss_enabled=False → {"epss_score": 0.0, "epss_percentile": None}
        payload contract 일관성을 위해 항상 동일한 fallback 반환.
        """
        _fallback: Dict[str, Optional[float]] = {"epss_score": 0.0, "epss_percentile": None}
        if not self.config.epss_enabled:
            return _fallback
        self._load_epss_data()
        return self._epss_cache.get(cve_id, _fallback)

    # =========================================================================
    # 메인 실행 메서드
    # =========================================================================

    def run(self) -> Dict[str, Any]:
        return self.run_scheduled_scan()

    def run_manual_scan(self) -> Dict[str, Any]:
        return self._run_scan(trigger_mode="manual")

    def run_scheduled_scan(self) -> Dict[str, Any]:
        return self._run_scan(trigger_mode="scheduled")

    def run_worker_scan(self, scan_id: str, trigger_mode: str = "scheduled") -> Dict[str, Any]:
        api_client = DeployGuardAPIClient(self.config)
        api_client.bind_scan(scan_id, "image")
        self.scan_id = scan_id
        return self._execute_scan(api_client=api_client, scan_id=scan_id, trigger_mode=trigger_mode)

    def _run_scan(self, trigger_mode: str) -> Dict[str, Any]:
        print(f"\n{'='*60}")
        print(f"DeployGuard Image Scanner v3.1.0")
        print(f"Cluster: {self.config.cluster_id}")
        print(f"Mode: {trigger_mode}")
        print(f"Trivy: {'available' if self.trivy_available else 'not available'}")
        print(f"Trivy DB: {'ready' if self._trivy_db_ready else 'will download'}")
        print(f"Cosign: {'available' if self.cosign_available else 'not available'}")
        print(f"EPSS: {'enabled' if self.config.epss_enabled else 'disabled'}")
        print(f"{'='*60}\n")

        api_client = DeployGuardAPIClient(self.config)
        orchestrator = ScanOrchestrator(self.config, api_client)
        scan_id = orchestrator.start_scan(scanner_type="image", trigger_mode=trigger_mode)
        self.scan_id = scan_id
        return self._execute_scan(api_client=api_client, scan_id=scan_id, trigger_mode=trigger_mode)

    def _execute_scan(
        self,
        api_client: DeployGuardAPIClient,
        scan_id: str,
        trigger_mode: str,
    ) -> Dict[str, Any]:
        orchestrator = ScanOrchestrator(self.config, api_client)

        # Step 1: 전체 unique image 수집 (스캔 제한과 무관하게 전부 discovery)
        all_images = self._collect_images()
        total_discovered = len(all_images)
        print(f"[*] Discovered {total_discovered} unique images")

        scan_limit = self.config.max_images_per_scan
        to_scan = all_images[:scan_limit]
        to_skip = all_images[scan_limit:]

        # Step 2: 스캔 실행
        scanned: List[Dict[str, Any]] = []
        for idx, img_info in enumerate(to_scan):
            print(f"[{idx+1}/{len(to_scan)}] Scanning: {img_info['image_ref'][:60]}...")
            scanned.append(self._scan_single_image(img_info))

        # Step 3: 제한 초과 이미지 → skipped로 채워 payload에 포함
        for img_info in to_skip:
            skipped_item = self._make_skipped_image(img_info, reason="scan limit exceeded")
            scanned.append(skipped_item)

        # Step 4: payload 조립
        payload = self._build_payload(
            scan_id=scan_id,
            trigger_mode=trigger_mode,
            images=scanned,
        )

        local_file = None
        if self.config.save_local_copy:
            local_file = self._save_local_copy(payload, scan_id)

        uploaded_files = [orchestrator.upload_result(payload, self.config.upload_file_name)]

        run_summary = payload.get("run_summary", {})
        complete_result = orchestrator.complete_scan(
            meta={
                "scanner_type": "image",
                "trigger_mode": trigger_mode,
                "total_images": run_summary.get("total_images", 0),
                "completed_images": run_summary.get("completed_images", 0),
                "vulnerability_counts": self._aggregate_severity(scanned),
            }
        )

        return orchestrator.build_result(
            scan_id=scan_id,
            payload=payload,
            complete_result=complete_result,
            uploaded_files=uploaded_files,
            local_file=local_file,
        )

    def scan(self) -> Dict[str, Any]:
        """하위 호환용 — canonical payload만 반환."""
        all_images = self._collect_images()
        scan_limit = self.config.max_images_per_scan
        scanned = []
        for img_info in all_images[:scan_limit]:
            scanned.append(self._scan_single_image(img_info))
        for img_info in all_images[scan_limit:]:
            scanned.append(self._make_skipped_image(img_info, reason="scan limit exceeded"))
        return self._build_payload(scan_id=self.scan_id, trigger_mode="manual", images=scanned)

    # =========================================================================
    # 이미지 수집
    # =========================================================================

    def _collect_images(self) -> List[Dict[str, Any]]:
        """
        K8s scan 결과에서 unique image를 수집한다.

        내부 표현:
          _pod_refs: [{"namespace": str, "pod_name": str,
                       "container_name": str, "is_init_container": bool}]
        최종 output에서는 used_by_pods(namespace/pod_name만) 로 canonicalize.
        """
        images: Dict[str, Dict[str, Any]] = {}

        if not self.k8s_scan:
            print("[-] No K8s scan result provided — no images to scan")
            return []

        # canonical K8s payload는 top-level에 pods 배열
        pods = (
            self.k8s_scan.get("pods")
            or self.k8s_scan.get("resources", {}).get("pods")
            or self.k8s_scan.get("k8s", {}).get("pods")
            or []
        )

        for pod in pods:
            namespace = pod.get("namespace", "unknown")
            pod_name = pod.get("name", "unknown")

            for container in pod.get("containers", []):
                self._add_image(images, container, namespace, pod_name, is_init=False)

            for container in pod.get("init_containers", []):
                self._add_image(images, container, namespace, pod_name, is_init=True)

        # 많이 사용되는 이미지 먼저 (stable sort)
        result = sorted(
            images.values(),
            key=lambda x: (-len(x["_pod_refs"]), x["image_ref"]),
        )
        return result

    def _add_image(
        self,
        images: Dict[str, Dict[str, Any]],
        container: Dict[str, Any],
        namespace: str,
        pod_name: str,
        is_init: bool,
    ) -> None:
        image_ref = container.get("image", "").strip()
        if not image_ref:
            return

        if image_ref not in images:
            parsed = self._parse_image_ref(image_ref)
            images[image_ref] = {
                # canonical output fields
                "image_ref": image_ref,
                "image_digest": None,  # trivy/inspect 시점에 채움
                "registry": parsed["registry"],
                "repository": parsed["repository"],
                "tag": parsed["tag"],
                # internal — 최종 output에서 used_by_pods로 변환
                "_pod_refs": [],
                # internal flags (canonical output에 노출 안 함)
                "_is_public_registry": parsed["registry"] in PUBLIC_REGISTRIES,
                "_has_no_tag": not parsed["tag"] or parsed["tag"] == "latest",
            }

        # pod ref 중복 방지 (namespace + pod_name 기준)
        existing_refs = images[image_ref]["_pod_refs"]
        pod_key = (namespace, pod_name)
        if not any(r["namespace"] == namespace and r["pod_name"] == pod_name for r in existing_refs):
            existing_refs.append({
                "namespace": namespace,
                "pod_name": pod_name,
                # internal: container 세부 정보 (canonical output에서는 제외)
                "_container_name": container.get("name", ""),
                "_is_init_container": is_init,
            })

    def _parse_image_ref(self, image_ref: str) -> Dict[str, Optional[str]]:
        """이미지 참조 파싱. 결과는 항상 registry/repository/tag/digest 보장."""
        result: Dict[str, Optional[str]] = {
            "registry": "docker.io",
            "repository": "",
            "tag": "latest",
            "digest": None,
        }

        # digest 분리
        if "@" in image_ref:
            image_part, digest = image_ref.split("@", 1)
            result["digest"] = digest
        else:
            image_part = image_ref

        # tag 분리
        tag = "latest"
        if ":" in image_part:
            parts = image_part.rsplit(":", 1)
            # 포트 번호("host:5000")와 tag("image:v1") 구분
            if not re.search(r"[/:]", parts[-1]):
                image_part = parts[0]
                tag = parts[1]
        result["tag"] = tag or "latest"

        # registry / repository 분리
        parts = image_part.split("/")
        if len(parts) == 1:
            result["repository"] = f"library/{parts[0]}"
        elif len(parts) == 2:
            if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
                result["registry"] = parts[0]
                result["repository"] = parts[1]
            else:
                result["repository"] = "/".join(parts)
        else:
            if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
                result["registry"] = parts[0]
                result["repository"] = "/".join(parts[1:])
            else:
                result["repository"] = "/".join(parts)

        return result

    # =========================================================================
    # 단일 이미지 스캔 (핵심)
    # =========================================================================

    def _scan_single_image(self, image_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        단일 이미지에 대해:
          1. Trivy CVE 스캔
          2. EPSS enrichment
          3. signature 수집 (cosign)
          4. metadata 수집 (trivy/docker inspect)
          5. vulnerability_summary 계산
          6. canonical output 조립

        scan_status:
          completed — 스캔 정상 완료 (취약점 0개도 completed)
          skipped   — trivy unavailable 또는 scan limit 초과
          timeout   — 스캔 시간 초과
          failed    — 기타 오류
        """
        image_ref = image_info["image_ref"]
        item: Dict[str, Any] = {
            "image_ref": image_ref,
            "image_digest": image_info.get("image_digest"),
            "registry": image_info["registry"],
            "repository": image_info["repository"],
            "tag": image_info["tag"],
            "signature": _default_signature(),
            "metadata": _default_metadata(),
            "scan_status": "pending",
            "scan_error": None,
            "vulnerability_summary": _default_vulnerability_summary(),
            "vulnerabilities": [],
            "used_by_pods": self._canonicalize_pod_refs(image_info["_pod_refs"]),
        }

        # trivy 없으면 skipped
        if not self.trivy_available:
            item["scan_status"] = "skipped"
            item["scan_error"] = "trivy not available"
            # signature / metadata는 가능한 범위에서 수집 시도
            item["signature"] = self._collect_signature(image_ref)
            item["metadata"] = self._collect_image_metadata(image_ref)
            return item

        try:
            # (a) Trivy 스캔 — 실패 시 RuntimeError raise, 타임아웃 시 TimeoutExpired raise
            vulnerabilities, digest_from_trivy, metadata_from_trivy = self._run_trivy_scan(image_ref)

            # digest 업데이트
            if digest_from_trivy:
                item["image_digest"] = digest_from_trivy

            # (b) EPSS enrichment
            vulnerabilities = self._enrich_epss(vulnerabilities)

            # (c) cve_id 오름차순 stable sort
            vulnerabilities.sort(key=lambda v: v.get("cve_id", ""))

            item["vulnerabilities"] = vulnerabilities
            item["vulnerability_summary"] = self._build_vulnerability_summary(vulnerabilities)

            # metadata: trivy에서 추출된 것 우선, 부족하면 docker inspect 보완
            item["metadata"] = self._merge_metadata(metadata_from_trivy, image_ref)

            # (d) signature 수집 (스캔 결과와 독립)
            item["signature"] = self._collect_signature(image_ref)

            item["scan_status"] = "completed"
            item["scan_error"] = None

        except subprocess.TimeoutExpired:
            item["scan_status"] = "timeout"
            item["scan_error"] = "scan timed out"
            item["signature"] = self._collect_signature(image_ref)
            item["metadata"] = self._collect_image_metadata(image_ref)

        except RuntimeError as e:
            # _run_trivy_scan이 raise한 구체 실패 메시지 (exit code / 파일 없음 / JSON 오류 등)
            item["scan_status"] = "failed"
            item["scan_error"] = str(e)
            item["signature"] = self._collect_signature(image_ref)
            item["metadata"] = self._collect_image_metadata(image_ref)

        except Exception as e:
            # 예상치 못한 예외
            item["scan_status"] = "failed"
            item["scan_error"] = f"unexpected error: {e}"
            item["signature"] = self._collect_signature(image_ref)
            item["metadata"] = self._collect_image_metadata(image_ref)

        return item

    def _make_skipped_image(self, image_info: Dict[str, Any], reason: str) -> Dict[str, Any]:
        """scan limit 초과 이미지 — skipped 상태로 payload에 포함."""
        return {
            "image_ref": image_info["image_ref"],
            "image_digest": image_info.get("image_digest"),
            "registry": image_info["registry"],
            "repository": image_info["repository"],
            "tag": image_info["tag"],
            "signature": _default_signature(),
            "metadata": _default_metadata(),
            "scan_status": "skipped",
            "scan_error": reason,
            "vulnerability_summary": _default_vulnerability_summary(),
            "vulnerabilities": [],
            "used_by_pods": self._canonicalize_pod_refs(image_info["_pod_refs"]),
        }

    def _canonicalize_pod_refs(self, pod_refs: List[Dict[str, Any]]) -> List[Dict[str, str]]:
        """
        내부 _pod_refs → canonical used_by_pods.
        출력: [{"namespace": "...", "pod_name": "..."}] — stable sort.
        """
        seen = set()
        result = []
        for ref in pod_refs:
            key = (ref["namespace"], ref["pod_name"])
            if key not in seen:
                seen.add(key)
                result.append({"namespace": ref["namespace"], "pod_name": ref["pod_name"]})
        return sorted(result, key=lambda r: (r["namespace"], r["pod_name"]))

    # =========================================================================
    # Trivy 스캔
    # =========================================================================

    def _run_trivy_scan(
        self, image_ref: str
    ) -> Tuple[List[Dict[str, Any]], Optional[str], Dict[str, Any]]:
        """
        Trivy JSON 스캔 실행.

        [FIX] --skip-db-update는 DB 파일이 실제로 존재하는 경우에만 추가한다.
        DB가 없는 상태(첫 실행 또는 emptyDir 초기화 직후)에서 이 플래그를
        사용하면 Trivy가 FATAL 오류를 반환한다.

        DB 존재 여부: self._trivy_db_ready (인스턴스 생성 시 _trivy_db_exists()로 결정)
        config.trivy_skip_db_update: 운영자 의도 플래그 (True = skip 원함)
        최종 적용: config.trivy_skip_db_update AND self._trivy_db_ready

        Returns:
          (vulnerabilities, digest, metadata_from_trivy)

        Raises:
          RuntimeError          — trivy 프로세스 실패 / 출력 파일 미생성 /
                                  빈 파일 / JSON 파싱 오류
          subprocess.TimeoutExpired — 타임아웃 (호출부에서 별도 처리)
        """
        output_file = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                output_file = f.name

            cmd = [
                "trivy", "image",
                "--format", "json",
                "--output", output_file,
                "--severity", self.config.trivy_severity,
                "--timeout", self.config.trivy_timeout,
                "--quiet",
            ]

            # [FIX] --skip-db-update: 설정 플래그 AND DB 파일 실제 존재 시에만 추가
            # config.trivy_skip_db_update=True여도 DB가 없으면 붙이지 않는다
            use_skip_db_update = self.config.trivy_skip_db_update and self._trivy_db_ready
            if use_skip_db_update:
                cmd.append("--skip-db-update")
            else:
                print(f"    [*] Trivy DB not found or skip disabled — will download DB for: {image_ref[:50]}")

            cmd.append(image_ref)

            proc = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=300,
                check=False,   # returncode는 아래에서 직접 검사
            )

            # returncode != 0 → 실패. stderr / stdout 첫 200자에서 원인 추출.
            if proc.returncode != 0:
                raw_err = (proc.stderr or proc.stdout or "").strip()
                cause = raw_err[:200] if raw_err else "unknown error"
                raise RuntimeError(
                    f"trivy failed: exit code {proc.returncode}: {cause}"
                )

            # 출력 파일 미생성
            if not os.path.exists(output_file):
                raise RuntimeError("trivy failed: no output file generated")

            # 출력 파일 비어 있음
            if os.path.getsize(output_file) == 0:
                raise RuntimeError("trivy failed: empty output file")

            # JSON 파싱 실패
            try:
                with open(output_file, "r") as f:
                    raw = json.load(f)
            except json.JSONDecodeError as e:
                raise RuntimeError(f"trivy failed: invalid JSON output: {e}") from e

            vulns = self._parse_trivy_vulnerabilities(raw)
            digest = self._extract_trivy_digest(raw)
            meta = self._extract_trivy_metadata(raw)
            return (vulns, digest, meta)

        finally:
            if output_file and os.path.exists(output_file):
                try:
                    os.unlink(output_file)
                except Exception:
                    pass

    def _parse_trivy_vulnerabilities(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Trivy JSON → canonical vulnerability list."""
        vulnerabilities = []
        for result_block in raw.get("Results", []):
            target = result_block.get("Target", "")
            target_type = result_block.get("Type", "")
            for v in result_block.get("Vulnerabilities", []):
                cve_id = v.get("VulnerabilityID", "")
                severity = v.get("Severity", "UNKNOWN").upper()

                # CVSS: NVD 우선 → redhat → ghsa
                cvss_score: Optional[float] = None
                cvss_vector: Optional[str] = None
                for source in ("nvd", "redhat", "ghsa"):
                    cvss_block = (v.get("CVSS") or {}).get(source, {})
                    if cvss_block:
                        cvss_score = cvss_block.get("V3Score") or cvss_block.get("V2Score")
                        cvss_vector = cvss_block.get("V3Vector") or cvss_block.get("V2Vector")
                        if cvss_score:
                            break

                published_raw = v.get("PublishedDate")
                last_modified_raw = v.get("LastModifiedDate")

                vulnerabilities.append({
                    "cve_id": cve_id,
                    "severity": severity,
                    "cvss_score": float(cvss_score) if cvss_score is not None else None,
                    "cvss_vector": cvss_vector,
                    "epss_score": None,           # _enrich_epss에서 채움
                    "epss_percentile": None,
                    "title": v.get("Title", ""),
                    "description": (v.get("Description") or "")[:500],
                    "pkg_name": v.get("PkgName", ""),
                    "installed_version": v.get("InstalledVersion", ""),
                    "fixed_version": v.get("FixedVersion") or None,
                    "fix_available": bool(v.get("FixedVersion")),
                    "published_at": published_raw,
                    "last_modified_at": last_modified_raw,
                    "references": (v.get("References") or [])[:5],
                    "target": target,
                    "target_type": target_type,
                    "is_known_exploitable": cve_id in KNOWN_EXPLOITABLE_CVES,
                })
        return vulnerabilities

    def _extract_trivy_digest(self, raw: Dict[str, Any]) -> Optional[str]:
        """Trivy JSON から image digest 추출 시도."""
        meta = raw.get("Metadata", {})
        repo_digests = meta.get("RepoDigests", [])
        if repo_digests:
            first = repo_digests[0]
            if "@" in first:
                return first.split("@", 1)[1]
        image_id = meta.get("ImageID")
        if image_id and image_id.startswith("sha256:"):
            return image_id
        return None

    def _extract_trivy_metadata(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        """Trivy JSON의 Metadata 섹션에서 image metadata 추출."""
        meta = raw.get("Metadata", {})
        os_info = meta.get("OS", {}) or {}
        image_config = meta.get("ImageConfig", {}) or {}
        config_section = image_config.get("config", {}) or {}

        created_at_raw: Optional[str] = image_config.get("created") or meta.get("Created")
        image_age_days: Optional[int] = None
        if created_at_raw:
            try:
                created_dt = datetime.fromisoformat(
                    created_at_raw.replace("Z", "+00:00")
                )
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                image_age_days = (datetime.now(timezone.utc) - created_dt).days
            except Exception:
                pass

        diff_ids = image_config.get("rootfs", {}).get("diff_ids", [])
        total_layers = len(diff_ids) if diff_ids else None

        size_bytes = meta.get("Size")
        image_size_mb: Optional[float] = None
        if size_bytes:
            try:
                image_size_mb = round(float(size_bytes) / (1024 * 1024), 2)
            except Exception:
                pass

        has_healthcheck: Optional[bool] = None
        if "Healthcheck" in config_section or "healthcheck" in config_section:
            has_healthcheck = True
        elif config_section:
            has_healthcheck = False

        return {
            "os": os_info.get("Family") or os_info.get("Name") or None,
            "architecture": meta.get("Architecture") or image_config.get("architecture") or None,
            "has_healthcheck": has_healthcheck,
            "created_at": created_at_raw,
            "image_age_days": image_age_days,
            "total_layers": total_layers,
            "image_size_mb": image_size_mb,
        }

    def _merge_metadata(
        self, trivy_meta: Dict[str, Any], image_ref: str
    ) -> Dict[str, Any]:
        """
        Trivy metadata + docker inspect(fallback) 병합.
        항상 _default_metadata() shape 보장.
        """
        result = dict(trivy_meta)

        needs_inspect = any(result.get(k) is None for k in (
            "os", "architecture", "has_healthcheck",
            "created_at", "total_layers", "image_size_mb",
        ))
        if needs_inspect and self.docker_available:
            inspect = self._docker_inspect_metadata(image_ref)
            for k, v in inspect.items():
                if result.get(k) is None and v is not None:
                    result[k] = v

        if result.get("created_at") and result.get("image_age_days") is None:
            try:
                created_dt = datetime.fromisoformat(
                    result["created_at"].replace("Z", "+00:00")
                )
                if created_dt.tzinfo is None:
                    created_dt = created_dt.replace(tzinfo=timezone.utc)
                result["image_age_days"] = (datetime.now(timezone.utc) - created_dt).days
            except Exception:
                pass

        default = _default_metadata()
        for k in default:
            if k not in result:
                result[k] = default[k]

        return result

    def _collect_image_metadata(self, image_ref: str) -> Dict[str, Any]:
        """trivy 사용 불가 시 독립 metadata 수집 (docker inspect 시도)."""
        meta = _default_metadata()
        if self.docker_available:
            inspected = self._docker_inspect_metadata(image_ref)
            meta.update({k: v for k, v in inspected.items() if v is not None})
        return meta

    def _docker_inspect_metadata(self, image_ref: str) -> Dict[str, Any]:
        """docker inspect로 image metadata 추출. 실패 시 빈 dict."""
        result: Dict[str, Any] = {}
        try:
            proc = subprocess.run(
                ["docker", "inspect", "--format", "{{json .}}", image_ref],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                return result

            data = json.loads(proc.stdout.strip())
            if isinstance(data, list):
                data = data[0] if data else {}

            config = data.get("Config", {}) or {}
            root_fs = data.get("RootFS", {}) or {}
            layers = root_fs.get("Layers", [])

            created_at_raw = data.get("Created")
            image_age_days: Optional[int] = None
            if created_at_raw:
                try:
                    created_dt = datetime.fromisoformat(
                        created_at_raw.replace("Z", "+00:00")
                    )
                    if created_dt.tzinfo is None:
                        created_dt = created_dt.replace(tzinfo=timezone.utc)
                    image_age_days = (datetime.now(timezone.utc) - created_dt).days
                except Exception:
                    pass

            size_bytes = data.get("Size")
            image_size_mb: Optional[float] = None
            if size_bytes:
                try:
                    image_size_mb = round(float(size_bytes) / (1024 * 1024), 2)
                except Exception:
                    pass

            result = {
                "os": config.get("Os") or data.get("Os") or None,
                "architecture": data.get("Architecture") or None,
                "has_healthcheck": config.get("Healthcheck") is not None,
                "created_at": created_at_raw,
                "image_age_days": image_age_days,
                "total_layers": len(layers) if layers else None,
                "image_size_mb": image_size_mb,
            }
        except Exception as e:
            print(f"    [-] docker inspect failed for {image_ref}: {e}")
        return result

    # =========================================================================
    # Signature 수집
    # =========================================================================

    def _collect_signature(self, image_ref: str) -> Dict[str, Any]:
        """
        cosign으로 서명 확인.
        항상 3개 키 보장.
        """
        if not self.cosign_available:
            return _default_signature()

        try:
            result = subprocess.run(
                ["cosign", "verify", image_ref,
                 "--certificate-identity-regexp", ".*",
                 "--certificate-oidc-issuer-regexp", ".*"],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0:
                signer: Optional[str] = None
                try:
                    sig_data = json.loads(result.stdout.strip())
                    if isinstance(sig_data, list) and sig_data:
                        cert = sig_data[0].get("optional", {})
                        signer = (
                            cert.get("Subject")
                            or cert.get("Issuer")
                            or "keyless"
                        )
                except Exception:
                    signer = "unknown"
                return {"signed": True, "signer": signer, "signature_type": "cosign"}
            else:
                return _default_signature()

        except subprocess.TimeoutExpired:
            print(f"    [-] cosign verify timed out for {image_ref}")
            return _default_signature()
        except Exception as e:
            print(f"    [-] cosign verify failed for {image_ref}: {e}")
            return _default_signature()

    # =========================================================================
    # EPSS Enrichment
    # =========================================================================

    def _enrich_epss(self, vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """vulnerabilities 리스트에 epss_score / epss_percentile 채움."""
        for vuln in vulnerabilities:
            epss = self._get_epss(vuln.get("cve_id", ""))
            vuln["epss_score"] = epss.get("epss_score")
            vuln["epss_percentile"] = epss.get("epss_percentile")
        return vulnerabilities

    # =========================================================================
    # Vulnerability Summary
    # =========================================================================

    def _build_vulnerability_summary(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        vulnerability_summary 계산.
        severity key: 소문자 canonical (critical, high, medium, low, unknown).
        """
        summary = _default_vulnerability_summary()

        for v in vulnerabilities:
            sev = v.get("severity", "UNKNOWN").upper()
            key = sev.lower() if sev.lower() in summary else "unknown"
            summary[key] += 1
            summary["total"] += 1

            score = v.get("cvss_score")
            if score is not None:
                if summary["max_cvss"] is None or score > summary["max_cvss"]:
                    summary["max_cvss"] = score

            epss = v.get("epss_score")
            if epss is not None:
                if summary["max_epss"] is None or epss > summary["max_epss"]:
                    summary["max_epss"] = epss

            if v.get("fix_available") or v.get("fixed_version"):
                summary["fixable"] += 1

            if v.get("is_known_exploitable"):
                summary["has_known_exploitable_cve"] = True

        return summary

    def _aggregate_severity(self, images: List[Dict[str, Any]]) -> Dict[str, int]:
        """전체 이미지 severity 합계 (complete_scan meta용)."""
        totals: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for img in images:
            vs = img.get("vulnerability_summary", {})
            totals["CRITICAL"] += vs.get("critical", 0)
            totals["HIGH"] += vs.get("high", 0)
            totals["MEDIUM"] += vs.get("medium", 0)
            totals["LOW"] += vs.get("low", 0)
        return totals

    # =========================================================================
    # Payload 생성
    # =========================================================================

    def _build_payload(
        self,
        scan_id: str,
        trigger_mode: str,
        images: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Canonical raw payload.
        내부 _* 필드는 제거하고 downstream contract 키만 남긴다.
        """
        clean_images = [self._clean_image_item(img) for img in images]

        payload: Dict[str, Any] = {
            "scan_id": scan_id,
            "cluster_id": self.config.cluster_id,
            "scanned_at": self.scan_time,
            "scanner_version": (
                f"trivy-{self.trivy_version}" if self.trivy_version else "trivy-unknown"
            ),
            "total_images": len(clean_images),
            "images": clean_images,
            "run_summary": self._generate_run_summary(images),
        }
        return payload

    def _clean_image_item(self, img: Dict[str, Any]) -> Dict[str, Any]:
        """internal _* 키 제거, canonical output shape 강제."""
        return {
            "image_ref": img.get("image_ref", ""),
            "image_digest": img.get("image_digest") or "",
            "registry": img.get("registry", ""),
            "repository": img.get("repository", ""),
            "tag": img.get("tag", ""),
            "signature": img.get("signature") or _default_signature(),
            "metadata": img.get("metadata") or _default_metadata(),
            "scan_status": img.get("scan_status", "unknown"),
            "scan_error": img.get("scan_error"),
            "vulnerability_summary": img.get("vulnerability_summary") or _default_vulnerability_summary(),
            "vulnerabilities": img.get("vulnerabilities", []),
            "used_by_pods": img.get("used_by_pods", []),
        }

    def _generate_run_summary(self, images: List[Dict[str, Any]]) -> Dict[str, Any]:
        """스캔 실행 accounting 요약."""
        status_counts: Dict[str, int] = {}
        for img in images:
            s = img.get("scan_status", "unknown")
            status_counts[s] = status_counts.get(s, 0) + 1

        return {
            "total_images": len(images),
            "completed_images": status_counts.get("completed", 0),
            "skipped_images": status_counts.get("skipped", 0),
            "failed_images": status_counts.get("failed", 0),
            "timeout_images": status_counts.get("timeout", 0),
        }

    # =========================================================================
    # 로컬 저장
    # =========================================================================

    def _save_local_copy(self, payload: Dict[str, Any], scan_id: str) -> str:
        os.makedirs(self.config.output_dir, exist_ok=True)
        filename = self.config.output_filename or f"image_scan_{scan_id}.json"
        filepath = os.path.join(self.config.output_dir, filename)
        save_json(payload, filepath)
        return filepath