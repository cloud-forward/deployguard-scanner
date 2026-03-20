"""
DeployGuard K8s Scanner - Strict Canonical Raw Output Producer

출력 계약(canonical contract):
  {
    "scan_id", "cluster_id", "cluster_type", "scanned_at",
    "namespaces", "pods", "service_accounts", "roles", "cluster_roles",
    "role_bindings", "cluster_role_bindings", "secrets", "services",
    "ingresses", "network_policies", "run_summary"
  }

불변 원칙:
  - scanner는 raw evidence만 수집한다.
  - 해석/판단/랭킹 필드는 canonical payload에 들어가지 않는다.
  - 같은 입력 → 같은 JSON (deterministic ordering)
  - security_context는 항상 full object (null 금지)
  - automount_service_account_token은 최종 boolean semantics
  - env_from_configmaps.env_vars는 실제 key 목록으로 채움
  - env_from_secrets.env_vars는 envFrom 경로에서도 secret key 목록으로 채움
  - used_by_service_accounts는 Pod→SA 역방향 추적으로 채움 (K8s 1.24+ 대응)
    sa.secrets가 비어있어도 Pod의 env/volume Secret 참조를 통해 SA까지 역추적

[FIX v3.2]
  1. used_by_service_accounts 항상 빈 배열 문제
     - K8s 1.24+에서 sa.secrets 자동 생성 중단으로 기존 SA→Secret 직접 링크 소멸
     - _parse_container()에 sa_name 파라미터 추가
     - envFrom / env.valueFrom / volume.secret 경로에서 _track_secret_sa() 호출
     - _parse_volumes()에도 sa_name 전달하여 volume secret → SA 역추적

  2. Service 외부 노출 판정 보완
     - lb_provisioned (bool): LB IP 실제 할당 여부 (pending 구분)
     - has_node_port (bool): NodePort 존재 여부
     - 두 필드 추가로 downstream Analysis Engine의 외부 노출 판단 신호 보강

  3. run_summary payload 포함 및 security_indicators 추가
     - _build_payload()에 run_summary 블록 추가
     - resource_counts: 11개 canonical 배열 각각의 len()
     - security_indicators: privileged/host_pid/host_network/host_ipc/automount 집계
     - downstream이 매번 전체 배열 재순회하지 않아도 되도록 사전 집계 제공
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from kubernetes import client, config as k8s_config

from .config import ScannerConfig
from .api_client import DeployGuardAPIClient
from .utils import generate_scan_id, get_timestamp, save_json
from shared.orchestrator import ScanOrchestrator


# ─────────────────────────────────────────────
# 허용된 cluster_type 값 (문서 정의)
# ─────────────────────────────────────────────
_ALLOWED_CLUSTER_TYPES = {"eks", "self-managed", "unknown"}

# kube-public은 공개 namespace로 분석 불필요 (명세 §16)
_EXCLUDED_NAMESPACES = {"kube-public"}


def _to_iso8601(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.isoformat()


def _calculate_age_days(created_at: Optional[datetime]) -> Optional[int]:
    if created_at is None:
        return None
    now = datetime.now(timezone.utc)
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    return (now - created_at).days


def _normalize_cluster_type(raw: str) -> str:
    """
    cluster_type을 문서 허용 값(eks / self-managed / unknown)으로 제한.

    명세 §3:
      - API Server version에 "eks"가 포함되면 "eks"
      - 아니면 "self-managed"
      - 판별 불가하면 "unknown"

    gke/aks 등 타 관리형 K8s는 self-managed로 매핑한다.
    """
    lower = raw.lower()
    if lower == "eks":
        return "eks"
    if lower == "unknown":
        return "unknown"
    return "self-managed"


def _default_security_context() -> Dict[str, Any]:
    """
    K8s 기본값 기준 full security_context object.
    항상 이 shape를 반환해야 한다 — partial/null 금지.
    """
    return {
        "privileged": False,
        "run_as_user": None,
        "run_as_non_root": False,
        "read_only_root_filesystem": False,
        "allow_privilege_escalation": True,   # K8s 기본값 true
        "capabilities": {
            "add": [],
            "drop": [],
        },
    }


class K8sScanner:
    """
    K8s 리소스 스캐너 — Strict Canonical Raw Output Producer

    출력은 반드시 canonical contract를 준수한다.
    Analysis Engine / Fact Extractor 가 바로 소비할 수 있도록
    field shape, 기본값, linkage, determinism 을 모두 닫는다.
    """

    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig.from_env()
        self.scan_id = generate_scan_id()
        self.scan_time = get_timestamp()
        self._init_k8s_client()

        # ── internal tracking (canonical output과 분리) ──────────────
        # namespace → {secret_name → [pod_names]}
        self._secret_used_by_pods: Dict[str, Dict[str, List[str]]] = {}
        # namespace → {cm_name → [pod_names]}
        self._cm_used_by_pods: Dict[str, Dict[str, List[str]]] = {}
        # namespace → {secret_name → [sa_names]}
        self._secret_used_by_sa: Dict[str, Dict[str, List[str]]] = {}
        # namespace → {cm_name → [key_list]}  (env_from_configmaps 보강용)
        self._cm_key_cache: Dict[str, Dict[str, List[str]]] = {}
        # namespace → {secret_name → [key_list]}  (env_from_secrets envFrom 보강용)
        self._secret_key_cache: Dict[str, Dict[str, List[str]]] = {}
        # namespace → {sa_name → bool}  (Pod effective automount 계산용)
        self._sa_automount_cache: Dict[str, Dict[str, bool]] = {}

    # ══════════════════════════════════════════════════════════════════
    # K8s 클라이언트 초기화
    # ══════════════════════════════════════════════════════════════════

    def _init_k8s_client(self) -> None:
        try:
            k8s_config.load_incluster_config()
            self.config_source = "in-cluster"
        except k8s_config.ConfigException:
            try:
                k8s_config.load_kube_config()
                self.config_source = "kubeconfig"
            except k8s_config.ConfigException as e:
                raise RuntimeError(f"Failed to load K8s config: {e}")

        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.networking_v1 = client.NetworkingV1Api()
        self._detect_cluster_type()

    def _detect_cluster_type(self) -> None:
        """
        명세 §3 cluster_type 판별:
          - git_version에 "eks" 포함 → "eks"
          - 판별 성공했으나 eks 아님 → "self-managed"
          - 예외 발생 → "unknown"
        """
        try:
            git_version = (client.VersionApi().get_code().git_version or "").lower()
            if "eks" in git_version:
                self.cluster_type = "eks"
            else:
                self.cluster_type = "self-managed"
        except Exception:
            self.cluster_type = "unknown"

    def _should_scan_namespace(self, namespace: str) -> bool:
        # 명세 §16: kube-public 제외
        if namespace in _EXCLUDED_NAMESPACES:
            return False
        if namespace == "kube-system":
            return self.config.include_system_namespaces
        if namespace in self.config.exclude_namespaces:
            return False
        if self.config.namespaces and namespace not in self.config.namespaces:
            return False
        return True

    # ══════════════════════════════════════════════════════════════════
    # 공개 실행 메서드
    # ══════════════════════════════════════════════════════════════════

    def run(self) -> Dict[str, Any]:
        return self.run_scheduled_scan()

    def run_manual_scan(self) -> Dict[str, Any]:
        return self._run_scan(trigger_mode="manual")

    def run_scheduled_scan(self) -> Dict[str, Any]:
        return self._run_scan(trigger_mode="scheduled")

    def run_worker_scan(self, scan_id: str, trigger_mode: str = "scheduled") -> Dict[str, Any]:
        api_client = DeployGuardAPIClient(self.config)
        api_client.bind_scan(scan_id, "k8s")
        self.scan_id = scan_id
        return self._execute_scan(api_client=api_client, scan_id=scan_id, trigger_mode=trigger_mode)

    def scan(self) -> Dict[str, Any]:
        """하위 호환용 — canonical payload만 반환."""
        resources = self._collect_all_resources()
        return self._build_payload(scan_id=self.scan_id, resources=resources)

    # ══════════════════════════════════════════════════════════════════
    # 내부 실행 흐름
    # ══════════════════════════════════════════════════════════════════

    def _run_scan(self, trigger_mode: str) -> Dict[str, Any]:
        api_client = DeployGuardAPIClient(self.config)
        orchestrator = ScanOrchestrator(self.config, api_client)
        scan_id = orchestrator.start_scan(scanner_type="k8s", trigger_mode=trigger_mode)
        self.scan_id = scan_id
        return self._execute_scan(api_client=api_client, scan_id=scan_id, trigger_mode=trigger_mode)

    def _execute_scan(
        self,
        api_client: DeployGuardAPIClient,
        scan_id: str,
        trigger_mode: str,
    ) -> Dict[str, Any]:
        orchestrator = ScanOrchestrator(self.config, api_client)
        resources = self._collect_all_resources()
        payload = self._build_payload(scan_id=scan_id, resources=resources)

        local_file = None
        if self.config.save_local_copy:
            local_file = self._save_local_copy(payload, scan_id)

        uploaded_files = [orchestrator.upload_result(payload, self.config.upload_file_name)]

        # complete_scan meta는 canonical payload와 분리된 운영 정보
        resource_counts = {k: len(v) for k, v in resources.items()}
        complete_result = orchestrator.complete_scan(
            meta={
                "scanner_type": "k8s",
                "trigger_mode": trigger_mode,
                "cluster_type": payload["cluster_type"],
                "resource_counts": resource_counts,
            }
        )

        return orchestrator.build_result(
            scan_id=scan_id,
            payload=payload,
            complete_result=complete_result,
            uploaded_files=uploaded_files,
            local_file=local_file,
        )

    # ══════════════════════════════════════════════════════════════════
    # 전체 리소스 수집
    # ══════════════════════════════════════════════════════════════════

    def _collect_all_resources(self) -> Dict[str, List[Any]]:
        """
        수집 순서:
          1. _build_secret_key_cache — secret key cache 선수 구축
          2. configmaps              — cm_key_cache 구축
          3. service_accounts        — sa_automount_cache 구축
          4. pods                    — 위 세 cache 참조 + Secret→SA 역추적
          5. secrets                 — used_by_pods / used_by_service_accounts 최종 반영
          그 외 순서 무관
        """
        print("[*] Collecting K8s resources...")
        resources: Dict[str, List[Any]] = {}

        # Step 0: secret key cache 선수 구축 (pods 수집 전)
        self._build_secret_key_cache()

        # 순서 의존 수집
        for name, collector in [
            ("configmaps",       self._collect_configmaps),
            ("service_accounts", self._collect_service_accounts),
            ("pods",             self._collect_pods),
            ("secrets",          self._collect_secrets),
        ]:
            try:
                items = collector()
                resources[name] = items
                print(f"    ✓ {name}: {len(items)}")
            except Exception as e:
                print(f"    ✗ {name}: ERROR - {e}")
                resources[name] = []

        # 순서 무관 수집
        order_free = [
            ("namespaces",            self._collect_namespaces),
            ("roles",                 self._collect_roles),
            ("cluster_roles",         self._collect_cluster_roles),
            ("role_bindings",         self._collect_role_bindings),
            ("cluster_role_bindings", self._collect_cluster_role_bindings),
            ("services",              self._collect_services),
            ("ingresses",             self._collect_ingresses),
            ("network_policies",      self._collect_network_policies),
        ]
        for name, collector in order_free:
            try:
                items = collector()
                resources[name] = items
                print(f"    ✓ {name}: {len(items)}")
            except Exception as e:
                print(f"    ✗ {name}: ERROR - {e}")
                resources[name] = []

        return resources

    def _build_secret_key_cache(self) -> None:
        """
        Secret key 목록을 사전 수집하여 _secret_key_cache 구축.
        envFrom.secretRef 경로에서 env_from_secrets.env_vars를 실제 key 목록으로 채우기 위해 필요.
        Secret value는 수집하지 않는다 — key 이름만.
        """
        try:
            for secret in self.core_v1.list_secret_for_all_namespaces().items:
                namespace = secret.metadata.namespace
                name = secret.metadata.name
                secret_type = secret.type or "Opaque"
                if secret_type == "kubernetes.io/service-account-token":
                    continue
                keys = sorted((secret.data or {}).keys())
                self._secret_key_cache.setdefault(namespace, {})[name] = keys
        except Exception as e:
            print(f"    ✗ secret_key_cache: ERROR - {e}")

    # ══════════════════════════════════════════════════════════════════
    # Namespace
    # ══════════════════════════════════════════════════════════════════

    def _collect_namespaces(self) -> List[Dict[str, Any]]:
        items = []
        for ns in self.core_v1.list_namespace().items:
            name = ns.metadata.name
            if name in _EXCLUDED_NAMESPACES:
                continue
            items.append({
                "name": name,
                "labels": ns.metadata.labels or {},
                "annotations": ns.metadata.annotations or {},
                "status": ns.status.phase or "Unknown",
            })
        return items

    # ══════════════════════════════════════════════════════════════════
    # ConfigMap (cm_key_cache 구축 — pods 수집 전 반드시 먼저)
    # ══════════════════════════════════════════════════════════════════

    def _collect_configmaps(self) -> List[Dict[str, Any]]:
        """
        역할 두 가지:
          1. cm_key_cache[namespace][name] = sorted([key, ...]) 구축
          2. canonical configmap 목록 반환 (내부 디버그용 — canonical payload에 포함 안 됨)
        """
        items = []
        for cm in self.core_v1.list_config_map_for_all_namespaces().items:
            namespace = cm.metadata.namespace
            name = cm.metadata.name
            keys = sorted((cm.data or {}).keys())

            # 필터 없이 전체 cache 구축 (pod가 어떤 namespace의 cm도 참조할 수 있음)
            self._cm_key_cache.setdefault(namespace, {})[name] = keys

            if not self._should_scan_namespace(namespace):
                continue

            items.append({
                "namespace": namespace,
                "name": name,
                "keys": keys,
            })
        return items

    # ══════════════════════════════════════════════════════════════════
    # Pod
    # ══════════════════════════════════════════════════════════════════

    def _collect_pods(self) -> List[Dict[str, Any]]:
        items = []
        for pod in self.core_v1.list_pod_for_all_namespaces().items:
            namespace = pod.metadata.namespace
            if not self._should_scan_namespace(namespace):
                continue
            phase = pod.status.phase or "Unknown"
            # 명세 §16: 종료된 Pod 제외
            if phase in ("Succeeded", "Failed"):
                continue

            name = pod.metadata.name
            sa_name = pod.spec.service_account_name or "default"

            # volumes map (volume_mounts source 매핑용)
            # [FIX 1] sa_name 전달 → volume secret → SA 역추적 가능
            volumes, volumes_map = self._parse_volumes(pod, namespace, name, sa_name)

            # SA automount effective boolean
            pod_automount = pod.spec.automount_service_account_token
            effective_automount = self._resolve_automount(pod_automount, namespace, sa_name)

            # [FIX 1] sa_name 전달 → env Secret → SA 역추적 가능
            containers = [
                self._parse_container(c, volumes_map, namespace, name, sa_name=sa_name)
                for c in (pod.spec.containers or [])
            ]
            init_containers = [
                self._parse_container(c, volumes_map, namespace, name, is_init=True, sa_name=sa_name)
                for c in (pod.spec.init_containers or [])
            ]

            owner_kind, owner_name = None, None
            for owner in (pod.metadata.owner_references or []):
                if owner.controller:
                    owner_kind, owner_name = owner.kind, owner.name
                    break

            items.append({
                "namespace": namespace,
                "name": name,
                "node_name": pod.spec.node_name,
                "service_account": sa_name,
                "status": phase,
                "age_days": _calculate_age_days(pod.metadata.creation_timestamp),
                "labels": pod.metadata.labels or {},
                "annotations": pod.metadata.annotations or {},
                "host_pid": bool(pod.spec.host_pid),
                "host_network": bool(pod.spec.host_network),
                "host_ipc": bool(pod.spec.host_ipc),
                "automount_service_account_token": effective_automount,
                "owner_kind": owner_kind,
                "owner_name": owner_name,
                "containers": containers,
                "init_containers": init_containers,
                "volumes": volumes,
            })
        return items

    def _resolve_automount(
        self,
        pod_value: Optional[bool],
        namespace: str,
        sa_name: str,
    ) -> bool:
        """
        effective automount_service_account_token:
          1. Pod에 명시돼 있으면 Pod 값 사용
          2. Pod에 없으면 SA automount cache 조회
          3. 둘 다 없으면 true (K8s 기본)
        최종값은 항상 bool — null 금지.
        """
        if pod_value is not None:
            return bool(pod_value)
        sa_val = self._sa_automount_cache.get(namespace, {}).get(sa_name)
        if sa_val is not None:
            return sa_val
        return True

    def _parse_volumes(
        self,
        pod,
        namespace: str,
        pod_name: str,
        sa_name: str = "default",  # [FIX 1] SA 역추적을 위해 추가
    ) -> Tuple[List[Dict[str, Any]], Dict[str, Dict[str, Any]]]:
        volumes = []
        volumes_map: Dict[str, Dict[str, Any]] = {}

        for v in (pod.spec.volumes or []):
            info: Dict[str, Any] = {
                "name": v.name,
                "type": "other",
                "secret_name": None,
                "configmap_name": None,
                "host_path": None,
            }

            if v.secret:
                info["type"] = "secret"
                info["secret_name"] = v.secret.secret_name
                self._track_secret_pod(namespace, v.secret.secret_name, pod_name)
                # [FIX 1] volume으로 마운트된 Secret도 SA와 연결
                self._track_secret_sa(namespace, v.secret.secret_name, sa_name)
            elif v.config_map:
                info["type"] = "configmap"
                info["configmap_name"] = v.config_map.name
                self._track_cm_pod(namespace, v.config_map.name, pod_name)
            elif v.host_path:
                info["type"] = "hostpath"
                info["host_path"] = v.host_path.path
            elif v.persistent_volume_claim:
                info["type"] = "persistentVolumeClaim"
            elif v.empty_dir is not None:
                info["type"] = "emptyDir"
            elif v.projected:
                info["type"] = "projected"

            volumes.append(info)
            volumes_map[v.name] = info

        return volumes, volumes_map

    def _parse_container(
        self,
        container,
        volumes_map: Dict[str, Dict[str, Any]],
        namespace: str,
        pod_name: str,
        is_init: bool = False,
        sa_name: str = "default",  # [FIX 1] SA 역추적을 위해 추가
    ) -> Dict[str, Any]:
        sc = container.security_context
        security_context = _default_security_context()

        if sc:
            if sc.privileged is not None:
                security_context["privileged"] = bool(sc.privileged)
            if sc.run_as_user is not None:
                security_context["run_as_user"] = sc.run_as_user
            if sc.run_as_non_root is not None:
                security_context["run_as_non_root"] = bool(sc.run_as_non_root)
            if sc.read_only_root_filesystem is not None:
                security_context["read_only_root_filesystem"] = bool(sc.read_only_root_filesystem)
            if sc.allow_privilege_escalation is not None:
                security_context["allow_privilege_escalation"] = bool(sc.allow_privilege_escalation)
            if sc.capabilities:
                security_context["capabilities"] = {
                    "add": sorted(sc.capabilities.add or []),
                    "drop": sorted(sc.capabilities.drop or []),
                }

        # volume_mounts
        volume_mounts = []
        for vm in (container.volume_mounts or []):
            vol = volumes_map.get(vm.name, {})
            volume_mounts.append({
                "name": vm.name,
                "mount_path": vm.mount_path,
                "read_only": bool(vm.read_only) if vm.read_only is not None else False,
                "source_type": vol.get("type"),
                "source_name": (
                    vol.get("secret_name")
                    or vol.get("configmap_name")
                    or vol.get("host_path")
                ),
            })

        # env_from_secrets / env_from_configmaps
        env_from_secrets: Dict[str, List[str]] = {}
        env_from_configmaps: Dict[str, List[str]] = {}

        # envFrom (bulk ref)
        for ef in (container.env_from or []):
            if ef.secret_ref and ef.secret_ref.name:
                sname = ef.secret_ref.name
                keys = self._secret_key_cache.get(namespace, {}).get(sname, [])
                if sname not in env_from_secrets:
                    env_from_secrets[sname] = []
                existing = set(env_from_secrets[sname])
                for k in keys:
                    if k not in existing:
                        env_from_secrets[sname].append(k)
                        existing.add(k)
                self._track_secret_pod(namespace, sname, pod_name)
                # [FIX 1] envFrom Secret → SA 역추적
                self._track_secret_sa(namespace, sname, sa_name)

            if ef.config_map_ref and ef.config_map_ref.name:
                cmname = ef.config_map_ref.name
                keys = self._cm_key_cache.get(namespace, {}).get(cmname, [])
                if cmname not in env_from_configmaps:
                    env_from_configmaps[cmname] = []
                existing = set(env_from_configmaps[cmname])
                for k in keys:
                    if k not in existing:
                        env_from_configmaps[cmname].append(k)
                        existing.add(k)
                self._track_cm_pod(namespace, cmname, pod_name)

        # env individual valueFrom
        for env in (container.env or []):
            if not env.value_from:
                continue
            if env.value_from.secret_key_ref and env.value_from.secret_key_ref.name:
                sname = env.value_from.secret_key_ref.name
                if sname not in env_from_secrets:
                    env_from_secrets[sname] = []
                if env.name not in env_from_secrets[sname]:
                    env_from_secrets[sname].append(env.name)
                self._track_secret_pod(namespace, sname, pod_name)
                # [FIX 1] 개별 env.valueFrom Secret → SA 역추적
                self._track_secret_sa(namespace, sname, sa_name)

            if env.value_from.config_map_key_ref and env.value_from.config_map_key_ref.name:
                cmname = env.value_from.config_map_key_ref.name
                if cmname not in env_from_configmaps:
                    env_from_configmaps[cmname] = []
                if env.name not in env_from_configmaps[cmname]:
                    env_from_configmaps[cmname].append(env.name)
                self._track_cm_pod(namespace, cmname, pod_name)

        # serialise as sorted lists (determinism)
        efs_list = [
            {"secret_name": k, "env_vars": sorted(v)}
            for k, v in sorted(env_from_secrets.items())
        ]
        efc_list = [
            {"configmap_name": k, "env_vars": sorted(v)}
            for k, v in sorted(env_from_configmaps.items())
        ]

        ports = []
        for p in (container.ports or []):
            ports.append({
                "container_port": p.container_port,
                "protocol": p.protocol or "TCP",
                "name": p.name,
                "host_port": p.host_port,
            })

        resources: Dict[str, Any] = {}
        if container.resources:
            resources = {
                "requests": dict(container.resources.requests or {}),
                "limits": dict(container.resources.limits or {}),
            }

        return {
            "name": container.name,
            "image": container.image or "",
            "image_pull_policy": container.image_pull_policy,
            "is_init_container": is_init,
            "security_context": security_context,
            "volume_mounts": volume_mounts,
            "env_from_secrets": efs_list,
            "env_from_configmaps": efc_list,
            "ports": ports,
            "resources": resources,
            "command": container.command,
            "args": container.args,
        }

    # ══════════════════════════════════════════════════════════════════
    # ServiceAccount
    # ══════════════════════════════════════════════════════════════════

    def _collect_service_accounts(self) -> List[Dict[str, Any]]:
        items = []
        for sa in self.core_v1.list_service_account_for_all_namespaces().items:
            namespace = sa.metadata.namespace
            if not self._should_scan_namespace(namespace):
                continue

            name = sa.metadata.name
            labels = sa.metadata.labels or {}
            annotations = sa.metadata.annotations or {}

            irsa_role_arn: Optional[str] = annotations.get("eks.amazonaws.com/role-arn") or None

            # sa.secrets + image_pull_secrets → Secret 역매핑 구축
            # K8s 1.24+ 환경에서는 sa.secrets가 비어 있는 것이 정상이다.
            # 실제 Secret 사용 연결은 Pod 수집 시 _parse_container/_parse_volumes에서
            # _track_secret_sa()를 통해 역방향으로 채워진다.
            sa_secrets: List[str] = sorted([s.name for s in (sa.secrets or []) if s.name])
            ips_secrets: List[str] = sorted([
                s.name for s in (sa.image_pull_secrets or []) if s.name
            ])
            all_secrets = sorted(set(sa_secrets + ips_secrets))
            for sname in all_secrets:
                self._track_secret_sa(namespace, sname, name)

            raw_automount = sa.automount_service_account_token
            automount = bool(raw_automount) if raw_automount is not None else True
            self._sa_automount_cache.setdefault(namespace, {})[name] = automount

            items.append({
                "namespace": namespace,
                "name": name,
                "labels": labels,
                "annotations": annotations,
                "automount_service_account_token": automount,
                "secrets": sa_secrets,
                "image_pull_secrets": ips_secrets,
                "irsa_role_arn": irsa_role_arn,
            })
        return items

    # ══════════════════════════════════════════════════════════════════
    # Secret
    # ══════════════════════════════════════════════════════════════════

    def _collect_secrets(self) -> List[Dict[str, Any]]:
        """
        canonical shape:
          namespace, name, type, labels, annotations, keys,
          used_by_pods (sorted), used_by_service_accounts (sorted)

        value는 절대 수집 금지.
        해석 플래그(has_sensitive_keys, is_unused, is_tls ...) 없음.

        [FIX 1] used_by_service_accounts는 이 시점에 _secret_used_by_sa에
        Pod 수집(_parse_container/_parse_volumes)에서 역추적된 SA 목록이
        채워져 있으므로 K8s 1.24+ 환경에서도 올바르게 반영된다.
        """
        items = []
        for secret in self.core_v1.list_secret_for_all_namespaces().items:
            namespace = secret.metadata.namespace
            if not self._should_scan_namespace(namespace):
                continue

            secret_type = secret.type or "Opaque"
            if secret_type == "kubernetes.io/service-account-token":
                continue

            name = secret.metadata.name
            keys = sorted((secret.data or {}).keys())

            used_by_pods = sorted(
                self._secret_used_by_pods.get(namespace, {}).get(name, [])
            )
            used_by_service_accounts = sorted(
                self._secret_used_by_sa.get(namespace, {}).get(name, [])
            )

            items.append({
                "namespace": namespace,
                "name": name,
                "type": secret_type,
                "labels": secret.metadata.labels or {},
                "annotations": secret.metadata.annotations or {},
                "keys": keys,
                "used_by_pods": used_by_pods,
                "used_by_service_accounts": used_by_service_accounts,
            })
        return items

    # ══════════════════════════════════════════════════════════════════
    # Role / ClusterRole
    # ══════════════════════════════════════════════════════════════════

    def _collect_roles(self) -> List[Dict[str, Any]]:
        items = []
        for role in self.rbac_v1.list_role_for_all_namespaces().items:
            if not self._should_scan_namespace(role.metadata.namespace):
                continue
            items.append(self._parse_role(role, role.metadata.namespace))
        return items

    def _collect_cluster_roles(self) -> List[Dict[str, Any]]:
        items = []
        for cr in self.rbac_v1.list_cluster_role().items:
            name = cr.metadata.name
            if name.startswith("system:") and not self.config.include_system_namespaces:
                continue
            items.append(self._parse_role(cr, namespace=None))
        return items

    def _parse_role(self, role, namespace: Optional[str]) -> Dict[str, Any]:
        rules = []
        for r in (role.rules or []):
            rules.append({
                "api_groups": sorted(r.api_groups or []),
                "resources": sorted(r.resources or []),
                "resource_names": sorted(r.resource_names or []),
                "verbs": sorted(r.verbs or []),
            })

        result: Dict[str, Any] = {
            "name": role.metadata.name,
            "labels": role.metadata.labels or {},
            "rules": rules,
        }
        if namespace is not None:
            result["namespace"] = namespace
        return result

    # ══════════════════════════════════════════════════════════════════
    # RoleBinding / ClusterRoleBinding
    # ══════════════════════════════════════════════════════════════════

    def _collect_role_bindings(self) -> List[Dict[str, Any]]:
        items = []
        for rb in self.rbac_v1.list_role_binding_for_all_namespaces().items:
            if not self._should_scan_namespace(rb.metadata.namespace):
                continue
            items.append(self._parse_binding(rb, rb.metadata.namespace))
        return items

    def _collect_cluster_role_bindings(self) -> List[Dict[str, Any]]:
        items = []
        for crb in self.rbac_v1.list_cluster_role_binding().items:
            name = crb.metadata.name
            if name.startswith("system:") and not self.config.include_system_namespaces:
                continue
            items.append(self._parse_binding(crb, namespace=None))
        return items

    def _parse_binding(self, binding, namespace: Optional[str]) -> Dict[str, Any]:
        subjects = []
        for s in (binding.subjects or []):
            subjects.append({
                "kind": s.kind,
                "name": s.name,
                "namespace": getattr(s, "namespace", None),
            })

        result: Dict[str, Any] = {
            "name": binding.metadata.name,
            "labels": binding.metadata.labels or {},
            "subjects": subjects,
            "role_ref": {
                "kind": binding.role_ref.kind,
                "name": binding.role_ref.name,
            },
        }
        if namespace is not None:
            result["namespace"] = namespace
        return result

    # ══════════════════════════════════════════════════════════════════
    # Service
    # ══════════════════════════════════════════════════════════════════

    def _collect_services(self) -> List[Dict[str, Any]]:
        """
        port shape:
          - 숫자 target_port  → target_port=int,  target_port_name=null
          - 문자열 target_port → target_port=null, target_port_name=string
        판단 필드(is_external, is_loadbalancer 등) 없음.

        [FIX 2] 외부 노출 판정 보조 필드 추가:
          lb_provisioned (bool): LB ingress가 실제 할당됐는지 여부
            - True  → LB IP/hostname 할당 완료
            - False → LoadBalancer 타입이지만 아직 pending이거나 다른 타입
          has_node_port (bool): NodePort가 하나라도 존재하는지 여부
            - True  → 노드 IP:NodePort로 외부 접근 가능 경로 존재
          두 필드 모두 raw 사실만 기록 — 판단은 Analysis Engine이 수행한다.
        """
        items = []
        for svc in self.core_v1.list_service_for_all_namespaces().items:
            namespace = svc.metadata.namespace
            if not self._should_scan_namespace(namespace):
                continue

            lb_ingress = []
            if svc.status.load_balancer and svc.status.load_balancer.ingress:
                for ing in svc.status.load_balancer.ingress:
                    lb_ingress.append({"ip": ing.ip, "hostname": ing.hostname})

            ports = []
            for p in (svc.spec.ports or []):
                raw_tp = p.target_port
                if raw_tp is None:
                    target_port_int = None
                    target_port_name = None
                elif isinstance(raw_tp, int):
                    target_port_int = raw_tp
                    target_port_name = None
                elif isinstance(raw_tp, str) and raw_tp.isdigit():
                    target_port_int = int(raw_tp)
                    target_port_name = None
                else:
                    target_port_int = None
                    target_port_name = str(raw_tp) if raw_tp else None

                ports.append({
                    "name": p.name,
                    "protocol": p.protocol or "TCP",
                    "port": p.port,
                    "target_port": target_port_int,
                    "target_port_name": target_port_name,
                    "node_port": p.node_port,
                })

            raw_external_ips: List[str] = sorted(svc.spec.external_i_ps or [])

            # [FIX 2] 외부 노출 판정 보조 필드
            lb_provisioned: bool = bool(lb_ingress)
            has_node_port: bool = any(p["node_port"] is not None for p in ports)

            items.append({
                "namespace": namespace,
                "name": svc.metadata.name,
                "labels": svc.metadata.labels or {},
                "annotations": svc.metadata.annotations or {},
                "type": svc.spec.type,
                "cluster_ip": svc.spec.cluster_ip,
                "external_ip": raw_external_ips[0] if raw_external_ips else None,
                "external_ips": raw_external_ips,
                "load_balancer_ip": svc.spec.load_balancer_ip,
                "load_balancer_ingress": lb_ingress,
                # [FIX 2] 추가 필드
                "lb_provisioned": lb_provisioned,
                "has_node_port": has_node_port,
                "selector": svc.spec.selector or {},
                "ports": ports,
            })
        return items

    # ══════════════════════════════════════════════════════════════════
    # Ingress
    # ══════════════════════════════════════════════════════════════════

    def _collect_ingresses(self) -> List[Dict[str, Any]]:
        """
        raw only — is_internet_facing 등 판단 필드 없음.
        Entry point 여부는 Analysis Engine이 결정한다.
        """
        items = []
        for ing in self.networking_v1.list_ingress_for_all_namespaces().items:
            namespace = ing.metadata.namespace
            if not self._should_scan_namespace(namespace):
                continue

            rules = []
            for rule in (ing.spec.rules or []):
                paths = []
                if rule.http:
                    for path in (rule.http.paths or []):
                        backend_service = None
                        backend_port = None
                        if path.backend and path.backend.service:
                            backend_service = path.backend.service.name
                            if path.backend.service.port:
                                backend_port = (
                                    path.backend.service.port.number
                                    or path.backend.service.port.name
                                )
                        paths.append({
                            "path": path.path,
                            "path_type": path.path_type,
                            "backend_service": backend_service,
                            "backend_port": backend_port,
                        })
                rules.append({"host": rule.host, "paths": paths})

            tls = []
            for t in (ing.spec.tls or []):
                tls.append({
                    "hosts": sorted(t.hosts or []),
                    "secret_name": t.secret_name,
                })

            items.append({
                "namespace": namespace,
                "name": ing.metadata.name,
                "labels": ing.metadata.labels or {},
                "annotations": ing.metadata.annotations or {},
                "ingress_class": ing.spec.ingress_class_name,
                "rules": rules,
                "tls": tls,
            })
        return items

    # ══════════════════════════════════════════════════════════════════
    # NetworkPolicy
    # ══════════════════════════════════════════════════════════════════

    def _collect_network_policies(self) -> List[Dict[str, Any]]:
        items = []
        for np in self.networking_v1.list_network_policy_for_all_namespaces().items:
            namespace = np.metadata.namespace
            if not self._should_scan_namespace(namespace):
                continue

            ingress_rules = []
            for r in (np.spec.ingress or []):
                d = r.to_dict() if hasattr(r, "to_dict") else {}
                ingress_rules.append(d)

            egress_rules = []
            for r in (np.spec.egress or []):
                d = r.to_dict() if hasattr(r, "to_dict") else {}
                egress_rules.append(d)

            items.append({
                "namespace": namespace,
                "name": np.metadata.name,
                "labels": np.metadata.labels or {},
                "pod_selector": (
                    np.spec.pod_selector.match_labels
                    if np.spec.pod_selector else {}
                ) or {},
                "policy_types": sorted(np.spec.policy_types or []),
                "ingress_rules": ingress_rules,
                "egress_rules": egress_rules,
            })
        return items

    # ══════════════════════════════════════════════════════════════════
    # Canonical Payload 생성
    # ══════════════════════════════════════════════════════════════════

    def _build_payload(
        self,
        scan_id: str,
        resources: Dict[str, List[Any]],
    ) -> Dict[str, Any]:
        """
        Strict canonical payload.

        [FIX 3] run_summary 블록 추가:
          - resource_counts: 11개 canonical 배열 각각의 len()
          - security_indicators: Pod 레벨 보안 설정 집계값
          downstream이 이 값에 의존해 배열 재순회를 줄일 수 있다.
          단, 이 값은 참고용이며 canonical 배열이 항상 source of truth다.
        """
        return {
            "scan_id": scan_id,
            "cluster_id": self.config.cluster_id,
            "cluster_type": _normalize_cluster_type(self.cluster_type),
            "scanned_at": self.scan_time,
            # ── 11개 canonical 배열 ──────────────────────────────
            "namespaces":            resources.get("namespaces", []),
            "pods":                  resources.get("pods", []),
            "service_accounts":      resources.get("service_accounts", []),
            "roles":                 resources.get("roles", []),
            "cluster_roles":         resources.get("cluster_roles", []),
            "role_bindings":         resources.get("role_bindings", []),
            "cluster_role_bindings": resources.get("cluster_role_bindings", []),
            "secrets":               resources.get("secrets", []),
            "services":              resources.get("services", []),
            "ingresses":             resources.get("ingresses", []),
            "network_policies":      resources.get("network_policies", []),
            # [FIX 3] run_summary 추가
            "run_summary": self._generate_run_summary(resources),
        }

    def _generate_run_summary(self, resources: Dict[str, List[Any]]) -> Dict[str, Any]:
        """
        [FIX 3] 스캔 결과 요약 집계.

        resource_counts:
          canonical 11개 배열 각각의 항목 수.

        security_indicators:
          Pod / Container 레벨 보안 설정의 집계값.
          판단(risk score, severity)은 포함하지 않는다 — raw count만.

          - privileged_containers     : privileged=true 컨테이너 수
          - host_pid_pods             : hostPID=true Pod 수
          - host_network_pods         : hostNetwork=true Pod 수
          - host_ipc_pods             : hostIPC=true Pod 수
          - automount_enabled_pods    : automountServiceAccountToken=true Pod 수
          - allow_privilege_esc_containers : allowPrivilegeEscalation=true 컨테이너 수
          - no_read_only_root_pods    : 모든 컨테이너가 readOnlyRootFilesystem=false인 Pod 수
          - run_as_root_containers    : runAsUser=0 또는 runAsNonRoot=false 컨테이너 수
        """
        _CANONICAL_ARRAYS = [
            "namespaces", "pods", "service_accounts", "roles", "cluster_roles",
            "role_bindings", "cluster_role_bindings", "secrets",
            "services", "ingresses", "network_policies",
        ]
        resource_counts = {k: len(resources.get(k, [])) for k in _CANONICAL_ARRAYS}

        pods = resources.get("pods", [])

        privileged_containers = 0
        host_pid_pods = 0
        host_network_pods = 0
        host_ipc_pods = 0
        automount_enabled_pods = 0
        allow_privilege_esc_containers = 0
        no_read_only_root_pods = 0
        run_as_root_containers = 0

        for pod in pods:
            if pod.get("host_pid"):
                host_pid_pods += 1
            if pod.get("host_network"):
                host_network_pods += 1
            if pod.get("host_ipc"):
                host_ipc_pods += 1
            if pod.get("automount_service_account_token"):
                automount_enabled_pods += 1

            all_containers = pod.get("containers", []) + pod.get("init_containers", [])
            pod_has_writable_root = False

            for c in all_containers:
                sc = c.get("security_context", {})
                if sc.get("privileged"):
                    privileged_containers += 1
                if sc.get("allow_privilege_escalation"):
                    allow_privilege_esc_containers += 1
                if not sc.get("read_only_root_filesystem"):
                    pod_has_writable_root = True
                # runAsUser=0 이거나 runAsNonRoot=false (K8s 기본)이면 root 실행 가능
                run_as_user = sc.get("run_as_user")
                run_as_non_root = sc.get("run_as_non_root", False)
                if run_as_user == 0 or not run_as_non_root:
                    run_as_root_containers += 1

            if pod_has_writable_root:
                no_read_only_root_pods += 1

        return {
            "resource_counts": resource_counts,
            "security_indicators": {
                "privileged_containers": privileged_containers,
                "host_pid_pods": host_pid_pods,
                "host_network_pods": host_network_pods,
                "host_ipc_pods": host_ipc_pods,
                "automount_enabled_pods": automount_enabled_pods,
                "allow_privilege_esc_containers": allow_privilege_esc_containers,
                "no_read_only_root_pods": no_read_only_root_pods,
                "run_as_root_containers": run_as_root_containers,
            },
        }

    # ══════════════════════════════════════════════════════════════════
    # Internal Tracking Helpers
    # ══════════════════════════════════════════════════════════════════

    def _track_secret_pod(self, namespace: str, secret_name: str, pod_name: str) -> None:
        ns = self._secret_used_by_pods.setdefault(namespace, {})
        pod_list = ns.setdefault(secret_name, [])
        if pod_name not in pod_list:
            pod_list.append(pod_name)

    def _track_cm_pod(self, namespace: str, cm_name: str, pod_name: str) -> None:
        ns = self._cm_used_by_pods.setdefault(namespace, {})
        pod_list = ns.setdefault(cm_name, [])
        if pod_name not in pod_list:
            pod_list.append(pod_name)

    def _track_secret_sa(self, namespace: str, secret_name: str, sa_name: str) -> None:
        ns = self._secret_used_by_sa.setdefault(namespace, {})
        sa_list = ns.setdefault(secret_name, [])
        if sa_name not in sa_list:
            sa_list.append(sa_name)

    def _save_local_copy(self, payload: Dict[str, Any], scan_id: str) -> str:
        os.makedirs(self.config.output_dir, exist_ok=True)
        filename = self.config.output_filename or f"k8s_scan_{scan_id}.json"
        filepath = os.path.join(self.config.output_dir, filename)
        save_json(payload, filepath)
        return filepath