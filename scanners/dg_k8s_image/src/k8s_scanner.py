"""
DeployGuard K8s Scanner - Fact Extractor 완벽 호환 버전

Fact Extractor가 기대하는 모든 필드를 수집합니다:
- K8sExtractor: pods, namespaces, nodes
- RBACExtractor: roles, cluster_roles, role_bindings, cluster_role_bindings, service_accounts
- NetworkExtractor: services, ingresses, network_policies
- StorageExtractor: secrets, configmaps, persistent_volumes, persistent_volume_claims
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

from kubernetes import client, config as k8s_config

from .config import ScannerConfig
from .api_client import DeployGuardAPIClient
from .utils import generate_scan_id, get_timestamp, save_json
from shared.orchestrator import ScanOrchestrator


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


# 위험한 Capabilities 목록 (K8sExtractor와 동일)
DANGEROUS_CAPABILITIES = {
    'SYS_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'DAC_READ_SEARCH',
    'DAC_OVERRIDE', 'NET_ADMIN', 'NET_RAW', 'SYS_RAWIO',
    'SETUID', 'SETGID', 'CHOWN', 'FOWNER', 'MKNOD',
}

# 위험한 호스트 경로 (StorageExtractor와 동일)
DANGEROUS_HOST_PATHS = {
    '/', '/etc', '/var', '/var/run', '/var/run/docker.sock',
    '/var/run/containerd/containerd.sock', '/var/run/crio/crio.sock',
    '/proc', '/sys', '/root', '/home',
}

# 민감한 데이터 키 패턴 (StorageExtractor와 동일)
SENSITIVE_KEY_PATTERNS = [
    r'password', r'passwd', r'secret', r'token', r'key',
    r'api[_-]?key', r'auth', r'credential', r'private',
    r'aws[_-]', r'azure[_-]', r'gcp[_-]', r'db[_-]',
]


class K8sScanner:
    """
    K8s 리소스 스캐너 - Fact Extractor 완벽 호환
    """

    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig.from_env()
        self.scan_id = generate_scan_id()
        self.scan_time = get_timestamp()
        self._init_k8s_client()
        
        # Secret/ConfigMap 사용 추적
        self._secret_usage: Dict[str, Dict[str, List[str]]] = {}  # {ns: {secret_name: [pod_names]}}
        self._configmap_usage: Dict[str, Dict[str, List[str]]] = {}
        self._sa_secret_usage: Dict[str, Dict[str, List[str]]] = {}  # SA가 사용하는 Secret

    def _init_k8s_client(self) -> None:
        """K8s 클라이언트 초기화"""
        try:
            k8s_config.load_incluster_config()
            self.config_source = "in-cluster"
            print("[+] Loaded in-cluster config")
        except k8s_config.ConfigException:
            try:
                k8s_config.load_kube_config()
                self.config_source = "kubeconfig"
                print("[+] Loaded kubeconfig")
            except k8s_config.ConfigException as e:
                raise RuntimeError(f"Failed to load K8s config: {e}")

        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.networking_v1 = client.NetworkingV1Api()
        
        # 클러스터 타입 감지
        self._detect_cluster_type()

    def _detect_cluster_type(self) -> None:
        """EKS vs self-managed 감지"""
        try:
            version_info = client.VersionApi().get_code()
            git_version = version_info.git_version or ""
            
            if "eks" in git_version.lower():
                self.cluster_type = "eks"
            elif "gke" in git_version.lower():
                self.cluster_type = "gke"
            elif "aks" in git_version.lower():
                self.cluster_type = "aks"
            else:
                self.cluster_type = "self-managed"
                
            print(f"[+] Detected cluster type: {self.cluster_type}")
        except Exception:
            self.cluster_type = "unknown"

    def _should_scan_namespace(self, namespace: str) -> bool:
        """네임스페이스 필터링"""
        # kube-system은 include_system_namespaces 설정에 따라
        if namespace == "kube-system":
            return self.config.include_system_namespaces
        
        if namespace in self.config.exclude_namespaces:
            return False
            
        if self.config.namespaces and namespace not in self.config.namespaces:
            return False
            
        return True

    # =========================================================================
    # 메인 실행 메서드
    # =========================================================================

    def run(self) -> Dict[str, Any]:
        """기본 실행 (scheduled 모드)"""
        return self.run_scheduled_scan()

    def run_manual_scan(self) -> Dict[str, Any]:
        """수동 스캔"""
        return self._run_scan(trigger_mode="manual")

    def run_scheduled_scan(self) -> Dict[str, Any]:
        """정기 스캔"""
        return self._run_scan(trigger_mode="scheduled")

    def run_worker_scan(self, scan_id: str, trigger_mode: str = "scheduled") -> Dict[str, Any]:
        api_client = DeployGuardAPIClient(self.config)
        api_client.bind_scan(scan_id, "k8s")
        self.scan_id = scan_id
        return self._execute_scan(api_client=api_client, scan_id=scan_id, trigger_mode=trigger_mode)

    def _run_scan(self, trigger_mode: str) -> Dict[str, Any]:
        """실제 스캔 실행"""
        print(f"\n{'='*60}")
        print(f"DeployGuard K8s Scanner v3.0.0")
        print(f"Cluster: {self.config.cluster_id}")
        print(f"Cluster Type: {self.cluster_type}")
        print(f"Mode: {trigger_mode}")
        print(f"{'='*60}\n")

        api_client = DeployGuardAPIClient(self.config)
        orchestrator = ScanOrchestrator(self.config, api_client)
        scan_id = orchestrator.start_scan(
            scanner_type="k8s",
            trigger_mode=trigger_mode,
        )
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

        payload = self._build_payload(
            scan_id=scan_id,
            trigger_mode=trigger_mode,
            resources=resources,
        )

        local_file = None
        if self.config.save_local_copy:
            local_file = self._save_local_copy(payload, scan_id)

        uploaded_files = [orchestrator.upload_result(payload, self.config.upload_file_name)]

        summary = payload.get("summary", {})
        complete_result = orchestrator.complete_scan(
            meta={
                "scanner_type": "k8s",
                "trigger_mode": trigger_mode,
                "cluster_type": self.cluster_type,
                "resource_counts": summary.get("by_type", {}),
                "security_indicators": summary.get("security_indicators", {}),
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
        """하위 호환용 - 리소스만 수집"""
        resources = self._collect_all_resources()
        return self._build_payload(
            scan_id=self.scan_id,
            trigger_mode="manual",
            resources=resources,
        )

    # =========================================================================
    # 리소스 수집
    # =========================================================================

    def _collect_all_resources(self) -> Dict[str, Any]:
        """모든 K8s 리소스 수집"""
        print("[*] Collecting K8s resources...")

        # 순서 중요: Pod를 먼저 수집해서 Secret/ConfigMap 사용 추적
        resources = {}

        collectors = [
            ("namespaces", self._collect_namespaces),
            ("nodes", self._collect_nodes),
            ("pods", self._collect_pods),  # Secret/ConfigMap 사용 추적
            ("services", self._collect_services),
            ("deployments", self._collect_deployments),
            ("daemonsets", self._collect_daemonsets),
            ("statefulsets", self._collect_statefulsets),
            ("replicasets", self._collect_replicasets),
            ("jobs", self._collect_jobs),
            ("cronjobs", self._collect_cronjobs),
            ("service_accounts", self._collect_service_accounts),
            ("secrets", self._collect_secrets),  # 사용 정보 포함
            ("configmaps", self._collect_configmaps),  # 사용 정보 포함
            ("persistent_volumes", self._collect_persistent_volumes),
            ("persistent_volume_claims", self._collect_persistent_volume_claims),
            ("roles", self._collect_roles),
            ("cluster_roles", self._collect_cluster_roles),
            ("role_bindings", self._collect_role_bindings),
            ("cluster_role_bindings", self._collect_cluster_role_bindings),
            ("network_policies", self._collect_network_policies),
            ("ingresses", self._collect_ingresses),
        ]

        for name, collector in collectors:
            try:
                items = collector()
                resources[name] = items
                print(f"    ✓ {name}: {len(items)}")
            except Exception as e:
                print(f"    ✗ {name}: ERROR - {e}")
                resources[name] = []

        return resources

    # =========================================================================
    # Namespace 수집
    # =========================================================================

    def _collect_namespaces(self) -> List[Dict[str, Any]]:
        """Namespace 정보 수집 (K8sExtractor.extract_namespace_facts 호환)"""
        items = []
        
        # NetworkPolicy 존재 여부 확인용
        np_namespaces: Set[str] = set()
        try:
            for np in self.networking_v1.list_network_policy_for_all_namespaces().items:
                np_namespaces.add(np.metadata.namespace)
        except Exception:
            pass

        for ns in self.core_v1.list_namespace().items:
            name = ns.metadata.name
            labels = ns.metadata.labels or {}
            annotations = ns.metadata.annotations or {}
            
            # PSS (Pod Security Standards) 레벨 확인
            pss_enforce = labels.get("pod-security.kubernetes.io/enforce")
            
            items.append({
                "name": name,
                "labels": labels,
                "annotations": annotations,
                "status": ns.status.phase,
                "created_at": _to_iso8601(ns.metadata.creation_timestamp),
                # Fact Extractor용 필드
                "pss_enforce": pss_enforce,  # privileged, baseline, restricted
                "has_network_policy": name in np_namespaces,
                "is_default": name == "default",
                "is_kube_system": name == "kube-system",
            })
        
        return items

    # =========================================================================
    # Node 수집
    # =========================================================================

    def _collect_nodes(self) -> List[Dict[str, Any]]:
        """Node 정보 수집"""
        items = []
        
        for node in self.core_v1.list_node().items:
            name = node.metadata.name
            labels = node.metadata.labels or {}
            annotations = node.metadata.annotations or {}
            
            # 주소 정보
            addresses = {}
            for addr in (node.status.addresses or []):
                addresses[addr.type] = addr.address
            
            # 상태 정보
            conditions = {}
            is_ready = False
            for cond in (node.status.conditions or []):
                conditions[cond.type] = cond.status
                if cond.type == "Ready" and cond.status == "True":
                    is_ready = True
            
            # provider_id에서 EC2 instance ID 추출 (EKS)
            provider_id = node.spec.provider_id or ""
            ec2_instance_id = None
            if provider_id.startswith("aws://"):
                # aws:///ap-northeast-2a/i-0123456789abcdef0
                parts = provider_id.split("/")
                if len(parts) >= 2:
                    ec2_instance_id = parts[-1]
            
            items.append({
                "name": name,
                "labels": labels,
                "annotations": annotations,
                "created_at": _to_iso8601(node.metadata.creation_timestamp),
                "addresses": addresses,
                "internal_ip": addresses.get("InternalIP"),
                "external_ip": addresses.get("ExternalIP"),
                "hostname": addresses.get("Hostname"),
                "conditions": conditions,
                "is_ready": is_ready,
                "allocatable": dict(node.status.allocatable or {}),
                "capacity": dict(node.status.capacity or {}),
                "node_info": {
                    "architecture": node.status.node_info.architecture if node.status.node_info else None,
                    "container_runtime_version": node.status.node_info.container_runtime_version if node.status.node_info else None,
                    "kernel_version": node.status.node_info.kernel_version if node.status.node_info else None,
                    "kubelet_version": node.status.node_info.kubelet_version if node.status.node_info else None,
                    "os_image": node.status.node_info.os_image if node.status.node_info else None,
                    "operating_system": node.status.node_info.operating_system if node.status.node_info else None,
                },
                "taints": [
                    {"key": t.key, "value": t.value, "effect": t.effect}
                    for t in (node.spec.taints or [])
                ],
                # AWS 연결용
                "provider_id": provider_id,
                "ec2_instance_id": ec2_instance_id,
                # EKS 노드그룹 라벨
                "eks_nodegroup": labels.get("eks.amazonaws.com/nodegroup"),
            })
        
        return items

    # =========================================================================
    # Pod 수집 (핵심 - 가장 많은 정보)
    # =========================================================================

    def _collect_pods(self) -> List[Dict[str, Any]]:
        """
        Pod 정보 수집 (K8sExtractor.extract_workload_facts 호환)
        
        이 메서드가 실행되면서 Secret/ConfigMap 사용 정보도 추적합니다.
        """
        items = []
        
        for pod in self.core_v1.list_pod_for_all_namespaces().items:
            namespace = pod.metadata.namespace
            
            if not self._should_scan_namespace(namespace):
                continue
            
            # 종료된 Pod 제외 (정의서 요구사항)
            phase = pod.status.phase
            if phase in ("Succeeded", "Failed"):
                continue
            
            name = pod.metadata.name
            labels = pod.metadata.labels or {}
            annotations = pod.metadata.annotations or {}
            
            # ===== Volumes 먼저 수집 (volume_mounts 매핑용) =====
            volumes_map: Dict[str, Dict[str, Any]] = {}
            volumes = []
            
            for v in (pod.spec.volumes or []):
                vol_info = {
                    "name": v.name,
                    "type": "unknown",
                    "source_name": None,
                    "is_host_path": False,
                    "host_path": None,
                }
                
                if v.host_path:
                    path = v.host_path.path
                    vol_info.update({
                        "type": "hostPath",
                        "source_name": path,
                        "is_host_path": True,
                        "host_path": path,
                        "is_dangerous_path": path in DANGEROUS_HOST_PATHS or any(
                            path.startswith(p) for p in ["/etc/", "/var/run/", "/proc/", "/sys/"]
                        ),
                    })
                elif v.secret:
                    secret_name = v.secret.secret_name
                    vol_info.update({
                        "type": "secret",
                        "source_name": secret_name,
                    })
                    # Secret 사용 추적
                    self._track_secret_usage(namespace, secret_name, name)
                elif v.config_map:
                    cm_name = v.config_map.name
                    vol_info.update({
                        "type": "configMap",
                        "source_name": cm_name,
                    })
                    # ConfigMap 사용 추적
                    self._track_configmap_usage(namespace, cm_name, name)
                elif v.persistent_volume_claim:
                    vol_info.update({
                        "type": "persistentVolumeClaim",
                        "source_name": v.persistent_volume_claim.claim_name,
                    })
                elif v.empty_dir:
                    vol_info.update({"type": "emptyDir"})
                elif v.projected:
                    vol_info.update({"type": "projected"})
                elif v.downward_api:
                    vol_info.update({"type": "downwardAPI"})
                
                volumes.append(vol_info)
                volumes_map[v.name] = vol_info
            
            # ===== Containers 수집 =====
            containers = []
            has_privileged = False
            has_root = False
            has_privilege_escalation = False
            dangerous_caps: Set[str] = set()
            has_no_resource_limits = True
            
            for c in (pod.spec.containers or []):
                container_info = self._parse_container(
                    c, volumes_map, namespace, name
                )
                containers.append(container_info)
                
                # 보안 플래그 집계
                sc = container_info.get("security_context") or {}
                if sc.get("privileged"):
                    has_privileged = True
                if sc.get("run_as_user") == 0:
                    has_root = True
                if sc.get("allow_privilege_escalation") is True:
                    has_privilege_escalation = True
                if sc.get("capabilities_add"):
                    dangerous_caps.update(
                        set(sc["capabilities_add"]) & DANGEROUS_CAPABILITIES
                    )
                if container_info.get("resources", {}).get("limits"):
                    has_no_resource_limits = False
            
            # ===== Init Containers 수집 =====
            init_containers = []
            for c in (pod.spec.init_containers or []):
                init_containers.append(self._parse_container(
                    c, volumes_map, namespace, name, is_init=True
                ))
            
            # ===== age_days 계산 =====
            created_at = pod.metadata.creation_timestamp
            age_days = _calculate_age_days(created_at)
            
            # ===== Owner Reference (어떤 워크로드가 관리하는지) =====
            owner_kind = None
            owner_name = None
            for owner in (pod.metadata.owner_references or []):
                if owner.controller:
                    owner_kind = owner.kind
                    owner_name = owner.name
                    break
            
            items.append({
                "namespace": namespace,
                "name": name,
                "kind": "Pod",  # Fact Extractor용
                "labels": labels,
                "annotations": annotations,
                "created_at": _to_iso8601(created_at),
                "age_days": age_days,
                
                # 워크로드 관계
                "owner_kind": owner_kind,
                "owner_name": owner_name,
                
                # ServiceAccount
                "service_account": pod.spec.service_account_name or "default",
                "automount_service_account_token": pod.spec.automount_service_account_token,
                
                # Host 네임스페이스
                "host_network": bool(pod.spec.host_network),
                "host_pid": bool(pod.spec.host_pid),
                "host_ipc": bool(pod.spec.host_ipc),
                
                # DNS
                "dns_policy": pod.spec.dns_policy,
                
                # 컨테이너
                "containers": containers,
                "init_containers": init_containers,
                
                # 볼륨
                "volumes": volumes,
                
                # 상태
                "phase": phase,
                "node_name": pod.spec.node_name,
                "pod_ip": pod.status.pod_ip,
                "host_ip": pod.status.host_ip,
                
                # ===== Fact Extractor용 사전 계산 필드 =====
                "has_privileged_container": has_privileged,
                "runs_as_root": has_root,
                "allows_privilege_escalation": has_privilege_escalation,
                "has_dangerous_capabilities": bool(dangerous_caps),
                "dangerous_capabilities": list(dangerous_caps),
                "has_host_path_volume": any(v.get("is_host_path") for v in volumes),
                "has_dangerous_host_path": any(v.get("is_dangerous_path") for v in volumes),
                "has_no_resource_limits": has_no_resource_limits,
                "mounts_docker_socket": any(
                    v.get("host_path") in [
                        "/var/run/docker.sock",
                        "/var/run/containerd/containerd.sock",
                        "/var/run/crio/crio.sock",
                    ]
                    for v in volumes
                ),
            })
        
        return items

    def _parse_container(
        self,
        container,
        volumes_map: Dict[str, Dict[str, Any]],
        namespace: str,
        pod_name: str,
        is_init: bool = False,
    ) -> Dict[str, Any]:
        """컨테이너 정보 파싱"""
        sc = container.security_context
        
        # Security Context
        security_context = None
        if sc:
            caps_add = list(sc.capabilities.add) if sc.capabilities and sc.capabilities.add else []
            caps_drop = list(sc.capabilities.drop) if sc.capabilities and sc.capabilities.drop else []
            
            security_context = {
                "privileged": sc.privileged,
                "run_as_user": sc.run_as_user,
                "run_as_group": sc.run_as_group,
                "run_as_non_root": sc.run_as_non_root,
                "allow_privilege_escalation": sc.allow_privilege_escalation,
                "read_only_root_filesystem": sc.read_only_root_filesystem,
                "capabilities_add": caps_add,  # Fact Extractor 호환
                "capabilities_drop": caps_drop,
                "capabilities": {
                    "add": caps_add,
                    "drop": caps_drop,
                },
            }
        
        # Volume Mounts (source_type, source_name 포함)
        volume_mounts = []
        for vm in (container.volume_mounts or []):
            vol_source = volumes_map.get(vm.name, {})
            volume_mounts.append({
                "name": vm.name,
                "mount_path": vm.mount_path,
                "read_only": vm.read_only,
                "sub_path": vm.sub_path,
                "source_type": vol_source.get("type"),
                "source_name": vol_source.get("source_name"),
            })
        
        # Env From (Secret, ConfigMap 참조)
        env_from_secrets = []
        env_from_configmaps = []
        
        for ef in (container.env_from or []):
            if ef.secret_ref:
                env_from_secrets.append({
                    "secret_name": ef.secret_ref.name,
                    "optional": ef.secret_ref.optional,
                })
                self._track_secret_usage(namespace, ef.secret_ref.name, pod_name)
            if ef.config_map_ref:
                env_from_configmaps.append({
                    "configmap_name": ef.config_map_ref.name,
                    "optional": ef.config_map_ref.optional,
                })
                self._track_configmap_usage(namespace, ef.config_map_ref.name, pod_name)
        
        # Env valueFrom (개별 키 참조)
        env_value_from_secrets = {}
        env_value_from_configmaps = {}
        
        for env in (container.env or []):
            if env.value_from:
                if env.value_from.secret_key_ref:
                    secret_name = env.value_from.secret_key_ref.name
                    if secret_name not in env_value_from_secrets:
                        env_value_from_secrets[secret_name] = []
                    env_value_from_secrets[secret_name].append(env.name)
                    self._track_secret_usage(namespace, secret_name, pod_name)
                    
                if env.value_from.config_map_key_ref:
                    cm_name = env.value_from.config_map_key_ref.name
                    if cm_name not in env_value_from_configmaps:
                        env_value_from_configmaps[cm_name] = []
                    env_value_from_configmaps[cm_name].append(env.name)
                    self._track_configmap_usage(namespace, cm_name, pod_name)
        
        # 통합된 env_from_secrets (정의서 호환)
        for secret_name, env_vars in env_value_from_secrets.items():
            env_from_secrets.append({
                "secret_name": secret_name,
                "env_vars": env_vars,
                "type": "valueFrom",
            })
        
        # Ports
        ports = []
        for p in (container.ports or []):
            ports.append({
                "container_port": p.container_port,
                "host_port": p.host_port,
                "protocol": p.protocol,
                "name": p.name,
            })
        
        # Resources
        resources = {}
        if container.resources:
            resources = {
                "requests": dict(container.resources.requests or {}),
                "limits": dict(container.resources.limits or {}),
            }
        
        return {
            "name": container.name,
            "image": container.image,
            "image_pull_policy": container.image_pull_policy,
            "is_init_container": is_init,
            "security_context": security_context,
            "volume_mounts": volume_mounts,
            "env_from_secrets": env_from_secrets,
            "env_from_configmaps": env_from_configmaps,
            "ports": ports,
            "resources": resources,
            "command": container.command,
            "args": container.args,
        }

    def _track_secret_usage(self, namespace: str, secret_name: str, pod_name: str) -> None:
        """Secret 사용 추적"""
        if namespace not in self._secret_usage:
            self._secret_usage[namespace] = {}
        if secret_name not in self._secret_usage[namespace]:
            self._secret_usage[namespace][secret_name] = []
        if pod_name not in self._secret_usage[namespace][secret_name]:
            self._secret_usage[namespace][secret_name].append(pod_name)

    def _track_configmap_usage(self, namespace: str, cm_name: str, pod_name: str) -> None:
        """ConfigMap 사용 추적"""
        if namespace not in self._configmap_usage:
            self._configmap_usage[namespace] = {}
        if cm_name not in self._configmap_usage[namespace]:
            self._configmap_usage[namespace][cm_name] = []
        if pod_name not in self._configmap_usage[namespace][cm_name]:
            self._configmap_usage[namespace][cm_name].append(pod_name)

    # =========================================================================
    # Service 수집
    # =========================================================================

    def _collect_services(self) -> List[Dict[str, Any]]:
        """Service 정보 수집 (NetworkExtractor.extract_service_facts 호환)"""
        items = []
        
        for svc in self.core_v1.list_service_for_all_namespaces().items:
            namespace = svc.metadata.namespace
            
            if not self._should_scan_namespace(namespace):
                continue
            
            name = svc.metadata.name
            svc_type = svc.spec.type
            
            # LoadBalancer 정보
            lb_ingress = []
            if svc.status.load_balancer and svc.status.load_balancer.ingress:
                for ing in svc.status.load_balancer.ingress:
                    lb_ingress.append({
                        "ip": ing.ip,
                        "hostname": ing.hostname,
                    })
            
            # Ports
            ports = []
            node_ports = []
            for p in (svc.spec.ports or []):
                ports.append({
                    "name": p.name,
                    "port": p.port,
                    "target_port": str(p.target_port) if p.target_port else None,
                    "node_port": p.node_port,
                    "protocol": p.protocol,
                })
                if p.node_port:
                    node_ports.append(p.node_port)
            
            items.append({
                "namespace": namespace,
                "name": name,
                "labels": svc.metadata.labels or {},
                "annotations": svc.metadata.annotations or {},
                "type": svc_type,
                "cluster_ip": svc.spec.cluster_ip,
                "external_ips": list(svc.spec.external_i_ps or []),
                "load_balancer_ip": svc.spec.load_balancer_ip,
                "load_balancer_ingress": lb_ingress,
                "selector": svc.spec.selector or {},
                "ports": ports,
                "session_affinity": svc.spec.session_affinity,
                # Fact Extractor용 필드
                "is_loadbalancer": svc_type == "LoadBalancer",
                "is_nodeport": svc_type == "NodePort",
                "is_external": svc_type in ("LoadBalancer", "NodePort") or bool(svc.spec.external_i_ps),
                "node_ports": node_ports,
            })
        
        return items

    # =========================================================================
    # Workload 수집 (Deployment, DaemonSet, StatefulSet 등)
    # =========================================================================

    def _collect_deployments(self) -> List[Dict[str, Any]]:
        """Deployment 정보 수집"""
        items = []
        
        for deploy in self.apps_v1.list_deployment_for_all_namespaces().items:
            if not self._should_scan_namespace(deploy.metadata.namespace):
                continue
            
            items.append({
                "namespace": deploy.metadata.namespace,
                "name": deploy.metadata.name,
                "kind": "Deployment",
                "labels": deploy.metadata.labels or {},
                "annotations": deploy.metadata.annotations or {},
                "replicas": deploy.spec.replicas,
                "available_replicas": deploy.status.available_replicas,
                "ready_replicas": deploy.status.ready_replicas,
                "selector": deploy.spec.selector.match_labels if deploy.spec.selector else {},
                "strategy": deploy.spec.strategy.type if deploy.spec.strategy else None,
                "created_at": _to_iso8601(deploy.metadata.creation_timestamp),
            })
        
        return items

    def _collect_daemonsets(self) -> List[Dict[str, Any]]:
        """DaemonSet 정보 수집"""
        items = []
        
        for ds in self.apps_v1.list_daemon_set_for_all_namespaces().items:
            if not self._should_scan_namespace(ds.metadata.namespace):
                continue
            
            items.append({
                "namespace": ds.metadata.namespace,
                "name": ds.metadata.name,
                "kind": "DaemonSet",
                "labels": ds.metadata.labels or {},
                "selector": ds.spec.selector.match_labels if ds.spec.selector else {},
                "desired_number_scheduled": ds.status.desired_number_scheduled,
                "current_number_scheduled": ds.status.current_number_scheduled,
                "number_ready": ds.status.number_ready,
            })
        
        return items

    def _collect_statefulsets(self) -> List[Dict[str, Any]]:
        """StatefulSet 정보 수집"""
        items = []
        
        for sts in self.apps_v1.list_stateful_set_for_all_namespaces().items:
            if not self._should_scan_namespace(sts.metadata.namespace):
                continue
            
            items.append({
                "namespace": sts.metadata.namespace,
                "name": sts.metadata.name,
                "kind": "StatefulSet",
                "labels": sts.metadata.labels or {},
                "replicas": sts.spec.replicas,
                "ready_replicas": sts.status.ready_replicas,
                "service_name": sts.spec.service_name,
            })
        
        return items

    def _collect_replicasets(self) -> List[Dict[str, Any]]:
        """ReplicaSet 정보 수집"""
        items = []
        
        for rs in self.apps_v1.list_replica_set_for_all_namespaces().items:
            if not self._should_scan_namespace(rs.metadata.namespace):
                continue
            
            # 현재 활성 ReplicaSet만 (replicas > 0)
            if (rs.spec.replicas or 0) == 0:
                continue
            
            items.append({
                "namespace": rs.metadata.namespace,
                "name": rs.metadata.name,
                "kind": "ReplicaSet",
                "labels": rs.metadata.labels or {},
                "replicas": rs.spec.replicas,
                "ready_replicas": rs.status.ready_replicas,
            })
        
        return items

    def _collect_jobs(self) -> List[Dict[str, Any]]:
        """Job 정보 수집"""
        items = []
        
        try:
            batch_v1 = client.BatchV1Api()
            for job in batch_v1.list_job_for_all_namespaces().items:
                if not self._should_scan_namespace(job.metadata.namespace):
                    continue
                
                items.append({
                    "namespace": job.metadata.namespace,
                    "name": job.metadata.name,
                    "kind": "Job",
                    "labels": job.metadata.labels or {},
                    "completions": job.spec.completions,
                    "succeeded": job.status.succeeded,
                    "failed": job.status.failed,
                    "active": job.status.active,
                })
        except Exception:
            pass
        
        return items

    def _collect_cronjobs(self) -> List[Dict[str, Any]]:
        """CronJob 정보 수집"""
        items = []
        
        try:
            batch_v1 = client.BatchV1Api()
            for cj in batch_v1.list_cron_job_for_all_namespaces().items:
                if not self._should_scan_namespace(cj.metadata.namespace):
                    continue
                
                items.append({
                    "namespace": cj.metadata.namespace,
                    "name": cj.metadata.name,
                    "kind": "CronJob",
                    "labels": cj.metadata.labels or {},
                    "schedule": cj.spec.schedule,
                    "suspend": cj.spec.suspend,
                    "last_schedule_time": _to_iso8601(cj.status.last_schedule_time),
                })
        except Exception:
            pass
        
        return items

    # =========================================================================
    # ServiceAccount 수집
    # =========================================================================

    def _collect_service_accounts(self) -> List[Dict[str, Any]]:
        """ServiceAccount 정보 수집 (RBACExtractor 호환)"""
        items = []
        
        for sa in self.core_v1.list_service_account_for_all_namespaces().items:
            namespace = sa.metadata.namespace
            
            if not self._should_scan_namespace(namespace):
                continue
            
            name = sa.metadata.name
            annotations = sa.metadata.annotations or {}
            
            # IRSA (EKS)
            irsa_role_arn = annotations.get("eks.amazonaws.com/role-arn")
            
            # Secret 참조
            secrets = [s.name for s in (sa.secrets or [])]
            
            items.append({
                "namespace": namespace,
                "name": name,
                "kind": "ServiceAccount",
                "labels": sa.metadata.labels or {},
                "annotations": annotations,
                "automount_service_account_token": sa.automount_service_account_token,
                "secrets": secrets,
                "image_pull_secrets": [s.name for s in (sa.image_pull_secrets or [])],
                # IRSA 정보
                "irsa_role_arn": irsa_role_arn,
                "is_irsa_enabled": bool(irsa_role_arn),
                # 기본 SA 여부
                "is_default_sa": name == "default",
            })
        
        return items

    # =========================================================================
    # Secret 수집
    # =========================================================================

    def _collect_secrets(self) -> List[Dict[str, Any]]:
        """
        Secret 정보 수집 (StorageExtractor.extract_secret_facts 호환)
        
        주의: 값(value)은 절대 수집하지 않음. key 이름만 수집.
        """
        items = []
        
        for secret in self.core_v1.list_secret_for_all_namespaces().items:
            namespace = secret.metadata.namespace
            
            if not self._should_scan_namespace(namespace):
                continue
            
            name = secret.metadata.name
            secret_type = secret.type
            
            # 서비스 어카운트 토큰은 제외 (정의서 요구사항)
            if secret_type == "kubernetes.io/service-account-token":
                continue
            
            keys = list((secret.data or {}).keys())
            
            # 사용 정보
            used_by_pods = self._secret_usage.get(namespace, {}).get(name, [])
            
            # 민감 데이터 키 패턴 체크
            has_sensitive_keys = False
            for key in keys:
                for pattern in SENSITIVE_KEY_PATTERNS:
                    if re.search(pattern, key, re.IGNORECASE):
                        has_sensitive_keys = True
                        break
                if has_sensitive_keys:
                    break
            
            items.append({
                "namespace": namespace,
                "name": name,
                "kind": "Secret",
                "labels": secret.metadata.labels or {},
                "type": secret_type,
                "keys": keys,
                # 사용 정보 (StorageExtractor 호환)
                "used_by_pods": used_by_pods,
                "used_by_service_accounts": [],  # 아래에서 채움
                "is_unused": len(used_by_pods) == 0,
                # 타입별 플래그
                "is_tls": secret_type == "kubernetes.io/tls",
                "is_dockerconfig": secret_type in [
                    "kubernetes.io/dockerconfigjson",
                    "kubernetes.io/dockercfg",
                ],
                "is_opaque": secret_type == "Opaque",
                # 민감 데이터 체크
                "has_sensitive_keys": has_sensitive_keys,
            })
        
        return items

    # =========================================================================
    # ConfigMap 수집
    # =========================================================================

    def _collect_configmaps(self) -> List[Dict[str, Any]]:
        """ConfigMap 정보 수집 (StorageExtractor.extract_configmap_facts 호환)"""
        items = []
        
        for cm in self.core_v1.list_config_map_for_all_namespaces().items:
            namespace = cm.metadata.namespace
            
            if not self._should_scan_namespace(namespace):
                continue
            
            name = cm.metadata.name
            keys = list((cm.data or {}).keys())
            
            # 사용 정보
            used_by_pods = self._configmap_usage.get(namespace, {}).get(name, [])
            
            # 민감 데이터 키 패턴 체크
            has_sensitive_data = False
            for key in keys:
                for pattern in SENSITIVE_KEY_PATTERNS:
                    if re.search(pattern, key, re.IGNORECASE):
                        has_sensitive_data = True
                        break
                if has_sensitive_data:
                    break
            
            items.append({
                "namespace": namespace,
                "name": name,
                "kind": "ConfigMap",
                "labels": cm.metadata.labels or {},
                "keys": keys,
                # 사용 정보
                "used_by_pods": used_by_pods,
                "is_unused": len(used_by_pods) == 0,
                # 민감 데이터 체크
                "has_sensitive_data": has_sensitive_data,
            })
        
        return items

    # =========================================================================
    # PersistentVolume / PersistentVolumeClaim 수집
    # =========================================================================

    def _collect_persistent_volumes(self) -> List[Dict[str, Any]]:
        """PersistentVolume 정보 수집 (StorageExtractor 호환)"""
        items = []
        
        for pv in self.core_v1.list_persistent_volume().items:
            name = pv.metadata.name
            
            # hostPath 체크
            is_host_path = False
            host_path = None
            mount_path = None
            
            if pv.spec.host_path:
                is_host_path = True
                host_path = pv.spec.host_path.path
                mount_path = host_path
            
            # NFS 체크
            is_nfs = bool(pv.spec.nfs)
            
            # CSI 체크
            is_csi = bool(pv.spec.csi)
            csi_driver = pv.spec.csi.driver if pv.spec.csi else None
            
            items.append({
                "name": name,
                "kind": "PersistentVolume",
                "labels": pv.metadata.labels or {},
                "capacity": dict(pv.spec.capacity or {}),
                "access_modes": list(pv.spec.access_modes or []),
                "reclaim_policy": pv.spec.persistent_volume_reclaim_policy,
                "storage_class": pv.spec.storage_class_name,
                "status": pv.status.phase,
                # StorageExtractor용 필드
                "is_host_path": is_host_path,
                "host_path": host_path,
                "mount_path": mount_path,
                "is_dangerous_path": host_path in DANGEROUS_HOST_PATHS if host_path else False,
                "is_nfs": is_nfs,
                "is_csi": is_csi,
                "csi_driver": csi_driver,
            })
        
        return items

    def _collect_persistent_volume_claims(self) -> List[Dict[str, Any]]:
        """PersistentVolumeClaim 정보 수집 (StorageExtractor 호환)"""
        items = []
        
        for pvc in self.core_v1.list_persistent_volume_claim_for_all_namespaces().items:
            namespace = pvc.metadata.namespace
            
            if not self._should_scan_namespace(namespace):
                continue
            
            items.append({
                "namespace": namespace,
                "name": pvc.metadata.name,
                "kind": "PersistentVolumeClaim",
                "labels": pvc.metadata.labels or {},
                "storage_class": pvc.spec.storage_class_name,
                "volume_name": pvc.spec.volume_name,
                "access_modes": list(pvc.spec.access_modes or []),
                "status": pvc.status.phase,
                "capacity": dict(pvc.status.capacity or {}),
                # StorageExtractor용 필드
                "is_pending": pvc.status.phase == "Pending",
            })
        
        return items

    # =========================================================================
    # RBAC 수집
    # =========================================================================

    def _collect_roles(self) -> List[Dict[str, Any]]:
        """Role 정보 수집 (RBACExtractor 호환)"""
        items = []
        
        for role in self.rbac_v1.list_role_for_all_namespaces().items:
            namespace = role.metadata.namespace
            
            if not self._should_scan_namespace(namespace):
                continue
            
            items.append(self._parse_role(role, namespace))
        
        return items

    def _collect_cluster_roles(self) -> List[Dict[str, Any]]:
        """ClusterRole 정보 수집 (RBACExtractor 호환)"""
        items = []
        
        for cr in self.rbac_v1.list_cluster_role().items:
            name = cr.metadata.name
            
            # 시스템 ClusterRole 제외 (옵션)
            if name.startswith("system:") and not self.config.include_system_namespaces:
                continue
            
            items.append(self._parse_role(cr, namespace=None, is_cluster=True))
        
        return items

    def _parse_role(
        self,
        role,
        namespace: Optional[str],
        is_cluster: bool = False,
    ) -> Dict[str, Any]:
        """Role/ClusterRole 파싱 (RBACExtractor 호환)"""
        name = role.metadata.name
        rules = []
        
        has_wildcard_resources = False
        has_wildcard_verbs = False
        dangerous_permissions: List[str] = []
        
        for r in (role.rules or []):
            api_groups = list(r.api_groups or [])
            resources = list(r.resources or [])
            verbs = list(r.verbs or [])
            resource_names = list(r.resource_names or [])
            
            rules.append({
                "api_groups": api_groups,
                "resources": resources,
                "verbs": verbs,
                "resource_names": resource_names,
            })
            
            # 와일드카드 체크
            if "*" in resources:
                has_wildcard_resources = True
            if "*" in verbs:
                has_wildcard_verbs = True
            
            # 위험 권한 체크
            for verb in verbs:
                for resource in resources:
                    perm = f"{verb}:{resource}"
                    
                    # secrets 접근
                    if resource in ("secrets", "*") and verb in ("get", "list", "watch", "*"):
                        dangerous_permissions.append(perm)
                    
                    # pods/exec
                    if resource in ("pods/exec", "pods/*", "*") and verb in ("create", "*"):
                        dangerous_permissions.append(perm)
                    
                    # pods 생성
                    if resource in ("pods", "*") and verb in ("create", "*"):
                        dangerous_permissions.append(perm)
                    
                    # RBAC 수정
                    if resource in ("roles", "rolebindings", "clusterroles", "clusterrolebindings", "*"):
                        if verb in ("create", "update", "patch", "delete", "*"):
                            dangerous_permissions.append(perm)
        
        # cluster-admin 체크
        is_cluster_admin = (
            has_wildcard_resources and 
            has_wildcard_verbs and 
            any("*" in r["api_groups"] or "" in r["api_groups"] for r in rules)
        )
        
        result = {
            "name": name,
            "kind": "ClusterRole" if is_cluster else "Role",
            "labels": role.metadata.labels or {},
            "rules": rules,
            # RBACExtractor용 필드
            "has_wildcard_resources": has_wildcard_resources,
            "has_wildcard_verbs": has_wildcard_verbs,
            "is_cluster_admin": is_cluster_admin,
            "dangerous_permissions": list(set(dangerous_permissions)),
        }
        
        if namespace:
            result["namespace"] = namespace
        
        return result

    def _collect_role_bindings(self) -> List[Dict[str, Any]]:
        """RoleBinding 정보 수집 (RBACExtractor 호환)"""
        items = []
        
        for rb in self.rbac_v1.list_role_binding_for_all_namespaces().items:
            namespace = rb.metadata.namespace
            
            if not self._should_scan_namespace(namespace):
                continue
            
            items.append(self._parse_binding(rb, namespace))
        
        return items

    def _collect_cluster_role_bindings(self) -> List[Dict[str, Any]]:
        """ClusterRoleBinding 정보 수집 (RBACExtractor 호환)"""
        items = []
        
        for crb in self.rbac_v1.list_cluster_role_binding().items:
            name = crb.metadata.name
            
            # 시스템 바인딩 제외 (옵션)
            if name.startswith("system:") and not self.config.include_system_namespaces:
                continue
            
            items.append(self._parse_binding(crb, namespace=None, is_cluster=True))
        
        return items

    def _parse_binding(
        self,
        binding,
        namespace: Optional[str],
        is_cluster: bool = False,
    ) -> Dict[str, Any]:
        """RoleBinding/ClusterRoleBinding 파싱"""
        name = binding.metadata.name
        
        role_ref = {
            "kind": binding.role_ref.kind,
            "name": binding.role_ref.name,
            "api_group": binding.role_ref.api_group,
        }
        
        subjects = []
        for s in (binding.subjects or []):
            subjects.append({
                "kind": s.kind,
                "name": s.name,
                "namespace": getattr(s, "namespace", None),
                "api_group": getattr(s, "api_group", None),
            })
        
        # cluster-admin 바인딩 체크
        binds_cluster_admin = binding.role_ref.name == "cluster-admin"
        
        result = {
            "name": name,
            "kind": "ClusterRoleBinding" if is_cluster else "RoleBinding",
            "labels": binding.metadata.labels or {},
            "role_ref": role_ref,
            "subjects": subjects,
            # RBACExtractor용 필드
            "binds_cluster_admin": binds_cluster_admin,
        }
        
        if namespace:
            result["namespace"] = namespace
        
        return result

    # =========================================================================
    # NetworkPolicy 수집
    # =========================================================================

    def _collect_network_policies(self) -> List[Dict[str, Any]]:
        """NetworkPolicy 정보 수집 (NetworkExtractor 호환)"""
        items = []
        
        for np in self.networking_v1.list_network_policy_for_all_namespaces().items:
            namespace = np.metadata.namespace
            
            if not self._should_scan_namespace(namespace):
                continue
            
            name = np.metadata.name
            policy_types = list(np.spec.policy_types or [])
            
            # Allow all 체크
            ingress_rules = np.spec.ingress or []
            egress_rules = np.spec.egress or []
            
            allows_all_ingress = False
            allows_all_egress = False
            
            # 빈 규칙 = allow all
            if "Ingress" in policy_types:
                if len(ingress_rules) == 1 and not ingress_rules[0].to_dict().get("from"):
                    allows_all_ingress = True
            
            if "Egress" in policy_types:
                if len(egress_rules) == 1 and not egress_rules[0].to_dict().get("to"):
                    allows_all_egress = True
            
            items.append({
                "namespace": namespace,
                "name": name,
                "kind": "NetworkPolicy",
                "labels": np.metadata.labels or {},
                "pod_selector": np.spec.pod_selector.match_labels if np.spec.pod_selector else {},
                "policy_types": policy_types,
                "ingress_rules_count": len(ingress_rules),
                "egress_rules_count": len(egress_rules),
                # NetworkExtractor용 필드
                "allows_all_ingress": allows_all_ingress,
                "allows_all_egress": allows_all_egress,
            })
        
        return items

    # =========================================================================
    # Ingress 수집
    # =========================================================================

    def _collect_ingresses(self) -> List[Dict[str, Any]]:
        """Ingress 정보 수집 (NetworkExtractor 호환)"""
        items = []
        
        for ing in self.networking_v1.list_ingress_for_all_namespaces().items:
            namespace = ing.metadata.namespace
            
            if not self._should_scan_namespace(namespace):
                continue
            
            name = ing.metadata.name
            
            # Rules 파싱
            rules = []
            hosts = []
            exposes_services = []
            
            for rule in (ing.spec.rules or []):
                host = rule.host
                if host:
                    hosts.append(host)
                
                paths = []
                if rule.http:
                    for path in (rule.http.paths or []):
                        backend_service = None
                        backend_port = None
                        
                        if path.backend and path.backend.service:
                            backend_service = path.backend.service.name
                            if path.backend.service.port:
                                backend_port = path.backend.service.port.number or path.backend.service.port.name
                            
                            if backend_service:
                                exposes_services.append(f"{namespace}/{backend_service}")
                        
                        paths.append({
                            "path": path.path,
                            "path_type": path.path_type,
                            "backend_service": backend_service,
                            "backend_port": backend_port,
                        })
                
                rules.append({
                    "host": host,
                    "paths": paths,
                })
            
            # TLS 체크
            tls_config = []
            has_tls = False
            
            for tls in (ing.spec.tls or []):
                has_tls = True
                tls_config.append({
                    "hosts": tls.hosts,
                    "secret_name": tls.secret_name,
                })
            
            items.append({
                "namespace": namespace,
                "name": name,
                "kind": "Ingress",
                "labels": ing.metadata.labels or {},
                "annotations": ing.metadata.annotations or {},
                "ingress_class_name": ing.spec.ingress_class_name,
                "rules": rules,
                "tls": tls_config,
                # NetworkExtractor용 필드
                "hosts": hosts,
                "has_tls": has_tls,
                "exposes_services": list(set(exposes_services)),
                "is_internet_facing": True,  # Ingress는 기본적으로 외부 노출
            })
        
        return items

    # =========================================================================
    # 페이로드 생성
    # =========================================================================

    def _build_payload(
        self,
        scan_id: str,
        trigger_mode: str,
        resources: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        스캔 결과 페이로드 생성
        
        Fact Extractor가 기대하는 구조:
        {
            "metadata": { ... },
            "k8s": { 리소스들 },  # 또는 "resources"
        }
        """
        return {
            # 메타데이터
            "scan_id": scan_id,
            "scan_type": "k8s",
            "cluster_id": self.config.cluster_id,
            "cluster_name": self.config.cluster_name or self.config.cluster_id,
            "cluster_type": self.cluster_type,
            "scanner_type": "k8s",
            "trigger_mode": trigger_mode,
            "scanned_at": self.scan_time,
            "scanner_version": "3.0.0",
            
            # Fact Extractor 호환 구조
            "metadata": {
                "cluster_id": self.config.cluster_id,
                "scan_id": scan_id,
                "scanned_at": self.scan_time,
                "cluster_type": self.cluster_type,
            },
            
            # 리소스 (두 가지 키로 제공 - 호환성)
            "resources": resources,
            "k8s": resources,
            
            # 요약
            "summary": self._generate_summary(resources),
        }

    def _generate_summary(self, resources: Dict[str, Any]) -> Dict[str, Any]:
        """리소스 요약 생성"""
        by_type = {k: len(v) for k, v in resources.items()}
        total = sum(by_type.values())

        pods = resources.get("pods", [])
        
        return {
            "total_resources": total,
            "by_type": by_type,
            "security_indicators": {
                "privileged_pods": sum(1 for p in pods if p.get("has_privileged_container")),
                "root_pods": sum(1 for p in pods if p.get("runs_as_root")),
                "host_network_pods": sum(1 for p in pods if p.get("host_network")),
                "host_pid_pods": sum(1 for p in pods if p.get("host_pid")),
                "host_path_pods": sum(1 for p in pods if p.get("has_host_path_volume")),
                "dangerous_host_path_pods": sum(1 for p in pods if p.get("has_dangerous_host_path")),
                "docker_socket_pods": sum(1 for p in pods if p.get("mounts_docker_socket")),
                "no_resource_limits_pods": sum(1 for p in pods if p.get("has_no_resource_limits")),
                "cluster_admin_bindings": sum(
                    1 for crb in resources.get("cluster_role_bindings", [])
                    if crb.get("binds_cluster_admin")
                ),
                "wildcard_cluster_roles": sum(
                    1 for cr in resources.get("cluster_roles", [])
                    if cr.get("has_wildcard_resources") and cr.get("has_wildcard_verbs")
                ),
                "unused_secrets": sum(
                    1 for s in resources.get("secrets", [])
                    if s.get("is_unused")
                ),
                "irsa_service_accounts": sum(
                    1 for sa in resources.get("service_accounts", [])
                    if sa.get("is_irsa_enabled")
                ),
                "default_sa_pods": sum(
                    1 for p in pods
                    if p.get("service_account") == "default"
                ),
                "namespaces_without_network_policy": sum(
                    1 for ns in resources.get("namespaces", [])
                    if not ns.get("has_network_policy")
                ),
            },
        }

    def _save_local_copy(self, payload: Dict[str, Any], scan_id: str) -> str:
        """로컬 저장"""
        os.makedirs(self.config.output_dir, exist_ok=True)
        
        filename = self.config.output_filename or f"k8s_scan_{scan_id}.json"
        filepath = os.path.join(self.config.output_dir, filename)
        
        save_json(payload, filepath)
        return filepath
