"""데이터 스키마 - Analysis Engine과 일치 (확장 버전)"""
from dataclasses import dataclass, field, asdict
from typing import Optional, Any
from datetime import datetime
import uuid


@dataclass
class ScanMetadata:
    """스캔 메타데이터"""
    scan_id: str
    cluster_id: str
    cluster_name: str
    scan_timestamp: str
    scanner_version: str
    
    @classmethod
    def create(cls, cluster_id: str, cluster_name: str, version: str = "1.0.0") -> "ScanMetadata":
        return cls(
            scan_id=str(uuid.uuid4()),
            cluster_id=cluster_id,
            cluster_name=cluster_name,
            scan_timestamp=datetime.utcnow().isoformat() + "Z",
            scanner_version=version
        )


# ============ K8s Resources ============

@dataclass
class K8sNode:
    """노드 정보"""
    name: str
    labels: dict[str, str]
    annotations: dict[str, str]
    taints: list[dict[str, Any]]
    conditions: list[dict[str, Any]]
    capacity: dict[str, str]
    allocatable: dict[str, str]
    node_info: dict[str, str]
    pod_cidr: Optional[str] = None
    internal_ip: Optional[str] = None
    external_ip: Optional[str] = None


@dataclass
class K8sWorkload:
    """워크로드 (Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob)"""
    kind: str
    name: str
    namespace: str
    uid: str
    node: Optional[str]
    images: list[str]
    labels: dict[str, str]
    annotations: dict[str, str]
    owner_references: list[dict[str, Any]]
    service_account: str
    automount_service_account_token: Optional[bool]
    security_context: dict[str, Any]
    containers: list[dict[str, Any]]
    init_containers: list[dict[str, Any]]
    volumes: list[dict[str, Any]]
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    priority_class: Optional[str] = None
    dns_policy: Optional[str] = None
    restart_policy: Optional[str] = None
    termination_grace_period: Optional[int] = None
    tolerations: list[dict[str, Any]] = field(default_factory=list)
    affinity: Optional[dict[str, Any]] = None
    status_phase: Optional[str] = None
    status_conditions: list[dict[str, Any]] = field(default_factory=list)


@dataclass 
class K8sRBAC:
    """RBAC 리소스"""
    kind: str
    name: str
    namespace: Optional[str]
    labels: dict[str, str]
    annotations: dict[str, str]
    rules: list[dict[str, Any]]
    subjects: list[dict[str, Any]] = field(default_factory=list)
    role_ref: Optional[dict[str, Any]] = None
    # 분석용 필드
    is_cluster_admin: bool = False
    has_wildcard_resources: bool = False
    has_wildcard_verbs: bool = False
    dangerous_permissions: list[str] = field(default_factory=list)


@dataclass
class K8sServiceAccount:
    """ServiceAccount"""
    name: str
    namespace: str
    labels: dict[str, str]
    annotations: dict[str, str]
    secrets: list[str]
    image_pull_secrets: list[str]
    automount_service_account_token: Optional[bool]
    # 바인딩된 역할 (분석 시 채워짐)
    bound_roles: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class K8sNetworkPolicy:
    """네트워크 정책"""
    name: str
    namespace: str
    labels: dict[str, str]
    pod_selector: dict[str, Any]
    ingress: list[dict[str, Any]]
    egress: list[dict[str, Any]]
    policy_types: list[str]
    # 분석용 필드
    allows_all_ingress: bool = False
    allows_all_egress: bool = False
    denies_all_ingress: bool = False
    denies_all_egress: bool = False


@dataclass
class K8sService:
    """서비스"""
    name: str
    namespace: str
    uid: str
    labels: dict[str, str]
    annotations: dict[str, str]
    type: str
    selector: dict[str, str]
    ports: list[dict[str, Any]]
    cluster_ip: Optional[str]
    external_ips: list[str] = field(default_factory=list)
    load_balancer_ip: Optional[str] = None
    load_balancer_ingress: list[dict[str, Any]] = field(default_factory=list)
    external_traffic_policy: Optional[str] = None
    session_affinity: Optional[str] = None


@dataclass
class K8sIngress:
    """Ingress - 외부 노출 진입점"""
    name: str
    namespace: str
    uid: str
    labels: dict[str, str]
    annotations: dict[str, str]
    ingress_class_name: Optional[str]
    tls: list[dict[str, Any]]
    rules: list[dict[str, Any]]
    default_backend: Optional[dict[str, Any]]
    # 분석용 필드
    hosts: list[str] = field(default_factory=list)
    exposes_services: list[str] = field(default_factory=list)
    has_tls: bool = False
    load_balancer_ips: list[str] = field(default_factory=list)


@dataclass
class K8sSecret:
    """시크릿 (값 제외, 메타데이터만)"""
    name: str
    namespace: str
    uid: str
    type: str
    labels: dict[str, str]
    annotations: dict[str, str]
    keys: list[str]
    # 분석용 필드
    used_by_pods: list[str] = field(default_factory=list)
    used_by_service_accounts: list[str] = field(default_factory=list)
    is_tls_secret: bool = False
    is_docker_config: bool = False


@dataclass
class K8sConfigMap:
    """ConfigMap"""
    name: str
    namespace: str
    uid: str
    labels: dict[str, str]
    annotations: dict[str, str]
    keys: list[str]
    # 분석용 필드
    has_sensitive_keys: bool = False
    sensitive_key_names: list[str] = field(default_factory=list)
    used_by_pods: list[str] = field(default_factory=list)


@dataclass
class K8sPersistentVolume:
    """PersistentVolume"""
    name: str
    uid: str
    labels: dict[str, str]
    storage_class: Optional[str]
    capacity: str
    access_modes: list[str]
    reclaim_policy: str
    status_phase: str
    volume_mode: Optional[str]
    source_type: str  # hostPath, nfs, awsElasticBlockStore, etc.
    source_details: dict[str, Any]
    claim_ref: Optional[dict[str, Any]] = None
    # 분석용 필드
    is_host_path: bool = False
    mount_path: Optional[str] = None


@dataclass
class K8sPersistentVolumeClaim:
    """PersistentVolumeClaim"""
    name: str
    namespace: str
    uid: str
    labels: dict[str, str]
    annotations: dict[str, str]
    storage_class: Optional[str]
    access_modes: list[str]
    requested_storage: str
    volume_name: Optional[str]
    volume_mode: Optional[str]
    status_phase: str
    # 분석용 필드
    used_by_pods: list[str] = field(default_factory=list)


@dataclass
class K8sLimitRange:
    """LimitRange - 네임스페이스별 리소스 제한"""
    name: str
    namespace: str
    limits: list[dict[str, Any]]


@dataclass
class K8sResourceQuota:
    """ResourceQuota - 네임스페이스별 리소스 쿼터"""
    name: str
    namespace: str
    hard: dict[str, str]
    used: dict[str, str]
    # 분석용 필드
    utilization_percent: dict[str, float] = field(default_factory=dict)


@dataclass
class K8sPodSecurityPolicy:
    """PodSecurityPolicy (deprecated but still in use)"""
    name: str
    labels: dict[str, str]
    spec: dict[str, Any]
    # 분석용 필드
    allows_privileged: bool = False
    allows_host_network: bool = False
    allows_host_pid: bool = False
    allows_host_ipc: bool = False
    allows_root: bool = False
    allowed_capabilities: list[str] = field(default_factory=list)


@dataclass
class K8sNamespace:
    """Namespace 정보"""
    name: str
    uid: str
    labels: dict[str, str]
    annotations: dict[str, str]
    status_phase: str
    # Pod Security Standards
    pss_enforce: Optional[str] = None  # privileged, baseline, restricted
    pss_audit: Optional[str] = None
    pss_warn: Optional[str] = None
    # 분석용 필드
    has_network_policy: bool = False
    has_limit_range: bool = False
    has_resource_quota: bool = False


@dataclass
class K8sEndpoints:
    """Endpoints - Service가 가리키는 실제 Pod IP들"""
    name: str
    namespace: str
    subsets: list[dict[str, Any]]
    # 분석용 필드
    ready_addresses: list[str] = field(default_factory=list)
    not_ready_addresses: list[str] = field(default_factory=list)


# ============ Image Scan Results ============

@dataclass
class ImageVulnerability:
    """이미지 취약점"""
    cve_id: str
    severity: str
    package: str
    installed_version: str
    fixed_version: Optional[str]
    title: str
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    published_date: Optional[str] = None
    last_modified_date: Optional[str] = None
    references: list[str] = field(default_factory=list)


@dataclass
class ImageScanResult:
    """이미지 스캔 결과"""
    image: str
    digest: Optional[str]
    scan_timestamp: str
    registry: Optional[str]
    repository: Optional[str]
    tag: Optional[str]
    os_family: str
    os_name: Optional[str]
    size_bytes: Optional[int]
    vulnerabilities: list[ImageVulnerability]
    summary: dict[str, int]
    # 분석용 필드
    used_by_pods: list[str] = field(default_factory=list)
    used_by_workloads: list[str] = field(default_factory=list)
    is_from_public_registry: bool = False
    has_no_tag: bool = False  # :latest 또는 태그 없음


# ============ Full Scan Result ============

@dataclass
class K8sResources:
    """K8s 리소스 전체"""
    namespaces: list[K8sNamespace] = field(default_factory=list)
    nodes: list[K8sNode] = field(default_factory=list)
    workloads: list[K8sWorkload] = field(default_factory=list)
    services: list[K8sService] = field(default_factory=list)
    ingresses: list[K8sIngress] = field(default_factory=list)
    endpoints: list[K8sEndpoints] = field(default_factory=list)
    service_accounts: list[K8sServiceAccount] = field(default_factory=list)
    rbac: list[K8sRBAC] = field(default_factory=list)
    network_policies: list[K8sNetworkPolicy] = field(default_factory=list)
    secrets: list[K8sSecret] = field(default_factory=list)
    configmaps: list[K8sConfigMap] = field(default_factory=list)
    persistent_volumes: list[K8sPersistentVolume] = field(default_factory=list)
    persistent_volume_claims: list[K8sPersistentVolumeClaim] = field(default_factory=list)
    limit_ranges: list[K8sLimitRange] = field(default_factory=list)
    resource_quotas: list[K8sResourceQuota] = field(default_factory=list)


@dataclass
class ScanResult:
    """전체 스캔 결과"""
    metadata: ScanMetadata
    k8s: K8sResources
    images: list[ImageScanResult] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return asdict(self)
    
    def get_statistics(self) -> dict:
        """스캔 통계"""
        total_vulns = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
        for img in self.images:
            for sev, count in img.summary.items():
                if sev in total_vulns:
                    total_vulns[sev] += count
        
        # 워크로드 종류별 카운트
        workload_counts = {}
        for w in self.k8s.workloads:
            workload_counts[w.kind] = workload_counts.get(w.kind, 0) + 1
        
        return {
            "namespaces": len(self.k8s.namespaces),
            "nodes": len(self.k8s.nodes),
            "workloads": len(self.k8s.workloads),
            "workload_breakdown": workload_counts,
            "services": len(self.k8s.services),
            "ingresses": len(self.k8s.ingresses),
            "service_accounts": len(self.k8s.service_accounts),
            "secrets": len(self.k8s.secrets),
            "configmaps": len(self.k8s.configmaps),
            "rbac_rules": len(self.k8s.rbac),
            "network_policies": len(self.k8s.network_policies),
            "persistent_volumes": len(self.k8s.persistent_volumes),
            "persistent_volume_claims": len(self.k8s.persistent_volume_claims),
            "limit_ranges": len(self.k8s.limit_ranges),
            "resource_quotas": len(self.k8s.resource_quotas),
            "images_scanned": len(self.images),
            "vulnerabilities": total_vulns,
            "total_vulnerabilities": sum(total_vulns.values()),
        }