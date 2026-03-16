"""Kubernetes 리소스 스캐너 - 확장 버전"""
import logging
from typing import Optional, Any
from kubernetes import client, config as k8s_config
from kubernetes.client.rest import ApiException

from ..config import Config
from ..models.schemas import (
    K8sResources, K8sWorkload, K8sRBAC, K8sNetworkPolicy,
    K8sSecret, K8sService, K8sConfigMap, K8sNode, K8sIngress,
    K8sServiceAccount, K8sPersistentVolume, K8sPersistentVolumeClaim,
    K8sLimitRange, K8sResourceQuota, K8sNamespace, K8sEndpoints
)

logger = logging.getLogger(__name__)


class K8sScanner:
    """Kubernetes 클러스터 리소스 수집기 - 확장 버전"""
    
    SENSITIVE_KEYS = {
        'password', 'passwd', 'secret', 'key', 'token', 'credential', 
        'api_key', 'apikey', 'api-key', 'auth', 'private', 'access_key',
        'secret_key', 'aws_access', 'aws_secret', 'database_url', 'db_pass',
        'connection_string', 'jwt', 'bearer', 'oauth'
    }
    
    DANGEROUS_VERBS = {'*', 'create', 'delete', 'deletecollection', 'patch', 'update'}
    DANGEROUS_RESOURCES = {
        '*', 'secrets', 'pods/exec', 'pods/attach', 'serviceaccounts/token',
        'nodes', 'persistentvolumes', 'clusterroles', 'clusterrolebindings',
        'roles', 'rolebindings', 'certificatesigningrequests'
    }
    
    def __init__(self, cfg: Config):
        self.config = cfg
        self._init_k8s_client()
    
    def _init_k8s_client(self):
        """K8s 클라이언트 초기화"""
        try:
            k8s_config.load_incluster_config()
            logger.info("Loaded in-cluster config")
        except k8s_config.ConfigException:
            k8s_config.load_kube_config()
            logger.info("Loaded kubeconfig")
        
        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.batch_v1 = client.BatchV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.networking_v1 = client.NetworkingV1Api()
        self.storage_v1 = client.StorageV1Api()
        self.policy_v1 = client.PolicyV1Api()
    
    def scan(self) -> K8sResources:
        """전체 K8s 리소스 스캔"""
        logger.info("=" * 60)
        logger.info("Starting K8s resource scan")
        logger.info("=" * 60)
        
        resources = K8sResources()
        
        # 네임스페이스 먼저 스캔
        resources.namespaces = self._scan_namespaces()
        
        # 스캔 대상 네임스페이스 결정
        target_namespaces = self._get_target_namespaces()
        logger.info(f"Target namespaces: {target_namespaces}")
        
        # 클러스터 레벨 리소스
        logger.info("Scanning cluster-level resources...")
        resources.nodes = self._scan_nodes()
        resources.persistent_volumes = self._scan_persistent_volumes()
        
        # 네임스페이스별 리소스
        logger.info("Scanning namespaced resources...")
        resources.workloads = self._scan_workloads(target_namespaces)
        resources.services = self._scan_services(target_namespaces)
        resources.ingresses = self._scan_ingresses(target_namespaces)
        resources.endpoints = self._scan_endpoints(target_namespaces)
        resources.service_accounts = self._scan_service_accounts(target_namespaces)
        resources.rbac = self._scan_rbac(target_namespaces)
        resources.network_policies = self._scan_network_policies(target_namespaces)
        resources.secrets = self._scan_secrets(target_namespaces)
        resources.configmaps = self._scan_configmaps(target_namespaces)
        resources.persistent_volume_claims = self._scan_pvcs(target_namespaces)
        resources.limit_ranges = self._scan_limit_ranges(target_namespaces)
        resources.resource_quotas = self._scan_resource_quotas(target_namespaces)
        
        # 네임스페이스 메타 정보 업데이트
        self._update_namespace_metadata(resources)
        
        # 참조 관계 분석
        self._analyze_references(resources)
        
        logger.info("=" * 60)
        logger.info(f"Scan complete: {len(resources.workloads)} workloads, "
                   f"{len(resources.services)} services, {len(resources.ingresses)} ingresses, "
                   f"{len(resources.secrets)} secrets, {len(resources.rbac)} RBAC rules")
        logger.info("=" * 60)
        
        return resources
    
    def _get_target_namespaces(self) -> list[str]:
        """스캔 대상 네임스페이스 결정"""
        if self.config.scan_namespaces:
            return [ns for ns in self.config.scan_namespaces if ns]
        
        all_ns = self.core_v1.list_namespace()
        return [
            ns.metadata.name for ns in all_ns.items
            if ns.metadata.name not in self.config.exclude_namespaces
        ]
    
    # ============ Namespace ============
    
    def _scan_namespaces(self) -> list[K8sNamespace]:
        """네임스페이스 스캔"""
        namespaces = []
        try:
            ns_list = self.core_v1.list_namespace()
            for ns in ns_list.items:
                labels = ns.metadata.labels or {}
                namespaces.append(K8sNamespace(
                    name=ns.metadata.name,
                    uid=ns.metadata.uid,
                    labels=labels,
                    annotations=ns.metadata.annotations or {},
                    status_phase=ns.status.phase,
                    pss_enforce=labels.get('pod-security.kubernetes.io/enforce'),
                    pss_audit=labels.get('pod-security.kubernetes.io/audit'),
                    pss_warn=labels.get('pod-security.kubernetes.io/warn'),
                ))
            logger.info(f"  Namespaces: {len(namespaces)}")
        except ApiException as e:
            logger.error(f"Failed to list namespaces: {e}")
        return namespaces
    
    # ============ Nodes ============
    
    def _scan_nodes(self) -> list[K8sNode]:
        """노드 정보 수집"""
        nodes = []
        try:
            node_list = self.core_v1.list_node()
            for node in node_list.items:
                # IP 주소 추출
                internal_ip = None
                external_ip = None
                for addr in (node.status.addresses or []):
                    if addr.type == "InternalIP":
                        internal_ip = addr.address
                    elif addr.type == "ExternalIP":
                        external_ip = addr.address
                
                nodes.append(K8sNode(
                    name=node.metadata.name,
                    labels=node.metadata.labels or {},
                    annotations=node.metadata.annotations or {},
                    taints=[{
                        "key": t.key, 
                        "value": t.value, 
                        "effect": t.effect
                    } for t in (node.spec.taints or [])],
                    conditions=[{
                        "type": c.type, 
                        "status": c.status,
                        "reason": c.reason,
                        "message": c.message
                    } for c in (node.status.conditions or [])],
                    capacity=dict(node.status.capacity) if node.status.capacity else {},
                    allocatable=dict(node.status.allocatable) if node.status.allocatable else {},
                    node_info={
                        "os": node.status.node_info.os_image if node.status.node_info else None,
                        "kernel": node.status.node_info.kernel_version if node.status.node_info else None,
                        "container_runtime": node.status.node_info.container_runtime_version if node.status.node_info else None,
                        "kubelet_version": node.status.node_info.kubelet_version if node.status.node_info else None,
                        "architecture": node.status.node_info.architecture if node.status.node_info else None,
                    },
                    pod_cidr=node.spec.pod_cidr,
                    internal_ip=internal_ip,
                    external_ip=external_ip,
                ))
            logger.info(f"  Nodes: {len(nodes)}")
        except ApiException as e:
            logger.error(f"Failed to list nodes: {e}")
        return nodes
    
    # ============ Workloads ============
    
    def _scan_workloads(self, namespaces: list[str]) -> list[K8sWorkload]:
        """워크로드 수집 (Pod, Deployment, DaemonSet, StatefulSet, ReplicaSet, Job, CronJob)"""
        workloads = []
        
        for ns in namespaces:
            # Pods
            try:
                pods = self.core_v1.list_namespaced_pod(ns)
                for pod in pods.items:
                    workloads.append(self._pod_to_workload(pod))
            except ApiException as e:
                logger.error(f"Failed to list pods in {ns}: {e}")
            
            # Deployments
            try:
                deploys = self.apps_v1.list_namespaced_deployment(ns)
                for deploy in deploys.items:
                    workloads.append(self._deployment_to_workload(deploy))
            except ApiException as e:
                logger.error(f"Failed to list deployments in {ns}: {e}")
            
            # DaemonSets
            try:
                daemonsets = self.apps_v1.list_namespaced_daemon_set(ns)
                for ds in daemonsets.items:
                    workloads.append(self._daemonset_to_workload(ds))
            except ApiException as e:
                logger.error(f"Failed to list daemonsets in {ns}: {e}")
            
            # StatefulSets
            try:
                statefulsets = self.apps_v1.list_namespaced_stateful_set(ns)
                for sts in statefulsets.items:
                    workloads.append(self._statefulset_to_workload(sts))
            except ApiException as e:
                logger.error(f"Failed to list statefulsets in {ns}: {e}")
            
            # ReplicaSets
            try:
                replicasets = self.apps_v1.list_namespaced_replica_set(ns)
                for rs in replicasets.items:
                    # Skip if owned by Deployment (avoid duplication)
                    if rs.metadata.owner_references:
                        continue
                    workloads.append(self._replicaset_to_workload(rs))
            except ApiException as e:
                logger.error(f"Failed to list replicasets in {ns}: {e}")
            
            # Jobs
            try:
                jobs = self.batch_v1.list_namespaced_job(ns)
                for job in jobs.items:
                    # Skip if owned by CronJob
                    if job.metadata.owner_references:
                        if any(ref.kind == "CronJob" for ref in job.metadata.owner_references):
                            continue
                    workloads.append(self._job_to_workload(job))
            except ApiException as e:
                logger.error(f"Failed to list jobs in {ns}: {e}")
            
            # CronJobs
            try:
                cronjobs = self.batch_v1.list_namespaced_cron_job(ns)
                for cj in cronjobs.items:
                    workloads.append(self._cronjob_to_workload(cj))
            except ApiException as e:
                logger.error(f"Failed to list cronjobs in {ns}: {e}")
        
        logger.info(f"  Workloads: {len(workloads)}")
        return workloads
    
    def _pod_to_workload(self, pod) -> K8sWorkload:
        """Pod를 K8sWorkload로 변환"""
        spec = pod.spec
        
        return K8sWorkload(
            kind="Pod",
            name=pod.metadata.name,
            namespace=pod.metadata.namespace,
            uid=pod.metadata.uid,
            node=spec.node_name,
            images=self._get_images_from_spec(spec),
            labels=pod.metadata.labels or {},
            annotations=pod.metadata.annotations or {},
            owner_references=self._get_owner_refs(pod.metadata.owner_references),
            service_account=spec.service_account_name or "default",
            automount_service_account_token=spec.automount_service_account_token,
            security_context=self._extract_pod_security_context(spec.security_context),
            containers=self._extract_containers(spec.containers),
            init_containers=self._extract_containers(spec.init_containers or []),
            volumes=self._extract_volumes(spec.volumes),
            host_network=spec.host_network or False,
            host_pid=spec.host_pid or False,
            host_ipc=spec.host_ipc or False,
            priority_class=spec.priority_class_name,
            dns_policy=spec.dns_policy,
            restart_policy=spec.restart_policy,
            termination_grace_period=spec.termination_grace_period_seconds,
            tolerations=[{
                "key": t.key, "operator": t.operator, 
                "value": t.value, "effect": t.effect
            } for t in (spec.tolerations or [])],
            affinity=self._extract_affinity(spec.affinity),
            status_phase=pod.status.phase if pod.status else None,
            status_conditions=[{
                "type": c.type, "status": c.status
            } for c in (pod.status.conditions or [])] if pod.status else [],
        )
    
    def _deployment_to_workload(self, deploy) -> K8sWorkload:
        """Deployment를 K8sWorkload로 변환"""
        spec = deploy.spec.template.spec
        
        return K8sWorkload(
            kind="Deployment",
            name=deploy.metadata.name,
            namespace=deploy.metadata.namespace,
            uid=deploy.metadata.uid,
            node=None,
            images=self._get_images_from_spec(spec),
            labels=deploy.metadata.labels or {},
            annotations=deploy.metadata.annotations or {},
            owner_references=self._get_owner_refs(deploy.metadata.owner_references),
            service_account=spec.service_account_name or "default",
            automount_service_account_token=spec.automount_service_account_token,
            security_context=self._extract_pod_security_context(spec.security_context),
            containers=self._extract_containers(spec.containers),
            init_containers=self._extract_containers(spec.init_containers or []),
            volumes=self._extract_volumes(spec.volumes),
            host_network=spec.host_network or False,
            host_pid=spec.host_pid or False,
            host_ipc=spec.host_ipc or False,
        )
    
    def _daemonset_to_workload(self, ds) -> K8sWorkload:
        """DaemonSet를 K8sWorkload로 변환"""
        spec = ds.spec.template.spec
        
        return K8sWorkload(
            kind="DaemonSet",
            name=ds.metadata.name,
            namespace=ds.metadata.namespace,
            uid=ds.metadata.uid,
            node=None,
            images=self._get_images_from_spec(spec),
            labels=ds.metadata.labels or {},
            annotations=ds.metadata.annotations or {},
            owner_references=self._get_owner_refs(ds.metadata.owner_references),
            service_account=spec.service_account_name or "default",
            automount_service_account_token=spec.automount_service_account_token,
            security_context=self._extract_pod_security_context(spec.security_context),
            containers=self._extract_containers(spec.containers),
            init_containers=self._extract_containers(spec.init_containers or []),
            volumes=self._extract_volumes(spec.volumes),
            host_network=spec.host_network or False,
            host_pid=spec.host_pid or False,
            host_ipc=spec.host_ipc or False,
        )
    
    def _statefulset_to_workload(self, sts) -> K8sWorkload:
        """StatefulSet를 K8sWorkload로 변환"""
        spec = sts.spec.template.spec
        
        return K8sWorkload(
            kind="StatefulSet",
            name=sts.metadata.name,
            namespace=sts.metadata.namespace,
            uid=sts.metadata.uid,
            node=None,
            images=self._get_images_from_spec(spec),
            labels=sts.metadata.labels or {},
            annotations=sts.metadata.annotations or {},
            owner_references=self._get_owner_refs(sts.metadata.owner_references),
            service_account=spec.service_account_name or "default",
            automount_service_account_token=spec.automount_service_account_token,
            security_context=self._extract_pod_security_context(spec.security_context),
            containers=self._extract_containers(spec.containers),
            init_containers=self._extract_containers(spec.init_containers or []),
            volumes=self._extract_volumes(spec.volumes),
            host_network=spec.host_network or False,
            host_pid=spec.host_pid or False,
            host_ipc=spec.host_ipc or False,
        )
    
    def _replicaset_to_workload(self, rs) -> K8sWorkload:
        """ReplicaSet를 K8sWorkload로 변환"""
        spec = rs.spec.template.spec
        
        return K8sWorkload(
            kind="ReplicaSet",
            name=rs.metadata.name,
            namespace=rs.metadata.namespace,
            uid=rs.metadata.uid,
            node=None,
            images=self._get_images_from_spec(spec),
            labels=rs.metadata.labels or {},
            annotations=rs.metadata.annotations or {},
            owner_references=self._get_owner_refs(rs.metadata.owner_references),
            service_account=spec.service_account_name or "default",
            automount_service_account_token=spec.automount_service_account_token,
            security_context=self._extract_pod_security_context(spec.security_context),
            containers=self._extract_containers(spec.containers),
            init_containers=self._extract_containers(spec.init_containers or []),
            volumes=self._extract_volumes(spec.volumes),
            host_network=spec.host_network or False,
            host_pid=spec.host_pid or False,
            host_ipc=spec.host_ipc or False,
        )
    
    def _job_to_workload(self, job) -> K8sWorkload:
        """Job을 K8sWorkload로 변환"""
        spec = job.spec.template.spec
        
        return K8sWorkload(
            kind="Job",
            name=job.metadata.name,
            namespace=job.metadata.namespace,
            uid=job.metadata.uid,
            node=None,
            images=self._get_images_from_spec(spec),
            labels=job.metadata.labels or {},
            annotations=job.metadata.annotations or {},
            owner_references=self._get_owner_refs(job.metadata.owner_references),
            service_account=spec.service_account_name or "default",
            automount_service_account_token=spec.automount_service_account_token,
            security_context=self._extract_pod_security_context(spec.security_context),
            containers=self._extract_containers(spec.containers),
            init_containers=self._extract_containers(spec.init_containers or []),
            volumes=self._extract_volumes(spec.volumes),
            host_network=spec.host_network or False,
            host_pid=spec.host_pid or False,
            host_ipc=spec.host_ipc or False,
            restart_policy=spec.restart_policy,
        )
    
    def _cronjob_to_workload(self, cj) -> K8sWorkload:
        """CronJob을 K8sWorkload로 변환"""
        spec = cj.spec.job_template.spec.template.spec
        
        return K8sWorkload(
            kind="CronJob",
            name=cj.metadata.name,
            namespace=cj.metadata.namespace,
            uid=cj.metadata.uid,
            node=None,
            images=self._get_images_from_spec(spec),
            labels=cj.metadata.labels or {},
            annotations=cj.metadata.annotations or {},
            owner_references=self._get_owner_refs(cj.metadata.owner_references),
            service_account=spec.service_account_name or "default",
            automount_service_account_token=spec.automount_service_account_token,
            security_context=self._extract_pod_security_context(spec.security_context),
            containers=self._extract_containers(spec.containers),
            init_containers=self._extract_containers(spec.init_containers or []),
            volumes=self._extract_volumes(spec.volumes),
            host_network=spec.host_network or False,
            host_pid=spec.host_pid or False,
            host_ipc=spec.host_ipc or False,
        )
    
    # ============ Services ============
    
    def _scan_services(self, namespaces: list[str]) -> list[K8sService]:
        """서비스 수집"""
        services = []
        for ns in namespaces:
            try:
                svc_list = self.core_v1.list_namespaced_service(ns)
                for svc in svc_list.items:
                    lb_ingress = []
                    if svc.status and svc.status.load_balancer and svc.status.load_balancer.ingress:
                        lb_ingress = [{
                            "ip": ing.ip,
                            "hostname": ing.hostname
                        } for ing in svc.status.load_balancer.ingress]
                    
                    services.append(K8sService(
                        name=svc.metadata.name,
                        namespace=svc.metadata.namespace,
                        uid=svc.metadata.uid,
                        labels=svc.metadata.labels or {},
                        annotations=svc.metadata.annotations or {},
                        type=svc.spec.type,
                        selector=svc.spec.selector or {},
                        ports=[{
                            "name": p.name,
                            "port": p.port,
                            "target_port": str(p.target_port) if p.target_port else None,
                            "protocol": p.protocol,
                            "node_port": p.node_port
                        } for p in (svc.spec.ports or [])],
                        cluster_ip=svc.spec.cluster_ip,
                        external_ips=svc.spec.external_i_ps or [],
                        load_balancer_ip=svc.spec.load_balancer_ip,
                        load_balancer_ingress=lb_ingress,
                        external_traffic_policy=svc.spec.external_traffic_policy,
                        session_affinity=svc.spec.session_affinity,
                    ))
            except ApiException as e:
                logger.error(f"Failed to list services in {ns}: {e}")
        logger.info(f"  Services: {len(services)}")
        return services
    
    # ============ Ingresses ============
    
    def _scan_ingresses(self, namespaces: list[str]) -> list[K8sIngress]:
        """Ingress 수집"""
        ingresses = []
        for ns in namespaces:
            try:
                ing_list = self.networking_v1.list_namespaced_ingress(ns)
                for ing in ing_list.items:
                    # 호스트 목록 추출
                    hosts = []
                    exposes_services = []
                    
                    for rule in (ing.spec.rules or []):
                        if rule.host:
                            hosts.append(rule.host)
                        if rule.http:
                            for path in (rule.http.paths or []):
                                if path.backend and path.backend.service:
                                    exposes_services.append(
                                        f"{ns}/{path.backend.service.name}"
                                    )
                    
                    # TLS 여부
                    has_tls = bool(ing.spec.tls)
                    
                    # LoadBalancer IP
                    lb_ips = []
                    if ing.status and ing.status.load_balancer and ing.status.load_balancer.ingress:
                        for lb in ing.status.load_balancer.ingress:
                            if lb.ip:
                                lb_ips.append(lb.ip)
                            if lb.hostname:
                                lb_ips.append(lb.hostname)
                    
                    ingresses.append(K8sIngress(
                        name=ing.metadata.name,
                        namespace=ns,
                        uid=ing.metadata.uid,
                        labels=ing.metadata.labels or {},
                        annotations=ing.metadata.annotations or {},
                        ingress_class_name=ing.spec.ingress_class_name,
                        tls=[{
                            "hosts": t.hosts or [],
                            "secret_name": t.secret_name
                        } for t in (ing.spec.tls or [])],
                        rules=[self._ingress_rule_to_dict(r) for r in (ing.spec.rules or [])],
                        default_backend=self._backend_to_dict(ing.spec.default_backend) if ing.spec.default_backend else None,
                        hosts=hosts,
                        exposes_services=list(set(exposes_services)),
                        has_tls=has_tls,
                        load_balancer_ips=lb_ips,
                    ))
            except ApiException as e:
                logger.error(f"Failed to list ingresses in {ns}: {e}")
        logger.info(f"  Ingresses: {len(ingresses)}")
        return ingresses
    
    def _ingress_rule_to_dict(self, rule) -> dict:
        """Ingress Rule 변환"""
        result = {"host": rule.host}
        if rule.http:
            result["paths"] = [{
                "path": p.path,
                "path_type": p.path_type,
                "backend": self._backend_to_dict(p.backend) if p.backend else None
            } for p in (rule.http.paths or [])]
        return result
    
    def _backend_to_dict(self, backend) -> dict:
        """Ingress Backend 변환"""
        if not backend:
            return {}
        result = {}
        if backend.service:
            result["service"] = {
                "name": backend.service.name,
                "port": {
                    "number": backend.service.port.number if backend.service.port else None,
                    "name": backend.service.port.name if backend.service.port else None
                }
            }
        if backend.resource:
            result["resource"] = {
                "api_group": backend.resource.api_group,
                "kind": backend.resource.kind,
                "name": backend.resource.name
            }
        return result
    
    # ============ Endpoints ============
    
    def _scan_endpoints(self, namespaces: list[str]) -> list[K8sEndpoints]:
        """Endpoints 수집"""
        endpoints = []
        for ns in namespaces:
            try:
                ep_list = self.core_v1.list_namespaced_endpoints(ns)
                for ep in ep_list.items:
                    ready_addrs = []
                    not_ready_addrs = []
                    
                    for subset in (ep.subsets or []):
                        for addr in (subset.addresses or []):
                            ready_addrs.append(addr.ip)
                        for addr in (subset.not_ready_addresses or []):
                            not_ready_addrs.append(addr.ip)
                    
                    endpoints.append(K8sEndpoints(
                        name=ep.metadata.name,
                        namespace=ns,
                        subsets=[{
                            "addresses": [a.ip for a in (s.addresses or [])],
                            "not_ready_addresses": [a.ip for a in (s.not_ready_addresses or [])],
                            "ports": [{
                                "name": p.name,
                                "port": p.port,
                                "protocol": p.protocol
                            } for p in (s.ports or [])]
                        } for s in (ep.subsets or [])],
                        ready_addresses=ready_addrs,
                        not_ready_addresses=not_ready_addrs,
                    ))
            except ApiException as e:
                logger.error(f"Failed to list endpoints in {ns}: {e}")
        logger.info(f"  Endpoints: {len(endpoints)}")
        return endpoints
    
    # ============ ServiceAccounts ============
    
    def _scan_service_accounts(self, namespaces: list[str]) -> list[K8sServiceAccount]:
        """ServiceAccount 수집"""
        service_accounts = []
        for ns in namespaces:
            try:
                sa_list = self.core_v1.list_namespaced_service_account(ns)
                for sa in sa_list.items:
                    service_accounts.append(K8sServiceAccount(
                        name=sa.metadata.name,
                        namespace=ns,
                        labels=sa.metadata.labels or {},
                        annotations=sa.metadata.annotations or {},
                        secrets=[s.name for s in (sa.secrets or [])],
                        image_pull_secrets=[s.name for s in (sa.image_pull_secrets or [])],
                        automount_service_account_token=sa.automount_service_account_token,
                    ))
            except ApiException as e:
                logger.error(f"Failed to list service accounts in {ns}: {e}")
        logger.info(f"  ServiceAccounts: {len(service_accounts)}")
        return service_accounts
    
    # ============ RBAC ============
    
    def _scan_rbac(self, namespaces: list[str]) -> list[K8sRBAC]:
        """RBAC 수집"""
        rbac_items = []
        
        # ClusterRoles
        try:
            cluster_roles = self.rbac_v1.list_cluster_role()
            for cr in cluster_roles.items:
                if cr.metadata.name.startswith("system:"):
                    continue
                
                rules = [self._rule_to_dict(r) for r in (cr.rules or [])]
                dangerous_perms, has_wildcard_res, has_wildcard_verbs, is_admin = self._analyze_rbac_rules(rules)
                
                rbac_items.append(K8sRBAC(
                    kind="ClusterRole",
                    name=cr.metadata.name,
                    namespace=None,
                    labels=cr.metadata.labels or {},
                    annotations=cr.metadata.annotations or {},
                    rules=rules,
                    is_cluster_admin=is_admin,
                    has_wildcard_resources=has_wildcard_res,
                    has_wildcard_verbs=has_wildcard_verbs,
                    dangerous_permissions=dangerous_perms,
                ))
        except ApiException as e:
            logger.error(f"Failed to list cluster roles: {e}")
        
        # ClusterRoleBindings
        try:
            crbs = self.rbac_v1.list_cluster_role_binding()
            for crb in crbs.items:
                if crb.metadata.name.startswith("system:"):
                    continue
                rbac_items.append(K8sRBAC(
                    kind="ClusterRoleBinding",
                    name=crb.metadata.name,
                    namespace=None,
                    labels=crb.metadata.labels or {},
                    annotations=crb.metadata.annotations or {},
                    rules=[],
                    subjects=[self._subject_to_dict(s) for s in (crb.subjects or [])],
                    role_ref={
                        "kind": crb.role_ref.kind, 
                        "name": crb.role_ref.name,
                        "api_group": crb.role_ref.api_group
                    }
                ))
        except ApiException as e:
            logger.error(f"Failed to list cluster role bindings: {e}")
        
        # Namespaced Roles and RoleBindings
        for ns in namespaces:
            try:
                roles = self.rbac_v1.list_namespaced_role(ns)
                for role in roles.items:
                    rules = [self._rule_to_dict(r) for r in (role.rules or [])]
                    dangerous_perms, has_wildcard_res, has_wildcard_verbs, is_admin = self._analyze_rbac_rules(rules)
                    
                    rbac_items.append(K8sRBAC(
                        kind="Role",
                        name=role.metadata.name,
                        namespace=ns,
                        labels=role.metadata.labels or {},
                        annotations=role.metadata.annotations or {},
                        rules=rules,
                        has_wildcard_resources=has_wildcard_res,
                        has_wildcard_verbs=has_wildcard_verbs,
                        dangerous_permissions=dangerous_perms,
                    ))
            except ApiException as e:
                logger.error(f"Failed to list roles in {ns}: {e}")
            
            try:
                rbs = self.rbac_v1.list_namespaced_role_binding(ns)
                for rb in rbs.items:
                    rbac_items.append(K8sRBAC(
                        kind="RoleBinding",
                        name=rb.metadata.name,
                        namespace=ns,
                        labels=rb.metadata.labels or {},
                        annotations=rb.metadata.annotations or {},
                        rules=[],
                        subjects=[self._subject_to_dict(s) for s in (rb.subjects or [])],
                        role_ref={
                            "kind": rb.role_ref.kind, 
                            "name": rb.role_ref.name,
                            "api_group": rb.role_ref.api_group
                        }
                    ))
            except ApiException as e:
                logger.error(f"Failed to list role bindings in {ns}: {e}")
        
        logger.info(f"  RBAC items: {len(rbac_items)}")
        return rbac_items
    
    def _analyze_rbac_rules(self, rules: list[dict]) -> tuple[list[str], bool, bool, bool]:
        """RBAC 규칙 위험도 분석"""
        dangerous_perms = []
        has_wildcard_resources = False
        has_wildcard_verbs = False
        is_cluster_admin = False
        
        for rule in rules:
            verbs = set(rule.get('verbs', []))
            resources = set(rule.get('resources', []))
            api_groups = set(rule.get('api_groups', []))
            
            # 와일드카드 체크
            if '*' in verbs:
                has_wildcard_verbs = True
            if '*' in resources:
                has_wildcard_resources = True
            
            # cluster-admin 수준 권한
            if '*' in verbs and '*' in resources and ('' in api_groups or '*' in api_groups):
                is_cluster_admin = True
            
            # 위험한 권한 조합
            for verb in verbs:
                for resource in resources:
                    if verb in self.DANGEROUS_VERBS and resource in self.DANGEROUS_RESOURCES:
                        dangerous_perms.append(f"{verb}:{resource}")
        
        return list(set(dangerous_perms)), has_wildcard_resources, has_wildcard_verbs, is_cluster_admin
    
    # ============ NetworkPolicies ============
    
    def _scan_network_policies(self, namespaces: list[str]) -> list[K8sNetworkPolicy]:
        """네트워크 정책 수집"""
        policies = []
        for ns in namespaces:
            try:
                np_list = self.networking_v1.list_namespaced_network_policy(ns)
                for np in np_list.items:
                    ingress_rules = [self._np_ingress_to_dict(r) for r in (np.spec.ingress or [])]
                    egress_rules = [self._np_egress_to_dict(r) for r in (np.spec.egress or [])]
                    policy_types = np.spec.policy_types or []
                    
                    # 분석
                    allows_all_ingress = False
                    allows_all_egress = False
                    denies_all_ingress = False
                    denies_all_egress = False
                    
                    if "Ingress" in policy_types:
                        if not np.spec.ingress:
                            denies_all_ingress = True
                        elif any(not r.get('from') for r in ingress_rules):
                            allows_all_ingress = True
                    
                    if "Egress" in policy_types:
                        if not np.spec.egress:
                            denies_all_egress = True
                        elif any(not r.get('to') for r in egress_rules):
                            allows_all_egress = True
                    
                    policies.append(K8sNetworkPolicy(
                        name=np.metadata.name,
                        namespace=ns,
                        labels=np.metadata.labels or {},
                        pod_selector=np.spec.pod_selector.match_labels if np.spec.pod_selector else {},
                        ingress=ingress_rules,
                        egress=egress_rules,
                        policy_types=policy_types,
                        allows_all_ingress=allows_all_ingress,
                        allows_all_egress=allows_all_egress,
                        denies_all_ingress=denies_all_ingress,
                        denies_all_egress=denies_all_egress,
                    ))
            except ApiException as e:
                logger.error(f"Failed to list network policies in {ns}: {e}")
        logger.info(f"  NetworkPolicies: {len(policies)}")
        return policies
    
    # ============ Secrets ============
    
    def _scan_secrets(self, namespaces: list[str]) -> list[K8sSecret]:
        """시크릿 메타데이터 수집 (값은 수집 안함)"""
        secrets = []
        for ns in namespaces:
            try:
                secret_list = self.core_v1.list_namespaced_secret(ns)
                for secret in secret_list.items:
                    if secret.type == "kubernetes.io/service-account-token":
                        continue
                    
                    secret_type = secret.type
                    is_tls = secret_type == "kubernetes.io/tls"
                    is_docker = secret_type in ["kubernetes.io/dockercfg", "kubernetes.io/dockerconfigjson"]
                    
                    secrets.append(K8sSecret(
                        name=secret.metadata.name,
                        namespace=ns,
                        uid=secret.metadata.uid,
                        type=secret_type,
                        labels=secret.metadata.labels or {},
                        annotations=secret.metadata.annotations or {},
                        keys=list(secret.data.keys()) if secret.data else [],
                        is_tls_secret=is_tls,
                        is_docker_config=is_docker,
                    ))
            except ApiException as e:
                logger.error(f"Failed to list secrets in {ns}: {e}")
        logger.info(f"  Secrets: {len(secrets)}")
        return secrets
    
    # ============ ConfigMaps ============
    
    def _scan_configmaps(self, namespaces: list[str]) -> list[K8sConfigMap]:
        """ConfigMap 수집"""
        configmaps = []
        for ns in namespaces:
            try:
                cm_list = self.core_v1.list_namespaced_config_map(ns)
                for cm in cm_list.items:
                    keys = list(cm.data.keys()) if cm.data else []
                    sensitive_keys = [
                        k for k in keys 
                        if any(sk in k.lower() for sk in self.SENSITIVE_KEYS)
                    ]
                    
                    configmaps.append(K8sConfigMap(
                        name=cm.metadata.name,
                        namespace=ns,
                        uid=cm.metadata.uid,
                        labels=cm.metadata.labels or {},
                        annotations=cm.metadata.annotations or {},
                        keys=keys,
                        has_sensitive_keys=bool(sensitive_keys),
                        sensitive_key_names=sensitive_keys,
                    ))
            except ApiException as e:
                logger.error(f"Failed to list configmaps in {ns}: {e}")
        logger.info(f"  ConfigMaps: {len(configmaps)}")
        return configmaps
    
    # ============ PV/PVC ============
    
    def _scan_persistent_volumes(self) -> list[K8sPersistentVolume]:
        """PersistentVolume 수집"""
        pvs = []
        try:
            pv_list = self.core_v1.list_persistent_volume()
            for pv in pv_list.items:
                source_type, source_details, is_host_path, mount_path = self._extract_pv_source(pv.spec)
                
                pvs.append(K8sPersistentVolume(
                    name=pv.metadata.name,
                    uid=pv.metadata.uid,
                    labels=pv.metadata.labels or {},
                    storage_class=pv.spec.storage_class_name,
                    capacity=pv.spec.capacity.get('storage', '') if pv.spec.capacity else '',
                    access_modes=pv.spec.access_modes or [],
                    reclaim_policy=pv.spec.persistent_volume_reclaim_policy or '',
                    status_phase=pv.status.phase if pv.status else '',
                    volume_mode=pv.spec.volume_mode,
                    source_type=source_type,
                    source_details=source_details,
                    claim_ref={
                        "name": pv.spec.claim_ref.name,
                        "namespace": pv.spec.claim_ref.namespace
                    } if pv.spec.claim_ref else None,
                    is_host_path=is_host_path,
                    mount_path=mount_path,
                ))
        except ApiException as e:
            logger.error(f"Failed to list persistent volumes: {e}")
        logger.info(f"  PersistentVolumes: {len(pvs)}")
        return pvs
    
    def _extract_pv_source(self, spec) -> tuple[str, dict, bool, Optional[str]]:
        """PV 소스 정보 추출"""
        is_host_path = False
        mount_path = None
        
        if spec.host_path:
            return "hostPath", {"path": spec.host_path.path, "type": spec.host_path.type}, True, spec.host_path.path
        elif spec.nfs:
            return "nfs", {"server": spec.nfs.server, "path": spec.nfs.path}, False, None
        elif spec.aws_elastic_block_store:
            return "awsElasticBlockStore", {
                "volume_id": spec.aws_elastic_block_store.volume_id,
                "fs_type": spec.aws_elastic_block_store.fs_type
            }, False, None
        elif spec.gce_persistent_disk:
            return "gcePersistentDisk", {
                "pd_name": spec.gce_persistent_disk.pd_name
            }, False, None
        elif spec.csi:
            return "csi", {
                "driver": spec.csi.driver,
                "volume_handle": spec.csi.volume_handle
            }, False, None
        else:
            return "other", {}, False, None
    
    def _scan_pvcs(self, namespaces: list[str]) -> list[K8sPersistentVolumeClaim]:
        """PersistentVolumeClaim 수집"""
        pvcs = []
        for ns in namespaces:
            try:
                pvc_list = self.core_v1.list_namespaced_persistent_volume_claim(ns)
                for pvc in pvc_list.items:
                    requested = ''
                    if pvc.spec.resources and pvc.spec.resources.requests:
                        requested = pvc.spec.resources.requests.get('storage', '')
                    
                    pvcs.append(K8sPersistentVolumeClaim(
                        name=pvc.metadata.name,
                        namespace=ns,
                        uid=pvc.metadata.uid,
                        labels=pvc.metadata.labels or {},
                        annotations=pvc.metadata.annotations or {},
                        storage_class=pvc.spec.storage_class_name,
                        access_modes=pvc.spec.access_modes or [],
                        requested_storage=requested,
                        volume_name=pvc.spec.volume_name,
                        volume_mode=pvc.spec.volume_mode,
                        status_phase=pvc.status.phase if pvc.status else '',
                    ))
            except ApiException as e:
                logger.error(f"Failed to list PVCs in {ns}: {e}")
        logger.info(f"  PVCs: {len(pvcs)}")
        return pvcs
    
    # ============ LimitRange / ResourceQuota ============
    
    def _scan_limit_ranges(self, namespaces: list[str]) -> list[K8sLimitRange]:
        """LimitRange 수집"""
        limit_ranges = []
        for ns in namespaces:
            try:
                lr_list = self.core_v1.list_namespaced_limit_range(ns)
                for lr in lr_list.items:
                    limit_ranges.append(K8sLimitRange(
                        name=lr.metadata.name,
                        namespace=ns,
                        limits=[{
                            "type": l.type,
                            "default": dict(l.default) if l.default else {},
                            "default_request": dict(l.default_request) if l.default_request else {},
                            "max": dict(l.max) if l.max else {},
                            "min": dict(l.min) if l.min else {},
                            "max_limit_request_ratio": dict(l.max_limit_request_ratio) if l.max_limit_request_ratio else {},
                        } for l in (lr.spec.limits or [])]
                    ))
            except ApiException as e:
                logger.error(f"Failed to list limit ranges in {ns}: {e}")
        logger.info(f"  LimitRanges: {len(limit_ranges)}")
        return limit_ranges
    
    def _scan_resource_quotas(self, namespaces: list[str]) -> list[K8sResourceQuota]:
        """ResourceQuota 수집"""
        quotas = []
        for ns in namespaces:
            try:
                rq_list = self.core_v1.list_namespaced_resource_quota(ns)
                for rq in rq_list.items:
                    hard = dict(rq.status.hard) if rq.status and rq.status.hard else {}
                    used = dict(rq.status.used) if rq.status and rq.status.used else {}
                    
                    # 사용률 계산
                    utilization = {}
                    for key in hard:
                        if key in used:
                            try:
                                h = self._parse_quantity(hard[key])
                                u = self._parse_quantity(used[key])
                                if h > 0:
                                    utilization[key] = round((u / h) * 100, 2)
                            except:
                                pass
                    
                    quotas.append(K8sResourceQuota(
                        name=rq.metadata.name,
                        namespace=ns,
                        hard=hard,
                        used=used,
                        utilization_percent=utilization,
                    ))
            except ApiException as e:
                logger.error(f"Failed to list resource quotas in {ns}: {e}")
        logger.info(f"  ResourceQuotas: {len(quotas)}")
        return quotas
    
    def _parse_quantity(self, quantity: str) -> float:
        """K8s quantity 파싱 (예: 100m, 1Gi)"""
        quantity = str(quantity)
        multipliers = {
            'Ki': 1024, 'Mi': 1024**2, 'Gi': 1024**3, 'Ti': 1024**4,
            'K': 1000, 'M': 1000**2, 'G': 1000**3, 'T': 1000**4,
            'm': 0.001, '': 1
        }
        for suffix, mult in multipliers.items():
            if quantity.endswith(suffix):
                return float(quantity[:-len(suffix)] if suffix else quantity) * mult
        return float(quantity)
    
    # ============ Helper Methods ============
    
    def _update_namespace_metadata(self, resources: K8sResources):
        """네임스페이스에 정책 존재 여부 업데이트"""
        np_namespaces = {np.namespace for np in resources.network_policies}
        lr_namespaces = {lr.namespace for lr in resources.limit_ranges}
        rq_namespaces = {rq.namespace for rq in resources.resource_quotas}
        
        for ns in resources.namespaces:
            ns.has_network_policy = ns.name in np_namespaces
            ns.has_limit_range = ns.name in lr_namespaces
            ns.has_resource_quota = ns.name in rq_namespaces
    
    def _analyze_references(self, resources: K8sResources):
        """리소스 간 참조 관계 분석"""
        # Secret 사용 현황
        secret_usage: dict[str, list[str]] = {}
        for w in resources.workloads:
            for vol in w.volumes:
                if vol.get('type') == 'secret':
                    key = f"{w.namespace}/{vol.get('secret_name')}"
                    if key not in secret_usage:
                        secret_usage[key] = []
                    secret_usage[key].append(f"{w.namespace}/{w.name}")
        
        for secret in resources.secrets:
            key = f"{secret.namespace}/{secret.name}"
            secret.used_by_pods = secret_usage.get(key, [])
        
        # PVC 사용 현황
        pvc_usage: dict[str, list[str]] = {}
        for w in resources.workloads:
            for vol in w.volumes:
                if vol.get('type') == 'pvc':
                    key = f"{w.namespace}/{vol.get('claim_name')}"
                    if key not in pvc_usage:
                        pvc_usage[key] = []
                    pvc_usage[key].append(f"{w.namespace}/{w.name}")
        
        for pvc in resources.persistent_volume_claims:
            key = f"{pvc.namespace}/{pvc.name}"
            pvc.used_by_pods = pvc_usage.get(key, [])
    
    def _get_images_from_spec(self, spec) -> list[str]:
        """Pod spec에서 이미지 목록 추출"""
        images = []
        for c in (spec.containers or []):
            if c.image:
                images.append(c.image)
        for c in (spec.init_containers or []):
            if c.image:
                images.append(c.image)
        return images
    
    def _get_owner_refs(self, owner_refs) -> list[dict]:
        """Owner references 추출"""
        if not owner_refs:
            return []
        return [{
            "kind": ref.kind,
            "name": ref.name,
            "uid": ref.uid,
            "controller": ref.controller
        } for ref in owner_refs]
    
    def _extract_containers(self, containers) -> list[dict]:
        """컨테이너 정보 추출"""
        result = []
        for c in (containers or []):
            result.append({
                "name": c.name,
                "image": c.image,
                "image_pull_policy": c.image_pull_policy,
                "ports": [{
                    "container_port": p.container_port,
                    "protocol": p.protocol,
                    "host_port": p.host_port
                } for p in (c.ports or [])],
                "security_context": self._extract_container_security_context(c.security_context),
                "resources": {
                    "requests": dict(c.resources.requests) if c.resources and c.resources.requests else {},
                    "limits": dict(c.resources.limits) if c.resources and c.resources.limits else {},
                },
                "env_from_secrets": self._get_secret_refs_from_env(c),
                "env_from_configmaps": self._get_configmap_refs_from_env(c),
                "volume_mounts": [{
                    "name": vm.name,
                    "mount_path": vm.mount_path,
                    "read_only": vm.read_only,
                    "sub_path": vm.sub_path
                } for vm in (c.volume_mounts or [])],
                "command": c.command,
                "args": c.args,
                "liveness_probe": bool(c.liveness_probe),
                "readiness_probe": bool(c.readiness_probe),
            })
        return result
    
    def _extract_container_security_context(self, sc) -> dict:
        """컨테이너 SecurityContext 추출"""
        if not sc:
            return {}
        return {
            "privileged": sc.privileged,
            "run_as_user": sc.run_as_user,
            "run_as_group": sc.run_as_group,
            "run_as_non_root": sc.run_as_non_root,
            "read_only_root_filesystem": sc.read_only_root_filesystem,
            "allow_privilege_escalation": sc.allow_privilege_escalation,
            "capabilities_add": list(sc.capabilities.add) if sc.capabilities and sc.capabilities.add else [],
            "capabilities_drop": list(sc.capabilities.drop) if sc.capabilities and sc.capabilities.drop else [],
            "seccomp_profile": sc.seccomp_profile.type if sc.seccomp_profile else None,
            "se_linux_options": {
                "level": sc.se_linux_options.level,
                "role": sc.se_linux_options.role,
                "type": sc.se_linux_options.type,
                "user": sc.se_linux_options.user
            } if sc.se_linux_options else None,
        }
    
    def _extract_pod_security_context(self, psc) -> dict:
        """Pod SecurityContext 추출"""
        if not psc:
            return {}
        return {
            "run_as_user": psc.run_as_user,
            "run_as_group": psc.run_as_group,
            "run_as_non_root": psc.run_as_non_root,
            "fs_group": psc.fs_group,
            "supplemental_groups": list(psc.supplemental_groups) if psc.supplemental_groups else [],
            "seccomp_profile": psc.seccomp_profile.type if psc.seccomp_profile else None,
            "se_linux_options": {
                "level": psc.se_linux_options.level,
                "role": psc.se_linux_options.role,
                "type": psc.se_linux_options.type,
                "user": psc.se_linux_options.user
            } if psc.se_linux_options else None,
            "sysctls": [{
                "name": s.name,
                "value": s.value
            } for s in (psc.sysctls or [])],
        }
    
    def _extract_volumes(self, volumes) -> list[dict]:
        """볼륨 정보 추출"""
        if not volumes:
            return []
        result = []
        for v in volumes:
            vol_info = {"name": v.name}
            if v.host_path:
                vol_info["type"] = "hostPath"
                vol_info["path"] = v.host_path.path
                vol_info["host_path_type"] = v.host_path.type
            elif v.secret:
                vol_info["type"] = "secret"
                vol_info["secret_name"] = v.secret.secret_name
                vol_info["optional"] = v.secret.optional
            elif v.config_map:
                vol_info["type"] = "configMap"
                vol_info["configmap_name"] = v.config_map.name
                vol_info["optional"] = v.config_map.optional
            elif v.persistent_volume_claim:
                vol_info["type"] = "pvc"
                vol_info["claim_name"] = v.persistent_volume_claim.claim_name
                vol_info["read_only"] = v.persistent_volume_claim.read_only
            elif v.empty_dir:
                vol_info["type"] = "emptyDir"
                vol_info["medium"] = v.empty_dir.medium
                vol_info["size_limit"] = v.empty_dir.size_limit
            elif v.projected:
                vol_info["type"] = "projected"
                vol_info["sources"] = len(v.projected.sources) if v.projected.sources else 0
            elif v.downward_api:
                vol_info["type"] = "downwardAPI"
            elif v.csi:
                vol_info["type"] = "csi"
                vol_info["driver"] = v.csi.driver
            else:
                vol_info["type"] = "other"
            result.append(vol_info)
        return result
    
    def _extract_affinity(self, affinity) -> Optional[dict]:
        """Affinity 추출"""
        if not affinity:
            return None
        result = {}
        if affinity.node_affinity:
            result["node_affinity"] = True
        if affinity.pod_affinity:
            result["pod_affinity"] = True
        if affinity.pod_anti_affinity:
            result["pod_anti_affinity"] = True
        return result if result else None
    
    def _get_secret_refs_from_env(self, container) -> list[str]:
        """환경변수에서 참조하는 시크릿 목록"""
        secret_refs = set()
        if container.env:
            for env in container.env:
                if env.value_from and env.value_from.secret_key_ref:
                    secret_refs.add(env.value_from.secret_key_ref.name)
        if container.env_from:
            for ef in container.env_from:
                if ef.secret_ref:
                    secret_refs.add(ef.secret_ref.name)
        return list(secret_refs)
    
    def _get_configmap_refs_from_env(self, container) -> list[str]:
        """환경변수에서 참조하는 ConfigMap 목록"""
        cm_refs = set()
        if container.env:
            for env in container.env:
                if env.value_from and env.value_from.config_map_key_ref:
                    cm_refs.add(env.value_from.config_map_key_ref.name)
        if container.env_from:
            for ef in container.env_from:
                if ef.config_map_ref:
                    cm_refs.add(ef.config_map_ref.name)
        return list(cm_refs)
    
    def _rule_to_dict(self, rule) -> dict:
        """RBAC Rule을 dict로 변환"""
        return {
            "verbs": list(rule.verbs or []),
            "api_groups": list(rule.api_groups or []),
            "resources": list(rule.resources or []),
            "resource_names": list(rule.resource_names or []),
            "non_resource_urls": list(rule.non_resource_ur_ls or []) if hasattr(rule, 'non_resource_ur_ls') else [],
        }
    
    def _subject_to_dict(self, subject) -> dict:
        """RBAC Subject를 dict로 변환"""
        return {
            "kind": subject.kind,
            "name": subject.name,
            "namespace": subject.namespace,
            "api_group": subject.api_group if hasattr(subject, 'api_group') else None,
        }
    
    def _np_ingress_to_dict(self, rule) -> dict:
        """NetworkPolicy Ingress Rule 변환"""
        return {
            "from": [self._np_peer_to_dict(p) for p in (rule._from or [])] if rule._from else [],
            "ports": [{
                "port": p.port,
                "protocol": p.protocol,
                "end_port": p.end_port
            } for p in (rule.ports or [])]
        }
    
    def _np_egress_to_dict(self, rule) -> dict:
        """NetworkPolicy Egress Rule 변환"""
        return {
            "to": [self._np_peer_to_dict(p) for p in (rule.to or [])] if rule.to else [],
            "ports": [{
                "port": p.port,
                "protocol": p.protocol,
                "end_port": p.end_port
            } for p in (rule.ports or [])]
        }
    
    def _np_peer_to_dict(self, peer) -> dict:
        """NetworkPolicy Peer 변환"""
        result = {}
        if peer.pod_selector:
            result["pod_selector"] = {
                "match_labels": peer.pod_selector.match_labels or {},
                "match_expressions": [{
                    "key": e.key,
                    "operator": e.operator,
                    "values": list(e.values or [])
                } for e in (peer.pod_selector.match_expressions or [])]
            }
        if peer.namespace_selector:
            result["namespace_selector"] = {
                "match_labels": peer.namespace_selector.match_labels or {},
                "match_expressions": [{
                    "key": e.key,
                    "operator": e.operator,
                    "values": list(e.values or [])
                } for e in (peer.namespace_selector.match_expressions or [])]
            }
        if peer.ip_block:
            result["ip_block"] = {
                "cidr": peer.ip_block.cidr,
                "except": list(peer.ip_block._except or []) if peer.ip_block._except else []
            }
        return result