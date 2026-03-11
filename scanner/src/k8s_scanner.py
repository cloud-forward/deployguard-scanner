"""DeployGuard K8s Scanner - K8s 리소스 수집"""

from typing import Any, Dict, List
from kubernetes import client, config
from .config import ScannerConfig
from .utils import generate_scan_id, get_timestamp, save_json


class K8sScanner:
    def __init__(self, scanner_config: ScannerConfig = None):
        self.config = scanner_config or ScannerConfig()
        self.scan_id = generate_scan_id()
        self.scan_time = get_timestamp()
        self._init_k8s_client()

    def _init_k8s_client(self):
        try:
            config.load_incluster_config()
            print("[+] Loaded in-cluster config")
        except config.ConfigException:
            config.load_kube_config()
            print("[+] Loaded kubeconfig")
        self.core_v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()
        self.networking_v1 = client.NetworkingV1Api()

    def _should_scan_namespace(self, namespace: str) -> bool:
        if namespace in self.config.exclude_namespaces:
            return False
        if self.config.namespaces and namespace not in self.config.namespaces:
            return False
        return True

    def scan(self) -> Dict[str, Any]:
        print(f"\n[*] Starting K8s scan: {self.scan_id}")
        result = {
            "scan_id": self.scan_id,
            "scan_type": "k8s",
            "cluster_id": self.config.cluster_id,
            "cluster_name": self.config.cluster_name,
            "scanned_at": self.scan_time,
            "resources": {},
            "summary": {},
            "errors": []
        }

        collectors = [
            ("namespaces", self._collect_namespaces),
            ("pods", self._collect_pods),
            ("services", self._collect_services),
            ("service_accounts", self._collect_service_accounts),
            ("secrets", self._collect_secrets),
            ("roles", self._collect_roles),
            ("cluster_roles", self._collect_cluster_roles),
            ("role_bindings", self._collect_role_bindings),
            ("cluster_role_bindings", self._collect_cluster_role_bindings),
            ("ingresses", self._collect_ingresses),
            ("network_policies", self._collect_network_policies),
        ]

        for resource_type, collector in collectors:
            try:
                print(f"[*] Collecting {resource_type}...")
                result["resources"][resource_type] = collector()
                print(f"    Found {len(result['resources'][resource_type])}")
            except Exception as e:
                print(f"[-] Failed: {resource_type}: {e}")
                result["errors"].append(str(e))
                result["resources"][resource_type] = []

        result["summary"] = self._generate_summary(result["resources"])
        return result

    def _collect_namespaces(self) -> List[Dict]:
        items = []
        for ns in self.core_v1.list_namespace().items:
            if not self._should_scan_namespace(ns.metadata.name):
                continue
            items.append({
                "name": ns.metadata.name,
                "labels": ns.metadata.labels or {},
                "status": ns.status.phase,
            })
        return items

    def _collect_pods(self) -> List[Dict]:
        items = []
        for pod in self.core_v1.list_pod_for_all_namespaces().items:
            if not self._should_scan_namespace(pod.metadata.namespace):
                continue
            containers = []
            for c in (pod.spec.containers or []):
                sc = c.security_context
                containers.append({
                    "name": c.name,
                    "image": c.image,
                    "security_context": {
                        "privileged": sc.privileged if sc else None,
                        "run_as_user": sc.run_as_user if sc else None,
                        "run_as_non_root": sc.run_as_non_root if sc else None,
                        "allow_privilege_escalation": sc.allow_privilege_escalation if sc else None,
                        "read_only_root_filesystem": sc.read_only_root_filesystem if sc else None,
                        "capabilities": {"add": sc.capabilities.add, "drop": sc.capabilities.drop} if sc and sc.capabilities else None,
                    } if sc else None,
                    "ports": [{"container_port": p.container_port, "host_port": p.host_port} for p in (c.ports or [])],
                    "volume_mounts": [{"name": vm.name, "mount_path": vm.mount_path, "read_only": vm.read_only} for vm in (c.volume_mounts or [])],
                })
            
            volumes = []
            for v in (pod.spec.volumes or []):
                vol_info = {"name": v.name, "type": None, "source": None}
                if v.secret:
                    vol_info["type"] = "secret"
                    vol_info["source"] = v.secret.secret_name
                elif v.config_map:
                    vol_info["type"] = "configmap"
                    vol_info["source"] = v.config_map.name
                elif v.host_path:
                    vol_info["type"] = "hostPath"
                    vol_info["source"] = v.host_path.path
                volumes.append(vol_info)

            items.append({
                "namespace": pod.metadata.namespace,
                "name": pod.metadata.name,
                "labels": pod.metadata.labels or {},
                "service_account": pod.spec.service_account_name,
                "automount_service_account_token": pod.spec.automount_service_account_token,
                "host_network": pod.spec.host_network,
                "host_pid": pod.spec.host_pid,
                "host_ipc": pod.spec.host_ipc,
                "containers": containers,
                "volumes": volumes,
                "phase": pod.status.phase,
                "node_name": pod.spec.node_name,
            })
        return items

    def _collect_services(self) -> List[Dict]:
        items = []
        for svc in self.core_v1.list_service_for_all_namespaces().items:
            if not self._should_scan_namespace(svc.metadata.namespace):
                continue
            items.append({
                "namespace": svc.metadata.namespace,
                "name": svc.metadata.name,
                "type": svc.spec.type,
                "cluster_ip": svc.spec.cluster_ip,
                "selector": svc.spec.selector or {},
                "ports": [{"port": p.port, "target_port": str(p.target_port), "node_port": p.node_port, "protocol": p.protocol} for p in (svc.spec.ports or [])],
            })
        return items

    def _collect_service_accounts(self) -> List[Dict]:
        items = []
        for sa in self.core_v1.list_service_account_for_all_namespaces().items:
            if not self._should_scan_namespace(sa.metadata.namespace):
                continue
            annotations = sa.metadata.annotations or {}
            items.append({
                "namespace": sa.metadata.namespace,
                "name": sa.metadata.name,
                "automount_service_account_token": sa.automount_service_account_token,
                "secrets": [s.name for s in (sa.secrets or [])],
                "irsa_role_arn": annotations.get("eks.amazonaws.com/role-arn"),
            })
        return items

    def _collect_secrets(self) -> List[Dict]:
        items = []
        sensitive_keywords = ["password", "token", "key", "secret", "cred", "auth", "api"]
        for secret in self.core_v1.list_secret_for_all_namespaces().items:
            if not self._should_scan_namespace(secret.metadata.namespace):
                continue
            data_keys = list(secret.data.keys()) if secret.data else []
            is_sensitive = any(kw in secret.metadata.name.lower() or any(kw in k.lower() for k in data_keys) for kw in sensitive_keywords)
            items.append({
                "namespace": secret.metadata.namespace,
                "name": secret.metadata.name,
                "type": secret.type,
                "data_keys": data_keys,
                "is_sensitive": is_sensitive,
            })
        return items

    def _collect_roles(self) -> List[Dict]:
        items = []
        for role in self.rbac_v1.list_role_for_all_namespaces().items:
            if not self._should_scan_namespace(role.metadata.namespace):
                continue
            items.append({
                "namespace": role.metadata.namespace,
                "name": role.metadata.name,
                "rules": [{"api_groups": r.api_groups or [], "resources": r.resources or [], "verbs": r.verbs or []} for r in (role.rules or [])],
            })
        return items

    def _collect_cluster_roles(self) -> List[Dict]:
        items = []
        for cr in self.rbac_v1.list_cluster_role().items:
            if cr.metadata.name.startswith("system:"):
                continue
            rules = [{"api_groups": r.api_groups or [], "resources": r.resources or [], "verbs": r.verbs or []} for r in (cr.rules or [])]
            has_wildcard = any("*" in r["api_groups"] or "*" in r["resources"] or "*" in r["verbs"] for r in rules)
            items.append({
                "name": cr.metadata.name,
                "rules": rules,
                "has_wildcard_permissions": has_wildcard,
            })
        return items

    def _collect_role_bindings(self) -> List[Dict]:
        items = []
        for rb in self.rbac_v1.list_role_binding_for_all_namespaces().items:
            if not self._should_scan_namespace(rb.metadata.namespace):
                continue
            items.append({
                "namespace": rb.metadata.namespace,
                "name": rb.metadata.name,
                "role_ref": {"kind": rb.role_ref.kind, "name": rb.role_ref.name},
                "subjects": [{"kind": s.kind, "name": s.name, "namespace": s.namespace} for s in (rb.subjects or [])],
            })
        return items

    def _collect_cluster_role_bindings(self) -> List[Dict]:
        items = []
        for crb in self.rbac_v1.list_cluster_role_binding().items:
            if crb.metadata.name.startswith("system:"):
                continue
            items.append({
                "name": crb.metadata.name,
                "role_ref": {"kind": crb.role_ref.kind, "name": crb.role_ref.name},
                "subjects": [{"kind": s.kind, "name": s.name, "namespace": s.namespace} for s in (crb.subjects or [])],
                "is_cluster_admin": crb.role_ref.name == "cluster-admin",
            })
        return items

    def _collect_ingresses(self) -> List[Dict]:
        items = []
        try:
            for ing in self.networking_v1.list_ingress_for_all_namespaces().items:
                if not self._should_scan_namespace(ing.metadata.namespace):
                    continue
                rules = []
                for rule in (ing.spec.rules or []):
                    paths = []
                    if rule.http:
                        for p in (rule.http.paths or []):
                            paths.append({
                                "path": p.path,
                                "backend_service": p.backend.service.name if p.backend and p.backend.service else None,
                                "backend_port": p.backend.service.port.number if p.backend and p.backend.service and p.backend.service.port else None,
                            })
                    rules.append({"host": rule.host, "paths": paths})
                items.append({
                    "namespace": ing.metadata.namespace,
                    "name": ing.metadata.name,
                    "rules": rules,
                })
        except Exception:
            pass
        return items

    def _collect_network_policies(self) -> List[Dict]:
        items = []
        try:
            for np in self.networking_v1.list_network_policy_for_all_namespaces().items:
                if not self._should_scan_namespace(np.metadata.namespace):
                    continue
                items.append({
                    "namespace": np.metadata.namespace,
                    "name": np.metadata.name,
                    "pod_selector": np.spec.pod_selector.match_labels if np.spec.pod_selector else {},
                    "policy_types": np.spec.policy_types or [],
                })
        except Exception:
            pass
        return items

    def _generate_summary(self, resources: Dict) -> Dict:
        summary = {"total_resources": 0, "by_type": {}, "security_indicators": {
            "privileged_pods": 0, "host_network_pods": 0, "host_pid_pods": 0,
            "cluster_admin_bindings": 0, "wildcard_cluster_roles": 0, "sensitive_secrets": 0,
        }}
        for rtype, items in resources.items():
            summary["by_type"][rtype] = len(items)
            summary["total_resources"] += len(items)
        
        for pod in resources.get("pods", []):
            for c in pod.get("containers", []):
                if c.get("security_context", {}) and c["security_context"].get("privileged"):
                    summary["security_indicators"]["privileged_pods"] += 1
                    break
            if pod.get("host_network"):
                summary["security_indicators"]["host_network_pods"] += 1
            if pod.get("host_pid"):
                summary["security_indicators"]["host_pid_pods"] += 1
        
        for crb in resources.get("cluster_role_bindings", []):
            if crb.get("is_cluster_admin"):
                summary["security_indicators"]["cluster_admin_bindings"] += 1
        
        for cr in resources.get("cluster_roles", []):
            if cr.get("has_wildcard_permissions"):
                summary["security_indicators"]["wildcard_cluster_roles"] += 1
        
        for secret in resources.get("secrets", []):
            if secret.get("is_sensitive"):
                summary["security_indicators"]["sensitive_secrets"] += 1
        
        return summary
