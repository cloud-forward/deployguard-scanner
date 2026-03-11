import os
from dataclasses import dataclass, field
from typing import List, Optional

@dataclass
class ScannerConfig:
    cluster_id: str = os.getenv("CLUSTER_ID", "unknown-cluster")
    cluster_name: str = os.getenv("CLUSTER_NAME", "unknown")
    output_dir: str = os.getenv("OUTPUT_DIR", "./output")
    namespaces: List[str] = field(default_factory=list)
    exclude_namespaces: List[str] = field(default_factory=lambda: ["kube-system", "kube-public", "kube-node-lease"])
    trivy_severity: str = os.getenv("TRIVY_SEVERITY", "HIGH,CRITICAL")
    trivy_timeout: str = os.getenv("TRIVY_TIMEOUT", "5m")
    max_images_per_scan: int = int(os.getenv("MAX_IMAGES_PER_SCAN", "50"))
