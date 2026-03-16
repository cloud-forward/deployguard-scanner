"""DeployGuard Scanner - 메인 진입점"""
import sys
import os
import json
import logging
from datetime import datetime

from .config import Config
from .scanners.k8s_scanner import K8sScanner
from .scanners.image_scanner import ImageScanner
from .exporters.api_exporter import APIExporter
from .models.schemas import ScanResult, ScanMetadata

# 로깅 설정
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)


def main():
    """메인 실행"""
    start_time = datetime.utcnow()
    
    logger.info("=" * 70)
    logger.info("  DeployGuard Scanner Starting")
    logger.info("=" * 70)
    
    # 설정 로드
    config = Config.from_env()
    
    # 설정 검증
    errors = config.validate()
    if errors:
        for err in errors:
            logger.error(f"Config error: {err}")
        logger.info("Tip: Set CLUSTER_ID, API_KEY, API_ENDPOINT environment variables")
        sys.exit(1)
    
    # 설정 로깅 (민감정보 마스킹)
    logger.info(f"Configuration: {config.to_dict()}")
    
    # 메타데이터 생성
    metadata = ScanMetadata.create(
        cluster_id=config.cluster_id,
        cluster_name=config.cluster_name
    )
    logger.info(f"Scan ID: {metadata.scan_id}")
    logger.info("")
    
    # ========== Phase 1: K8s 스캔 ==========
    logger.info("=" * 70)
    logger.info("  Phase 1: Kubernetes Resource Collection")
    logger.info("=" * 70)
    
    k8s_scanner = K8sScanner(config)
    k8s_resources = k8s_scanner.scan()
    
    # 이미지 목록 추출
    images = []
    image_to_workloads: dict[str, list[str]] = {}
    
    for workload in k8s_resources.workloads:
        for img in workload.images:
            images.append(img)
            workload_id = f"{workload.namespace}/{workload.kind}/{workload.name}"
            if img not in image_to_workloads:
                image_to_workloads[img] = []
            image_to_workloads[img].append(workload_id)
    
    # ========== Phase 2: 이미지 스캔 ==========
    logger.info("")
    logger.info("=" * 70)
    logger.info("  Phase 2: Image Vulnerability Scanning")
    logger.info("=" * 70)
    
    image_results = []
    if config.enable_image_scan:
        image_scanner = ImageScanner(config)
        image_results = image_scanner.scan_images(images, image_to_workloads)
    else:
        logger.info("Image scanning disabled by configuration")
    
    # 결과 조합
    scan_result = ScanResult(
        metadata=metadata,
        k8s=k8s_resources,
        images=image_results
    )
    
    # ========== 통계 출력 ==========
    stats = scan_result.get_statistics()
    logger.info("")
    logger.info("=" * 70)
    logger.info("  Scan Statistics")
    logger.info("=" * 70)
    logger.info(f"  Namespaces:          {stats['namespaces']}")
    logger.info(f"  Nodes:               {stats['nodes']}")
    logger.info(f"  Workloads:           {stats['workloads']}")
    if stats.get('workload_breakdown'):
        for kind, count in stats['workload_breakdown'].items():
            logger.info(f"    - {kind}: {count}")
    logger.info(f"  Services:            {stats['services']}")
    logger.info(f"  Ingresses:           {stats['ingresses']}")
    logger.info(f"  ServiceAccounts:     {stats['service_accounts']}")
    logger.info(f"  Secrets:             {stats['secrets']}")
    logger.info(f"  ConfigMaps:          {stats['configmaps']}")
    logger.info(f"  RBAC Rules:          {stats['rbac_rules']}")
    logger.info(f"  Network Policies:    {stats['network_policies']}")
    logger.info(f"  PersistentVolumes:   {stats['persistent_volumes']}")
    logger.info(f"  PVCs:                {stats['persistent_volume_claims']}")
    logger.info(f"  LimitRanges:         {stats['limit_ranges']}")
    logger.info(f"  ResourceQuotas:      {stats['resource_quotas']}")
    logger.info(f"  Images Scanned:      {stats['images_scanned']}")
    if stats['images_scanned'] > 0:
        logger.info(f"  Vulnerabilities:")
        for sev, count in stats['vulnerabilities'].items():
            if count > 0:
                logger.info(f"    - {sev}: {count}")
        logger.info(f"  Total Vulnerabilities: {stats['total_vulnerabilities']}")
    
    # ========== Phase 3: 결과 전송 ==========
    logger.info("")
    logger.info("=" * 70)
    logger.info("  Phase 3: Exporting Results")
    logger.info("=" * 70)
    
    # API 전송
    exporter = APIExporter(config)
    success = exporter.export(scan_result)
    
    if success:
        logger.info("API Export: SUCCESS")
    else:
        logger.error("API Export: FAILED")
        
        # 실패 시 로컬 백업
        if config.save_local:
            try:
                os.makedirs(config.local_output_dir, exist_ok=True)
                backup_path = os.path.join(
                    config.local_output_dir, 
                    f"scan_{metadata.scan_id}.json"
                )
                with open(backup_path, 'w', encoding='utf-8') as f:
                    json.dump(scan_result.to_dict(), f, default=str, indent=2, ensure_ascii=False)
                logger.info(f"Local backup saved: {backup_path}")
            except Exception as e:
                logger.error(f"Failed to save local backup: {e}")
    
    # ========== 완료 ==========
    duration = (datetime.utcnow() - start_time).total_seconds()
    logger.info("")
    logger.info("=" * 70)
    logger.info(f"  Scan completed in {duration:.1f} seconds")
    logger.info(f"  Status: {'SUCCESS' if success else 'FAILED'}")
    logger.info("=" * 70)
    
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()