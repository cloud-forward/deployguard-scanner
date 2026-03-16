# DeployGuard Scanner

Kubernetes 클러스터 보안 스캐너

## 기능

- **K8s 리소스 수집**: Pod, Deployment, Service, Ingress, RBAC, NetworkPolicy 등
- **이미지 취약점 스캔**: Trivy 기반 CVE 탐지
- **보안 설정 분석**: privileged, hostNetwork, dangerous capabilities 등

## 환경변수

| 변수 | 필수 | 설명 |
|------|------|------|
| `CLUSTER_ID` | ✅ | 클러스터 식별자 |
| `CLUSTER_NAME` | | 클러스터 이름 (기본: default) |
| `API_ENDPOINT` | ✅ | Analysis Engine API 주소 |
| `API_KEY` | ✅ | API 인증 키 |
| `ENABLE_IMAGE_SCAN` | | 이미지 스캔 활성화 (기본: true) |
| `TRIVY_SEVERITY` | | 스캔 심각도 (기본: CRITICAL,HIGH,MEDIUM) |
| `SCAN_NAMESPACES` | | 스캔할 네임스페이스 (쉼표 구분) |
| `EXCLUDE_NAMESPACES` | | 제외할 네임스페이스 |
| `S3_BUCKET` | | S3 버킷 (직접 업로드 시) |
| `S3_REGION` | | S3 리전 (기본: ap-northeast-2) |

## 로컬 테스트

```bash
make test