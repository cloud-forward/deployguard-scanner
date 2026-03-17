# DeployGuard Scanner

Kubernetes 클러스터 보안 스캐너

## 기능

- **K8s 리소스 수집**: Pod, Deployment, Service, Ingress, RBAC, NetworkPolicy 등
- **이미지 취약점 스캔**: Trivy 기반 CVE 탐지
- **보안 설정 분석**: privileged, hostNetwork, dangerous capabilities 등

## 환경변수

| 변수 | 필수 | 설명 |
|------|------|------|
| `DG_CLUSTER_ID` 또는 `CLUSTER_ID` | ✅ | 클러스터 식별자 |
| `DG_CLUSTER_NAME` 또는 `CLUSTER_NAME` | | 클러스터 이름 |
| `DG_API_ENDPOINT`, `DG_API_URL`, `DG_ENGINE_URL`, `API_URL` | ✅ | DeployGuard API 엔드포인트 |
| `DG_API_TOKEN` 또는 `API_TOKEN` | ✅ | API 인증 토큰 |
| `DG_SCANNER_TYPE` | | 스캐너 타입 (`k8s`, `image`, `all`) |
| `DG_TRIVY_SEVERITY` | | Trivy 스캔 심각도 |
| `DG_NAMESPACES` | | 스캔할 네임스페이스 (쉼표 구분) |
| `DG_EXCLUDE_NAMESPACES` | | 제외할 네임스페이스 |

기본 예시 엔드포인트: `https://analysis.deployguard.org`

## 로컬 테스트

```bash
make test
