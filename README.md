# deployguard-scanner

DeployGuard Scanner는 DeployGuard 시스템을 위한 다양한 보안 데이터 수집기(Security Data Collector)들을 포함하는 멀티 모듈 리포지토리입니다.

## 멀티 모듈 구조 (Multi-module Structure)

이 리포지토리는 효율적인 관리와 일관된 계약(Contract) 유지를 위해 멀티 모듈 구조로 설계되었습니다. 각 모듈은 독립적인 역할과 책임(Separation of Concerns)을 가지며, 사용되는 기술 스택이 다를 수 있습니다.

### 모듈별 역할

- **dg-runtime** (Go): DaemonSet 형태로 배포되어 런타임 보안 데이터를 수집합니다.
- **dg-k8s** (Go): Watcher 또는 CronJob 형태로 실행되며 Kubernetes 리소스 상태 및 설정 데이터를 수집합니다.
- **dg-cloud** (Python): 클라우드 인프라(AWS, GCP, Azure 등) API를 통해 보안 설정을 수집합니다.
- **dg-image** (Python): 컨테이너 이미지 취약점 및 설정 데이터를 수집합니다.
- **shared**: 모든 모듈에서 공통으로 사용되는 계약(Contracts) 및 스키마(Schemas)를 정의합니다. (구현 코드 제외)
- **docker**: 모듈 간 공유되는 빌드 설정 및 베이스 이미지를 위한 플레이스홀더 디렉토리입니다.

## 언어 스택 (Language Split)

성능과 생태계의 적합성에 따라 두 가지 언어를 사용합니다:

- **Go**: 고성능 및 저수준 시스템 접근이 필요한 런타임 및 Kubernetes 인터페이스 모듈에 사용됩니다.
- **Python**: 방대한 라이브러리와 API 연동 편의성이 필요한 클라우드 및 이미지 분석 모듈에 사용됩니다.

## 빌드 및 배포 (Build & Deployment)

- **독립적 빌드**: 각 모듈은 독립적인 Docker 이미지로 빌드될 수 있도록 구성됩니다.
- **배포**: 각 모듈은 Helm 차트 또는 Kubernetes 매니페스트를 통해 독립적으로 배포됩니다. (본 리포지토리에는 매니페스트가 포함되지 않습니다.)

## 시작하기 (Development)

상위 레벨의 작업을 위해 `Makefile`이 제공됩니다:

```bash
make build
make test
make lint
make docker-build
```
