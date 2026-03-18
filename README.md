# deployguard-scanner

DeployGuard Scanner는 DeployGuard 시스템을 위한 다양한 보안 데이터
수집기(Security Data Collector)들을 포함하는 멀티 모듈 리포지토리입니다.

이 리포지토리는 Kubernetes 및 클라우드 환경에서 보안 관련 자산 정보를
수집하여 **DeployGuard Analysis Engine**으로 전달하는 역할을 합니다.

Scanner는 데이터 저장이나 분석을 수행하지 않으며, **팩트 수집(Fact
Collection)** 에만 집중합니다.

------------------------------------------------------------------------

# 멀티 모듈 구조 (Multi-module Structure)

이 리포지토리는 효율적인 관리와 일관된 계약(Contract) 유지를 위해 **멀티
모듈 구조**로 설계되었습니다.\
각 모듈은 독립적인 역할과 책임(Separation of Concerns)을 가지며 동일한
데이터 계약을 기반으로 Analysis Engine과 통신합니다.

에이전트 스캐너(`dg-k8s`, `dg-image`)는 **Helm Chart 형태로 Kubernetes
클러스터에 설치**되며, AWS 스캐너(`dg-aws`)는 **engine 측
docker-compose**로 실행됩니다.

------------------------------------------------------------------------

# 모듈별 역할

## dg-k8s

Kubernetes 클러스터의 리소스 상태 및 보안 관련 설정을 수집합니다.

수집 대상 예시:

-   Pod
-   ServiceAccount
-   Role / ClusterRole
-   RoleBinding / ClusterRoleBinding
-   Service
-   Ingress
-   Secret 메타데이터

수집된 데이터는 DeployGuard Analysis Engine API로 전송됩니다.

------------------------------------------------------------------------

## dg-aws

AWS의 보안 설정 및 권한 구조를 수집합니다.

수집 대상 예시:

-   IAM Role
-   IAM Policy
-   IRSA 매핑
-   S3 Bucket
-   RDS

클라우드 API를 통해 데이터를 조회한 뒤 Analysis Engine으로 전달합니다.

------------------------------------------------------------------------

## dg-image

컨테이너 이미지 보안 관련 정보를 수집합니다.

수집 대상 예시:

-   이미지 취약점(CVE)
-   이미지 메타데이터
-   베이스 이미지 정보

취약점 데이터는 Attack Path 분석을 위한 입력 데이터로 사용됩니다.

------------------------------------------------------------------------

## shared

모든 스캐너 모듈에서 공통으로 사용하는 **데이터 계약(Contracts)** 과
**스키마(Schema)** 를 정의합니다.

포함 내용:

-   이벤트 스키마
-   자산 데이터 구조
-   Analysis Engine API 요청 포맷

이 디렉토리는 **구현 코드 없이 인터페이스 정의만 포함**합니다.

------------------------------------------------------------------------

## docker

공통 Docker 빌드 설정을 위한 디렉토리입니다.

예:

-   공통 베이스 이미지
-   공통 빌드 설정

------------------------------------------------------------------------

# 기술 스택

DeployGuard Scanner는 **단일 언어 스택으로 Python을 사용합니다.**

Python을 사용하는 이유:

-   Kubernetes API 연동 용이
-   클라우드 SDK 활용 편리
-   보안 스캐닝 라이브러리 활용 가능
-   빠른 개발 및 확장성

------------------------------------------------------------------------

# 빌드 및 배포 (Build & Deployment)

에이전트 스캐너(`dg-k8s`, `dg-image`)는 **Helm Chart 형태로 Kubernetes
클러스터에 설치**됩니다. AWS 스캐너(`dg-aws`)는 Helm이 아니라
**docker-compose**로 배포됩니다.

배포 방식:

-   k8s + image 에이전트 스캐너: Helm을 통해 클러스터에 설치
-   aws 스캐너: engine 인프라에서 docker-compose로 실행
-   클러스터 내부 또는 engine 측에서 Analysis Engine API로 데이터 전송

예시:

    helm upgrade --install deployguard-scanner ./scanners/dg_k8s_image \
      --set clusterId=<registered-cluster-id> \
      --set api.existingSecret=<api-token-secret>

------------------------------------------------------------------------

# 아키텍처 역할

DeployGuard 전체 아키텍처에서 Scanner의 역할은 다음과 같습니다.

    Kubernetes / Cloud Environment
                ↓
            Scanner
                ↓
         Analysis Engine
                ↓
            PostgreSQL
                ↓
             Dashboard

Scanner는 **환경의 보안 상태를 수집하는 역할만 수행하며 데이터 저장이나
분석 로직을 포함하지 않습니다.**

------------------------------------------------------------------------

# 개발 시작하기 (Development)

상위 레벨 작업을 위한 `Makefile`이 제공됩니다.

    make build
    make test
    make lint
    make docker-build

각 모듈은 독립적으로 개발 및 테스트가 가능합니다.

------------------------------------------------------------------------

# 설계 원칙

DeployGuard Scanner는 다음 원칙을 따릅니다.

-   Scanner는 **데이터 수집 전용 컴포넌트**
-   분석 로직은 **Analysis Engine에서만 수행**
-   Scanner는 **DB에 직접 접근하지 않음**
-   모든 데이터는 **Analysis API를 통해 전달**
-   모듈 간 **공통 데이터 계약(shared)** 유지
