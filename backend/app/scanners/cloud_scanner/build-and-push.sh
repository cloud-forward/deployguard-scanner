#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# build-and-push.sh
# Docker 이미지를 빌드하고 AWS ECR에 푸시합니다.
#
# 사용법:
#   ./build-and-push.sh [TAG]
#   TAG 생략 시 git short SHA 또는 "latest" 사용
#
# 필수 환경 변수:
#   AWS_REGION          예) ap-northeast-2
#   AWS_ACCOUNT_ID      예) 123456789012
#   ECR_REPO_NAME       예) deployguard-aws-scanner   (기본값)
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── 설정 ──────────────────────────────────────────────────────────────────────
AWS_REGION="${AWS_REGION:-ap-northeast-2}"
AWS_ACCOUNT_ID="${AWS_ACCOUNT_ID:?AWS_ACCOUNT_ID 환경 변수를 설정하세요 (예: 123456789012)}"
ECR_REPO_NAME="${ECR_REPO_NAME:-deployguard-aws-scanner}"
IMAGE_TAG="${1:-$(git rev-parse --short HEAD 2>/dev/null || echo "latest")}"

ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
IMAGE_URI="${ECR_REGISTRY}/${ECR_REPO_NAME}:${IMAGE_TAG}"
IMAGE_URI_LATEST="${ECR_REGISTRY}/${ECR_REPO_NAME}:latest"

echo "────────────────────────────────────────"
echo " Region  : ${AWS_REGION}"
echo " Account : ${AWS_ACCOUNT_ID}"
echo " Repo    : ${ECR_REPO_NAME}"
echo " Tag     : ${IMAGE_TAG}"
echo " URI     : ${IMAGE_URI}"
echo "────────────────────────────────────────"

# ── 1. ECR 리포지토리 생성 (이미 있으면 무시) ─────────────────────────────────
echo "[1/4] ECR 리포지토리 확인/생성..."
aws ecr describe-repositories \
    --repository-names "${ECR_REPO_NAME}" \
    --region "${AWS_REGION}" > /dev/null 2>&1 \
|| aws ecr create-repository \
    --repository-name "${ECR_REPO_NAME}" \
    --region "${AWS_REGION}" \
    --image-scanning-configuration scanOnPush=true \
    --image-tag-mutability MUTABLE

# ── 2. ECR 로그인 ──────────────────────────────────────────────────────────────
echo "[2/4] ECR 로그인..."
aws ecr get-login-password --region "${AWS_REGION}" \
    | docker login --username AWS --password-stdin "${ECR_REGISTRY}"

# ── 3. 이미지 빌드 ─────────────────────────────────────────────────────────────
echo "[3/4] Docker 이미지 빌드..."
docker build \
    --platform linux/amd64 \
    -t "${IMAGE_URI}" \
    -t "${IMAGE_URI_LATEST}" \
    .

# ── 4. ECR 푸시 ───────────────────────────────────────────────────────────────
echo "[4/4] ECR 푸시..."
docker push "${IMAGE_URI}"
docker push "${IMAGE_URI_LATEST}"

echo ""
echo "✅ 완료!"
echo "   Image URI : ${IMAGE_URI}"
echo ""
echo "Helm 배포 시 values.yaml에 아래 값을 사용하세요:"
echo "   image.repository: ${ECR_REGISTRY}/${ECR_REPO_NAME}"
echo "   image.tag:        ${IMAGE_TAG}"
