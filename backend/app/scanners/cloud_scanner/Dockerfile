# ── build stage ──────────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# 시스템 의존성 (botocore 빌드용)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.12-slim

# non-root 사용자
RUN useradd -r -u 1000 -g root scanner

WORKDIR /app

# 빌드 결과물 복사
COPY --from=builder /install /usr/local

# 소스 복사
COPY shared/       ./shared/
COPY deployguard_aws_scanner/ ./deployguard_aws_scanner/

# output 디렉토리
RUN mkdir -p /app/output && chown scanner:root /app/output

USER scanner

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# 기본 실행: scheduled 모드 (Helm CronJob / Deployment 모두 호환)
ENTRYPOINT ["python", "-m", "deployguard_aws_scanner.main"]
CMD ["scheduled"]
