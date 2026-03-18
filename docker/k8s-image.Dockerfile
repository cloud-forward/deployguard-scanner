FROM python:3.11-slim

# Trivy 설치
ARG TRIVY_VERSION=0.50.0

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    tar \
    gzip \
    && curl -fsSL -o /tmp/trivy.tar.gz \
      https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /tmp \
    && mv /tmp/trivy /usr/local/bin/trivy \
    && chmod +x /usr/local/bin/trivy \
    && trivy --version \
    && rm -f /tmp/trivy.tar.gz \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 의존성 설치
COPY scanners/dg_k8s_image/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# 소스 코드 복사
COPY scanners/dg_k8s_image/ ./scanners/dg_k8s_image/
COPY shared/ ./shared/

# Trivy DB 미리 다운로드
RUN trivy image --download-db-only || true

# 출력 디렉토리
RUN mkdir -p /app/output

ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app

ENTRYPOINT ["python", "-m", "scanners.dg_k8s_image.scan"]
CMD ["worker"]
