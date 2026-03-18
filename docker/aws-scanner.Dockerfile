FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim

RUN useradd -r -u 1000 -g root scanner

WORKDIR /app

COPY --from=builder /install /usr/local

COPY backend/ ./backend/
COPY shared/ ./shared/

RUN mkdir -p /app/output && chown scanner:root /app/output

USER scanner

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

ENTRYPOINT ["python", "-m", "backend.app.scanners.cloud_scanner.main"]
CMD ["scheduled"]
