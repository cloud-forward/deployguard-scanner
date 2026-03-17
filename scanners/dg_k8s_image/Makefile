.PHONY: help install test lint scan-k8s scan-image scan-all build push clean

CLUSTER_ID ?= test-cluster
API_URL ?= https://analysis.deployguard.org
IMAGE_NAME ?= deployguard-scanner
IMAGE_TAG ?= latest

help:
	@echo "DeployGuard Scanner"
	@echo ""
	@echo "Usage:"
	@echo "  make install      - 의존성 설치"
	@echo "  make scan-k8s     - K8s 스캔 실행"
	@echo "  make scan-image   - Image 스캔 실행"
	@echo "  make scan-all     - 전체 스캔 실행"
	@echo "  make build        - Docker 이미지 빌드"
	@echo "  make test         - 테스트 실행"
	@echo "  make lint         - 린트 체크"
	@echo "  make clean        - 정리"

install:
	pip install -r requirements.txt

scan-k8s:
	CLUSTER_ID=$(CLUSTER_ID) API_URL=$(API_URL) DG_SCANNER_TYPE=k8s python -m scanners.dg_k8s_image.scan scheduled

scan-image:
	CLUSTER_ID=$(CLUSTER_ID) API_URL=$(API_URL) DG_SCANNER_TYPE=image python -m scanners.dg_k8s_image.scan scheduled

scan-all:
	CLUSTER_ID=$(CLUSTER_ID) API_URL=$(API_URL) DG_SCANNER_TYPE=all python -m scanners.dg_k8s_image.scan scheduled

scan-manual:
	CLUSTER_ID=$(CLUSTER_ID) API_URL=$(API_URL) python -m scanners.dg_k8s_image.scan manual

build:
	docker build -f ../../docker/dg-k8s-image.Dockerfile -t $(IMAGE_NAME):$(IMAGE_TAG) ../..

push:
	docker push $(IMAGE_NAME):$(IMAGE_TAG)

test:
	python -m pytest tests/ -v

lint:
	python -m flake8 src/ scan.py
	python -m mypy src/ scan.py --ignore-missing-imports

clean:
	rm -rf output/*.json
	rm -rf __pycache__ src/__pycache__
	rm -rf .pytest_cache .mypy_cache
	find . -name "*.pyc" -delete
