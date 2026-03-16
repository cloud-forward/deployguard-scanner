from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
AWS_ROOT = ROOT / "backend" / "app" / "scanners" / "cloud_scanner"
K8S_IMAGE_ROOT = ROOT / "scanners" / "dg_k8s_image"


def _ensure_package(name: str, path: Path) -> types.ModuleType:
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        module.__path__ = [str(path)]
        sys.modules[name] = module
    return module


def _load_module(module_name: str, path: Path):
    module = sys.modules.get(module_name)
    if module is not None:
        return module

    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load module {module_name} from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def load_root_module(name: str):
    return importlib.import_module(f"backend.app.scanners.cloud_scanner.{name}")


def load_scanner_src_module(name: str):
    return importlib.import_module(f"scanners.dg_k8s_image.src.{name}")


def load_scanner_module(name: str):
    return importlib.import_module(f"scanners.dg_k8s_image.{name}")


class Response:
    def __init__(self, status_code: int, payload=None, text: str = "") -> None:
        self.status_code = status_code
        self._payload = payload if payload is not None else {}
        self.text = text

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def clear_env(monkeypatch: pytest.MonkeyPatch):
    for name in [
        "DG_CLUSTER_ID",
        "CLUSTER_ID",
        "AWS_REGION",
        "DG_REGION",
        "API_URL",
        "DG_API_URL",
        "DG_ENGINE_URL",
        "DG_API_TOKEN",
        "API_TOKEN",
        "DG_SCAN_POLL_PATH",
        "DG_SCANNER_TYPE",
        "DG_SAVE_LOCAL_COPY",
        "DG_NAMESPACES",
        "DG_EXCLUDE_NAMESPACES",
        "DG_INCLUDE_SYSTEM_NAMESPACES",
        "DG_TRIVY_ENABLED",
        "DG_MAX_IMAGES_PER_SCAN",
    ]:
        monkeypatch.delenv(name, raising=False)
