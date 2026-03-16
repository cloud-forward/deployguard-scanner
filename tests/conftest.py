from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


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
    package_name = "deployguard_testpkg"
    _ensure_package(package_name, ROOT)
    _ensure_package(f"{package_name}.shared", ROOT / "shared")
    _load_module(f"{package_name}.config", ROOT / "config.py")
    return _load_module(f"{package_name}.{name}", ROOT / f"{name}.py")


def load_scanner_src_module(name: str):
    package_name = "deployguard_scanner_testpkg"
    _ensure_package(package_name, ROOT / "scanner")
    _ensure_package(f"{package_name}.src", ROOT / "scanner" / "src")
    _load_module(f"{package_name}.src.config", ROOT / "scanner" / "src" / "config.py")
    return _load_module(f"{package_name}.src.{name}", ROOT / "scanner" / "src" / f"{name}.py")


def load_scanner_module(name: str):
    package_name = "deployguard_scanner_testpkg"
    _ensure_package(package_name, ROOT / "scanner")
    _ensure_package(f"{package_name}.src", ROOT / "scanner" / "src")
    _load_module(f"{package_name}.src.config", ROOT / "scanner" / "src" / "config.py")
    _load_module(f"{package_name}.src.api_client", ROOT / "scanner" / "src" / "api_client.py")
    return _load_module(f"{package_name}.{name}", ROOT / "scanner" / f"{name}.py")


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
