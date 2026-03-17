from __future__ import annotations

from typing import TypeVar

T = TypeVar("T")


def load_config(config_cls: type[T]) -> T:
    return config_cls.from_env()
