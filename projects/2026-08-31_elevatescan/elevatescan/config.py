from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Set

DEFAULT_GLOBS: List[str] = [
    "*.md",
    "*.txt",
    "*.json",
    "*.jsonl",
    "*.yaml",
    "*.yml",
]

DEFAULT_MAX_FILES = 1000
DEFAULT_MAX_BYTES = 1024 * 1024  # 1 MiB


@dataclass
class Config:
    globs: List[str] = field(default_factory=lambda: list(DEFAULT_GLOBS))
    disabled_rules: Set[str] = field(default_factory=set)
    max_files: int = DEFAULT_MAX_FILES
    max_bytes: int = DEFAULT_MAX_BYTES
    strict: bool = False
    include_info: bool = False
