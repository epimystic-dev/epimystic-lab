"""Runtime configuration for agentmdlint. Defaults are chosen conservatively."""

from dataclasses import dataclass, field
from datetime import date
from typing import List, Optional, Tuple

DEFAULT_FILES: Tuple[str, ...] = (
    "AGENTS.md",
    "AGENT.md",
    "CLAUDE.md",
    "GEMINI.md",
    "CURSOR.md",
    "AI_INSTRUCTIONS.md",
    "ASSISTANT.md",
    ".cursorrules",
    ".cursorrules.md",
    ".github/copilot-instructions.md",
)

DEFAULT_SOFT_BYTES = 20000
DEFAULT_HARD_BYTES = 60000
DEFAULT_SOFT_INSTRUCTIONS = 100
DEFAULT_HARD_INSTRUCTIONS = 300
DEFAULT_DUPLICATE_THRESHOLD = 0.85
DEFAULT_MIN_SECTION_TOKENS = 10
DEFAULT_STALE_DAYS = 730
DEFAULT_WALL_LENGTH = 7
DEFAULT_MAX_FILES = 40
DEFAULT_MAX_BYTES = 1_048_576  # 1 MiB


@dataclass
class Config:
    files: Tuple[str, ...] = DEFAULT_FILES
    soft_bytes: int = DEFAULT_SOFT_BYTES
    hard_bytes: int = DEFAULT_HARD_BYTES
    soft_instructions: int = DEFAULT_SOFT_INSTRUCTIONS
    hard_instructions: int = DEFAULT_HARD_INSTRUCTIONS
    duplicate_threshold: float = DEFAULT_DUPLICATE_THRESHOLD
    min_section_tokens: int = DEFAULT_MIN_SECTION_TOKENS
    stale_days: int = DEFAULT_STALE_DAYS
    wall_length: int = DEFAULT_WALL_LENGTH
    max_files: int = DEFAULT_MAX_FILES
    max_bytes: int = DEFAULT_MAX_BYTES
    today: Optional[date] = None  # None => use date.today()
