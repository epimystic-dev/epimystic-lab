"""Typosquat-shape detection via Damerau-Levenshtein distance against a
curated static snapshot of widely-installed Python packages.

The snapshot is a hand-curated list of packages that appear repeatedly at the
top of public PyPI download tallies and standard framework stacks; it is not
a claim to be *the* top-N by any specific metric, and it is not updated at
runtime (no network). All names are already PEP 503 canonicalized.

The snapshot is deliberately small (~55 entries): the goal is to detect
one-off character mistakes near a name a reader can be assumed to know, not
to enumerate all popular packages. False negatives are expected and
acceptable; a false positive on an unfamiliar package is not.
"""

from __future__ import annotations

from typing import Optional, Tuple

# PEP 503 canonicalized names.
POPULAR_PACKAGES: Tuple[str, ...] = (
    "requests",
    "urllib3",
    "certifi",
    "charset-normalizer",
    "idna",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "pillow",
    "scikit-learn",
    "torch",
    "tensorflow",
    "transformers",
    "opencv-python",
    "pyyaml",
    "six",
    "python-dateutil",
    "packaging",
    "setuptools",
    "wheel",
    "pip",
    "typing-extensions",
    "importlib-metadata",
    "cryptography",
    "cffi",
    "colorama",
    "click",
    "jinja2",
    "markupsafe",
    "flask",
    "django",
    "fastapi",
    "starlette",
    "uvicorn",
    "gunicorn",
    "pydantic",
    "httpx",
    "aiohttp",
    "boto3",
    "botocore",
    "sqlalchemy",
    "psycopg2",
    "psycopg2-binary",
    "redis",
    "pymongo",
    "celery",
    "protobuf",
    "grpcio",
    "pytest",
    "coverage",
    "tqdm",
    "beautifulsoup4",
    "lxml",
    "attrs",
    "rich",
)

# Names that are one edit away from a popular name but are themselves real
# packages people install intentionally; exclude them from the typosquat rule.
KNOWN_LEGITIMATE = frozenset(
    (
        "boto",           # legacy of boto3; still installed by some legacy code
        "botocore",       # 1-away from boto3 via non-adjacent edits; already in popular set
        "psycopg2-binary",
        "beautifulsoup",  # BS3; still exists on PyPI
    )
)


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal string alignment (restricted Damerau-Levenshtein) distance.

    Counts insertions, deletions, substitutions, and adjacent transpositions,
    each with unit cost. Restricted variant: a substring is not edited twice.
    Sufficient for typosquat proximity heuristics.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    la, lb = len(a), len(b)
    # dp[i][j] = distance between a[:i] and b[:j]
    dp = [[0] * (lb + 1) for _ in range(la + 1)]
    for i in range(la + 1):
        dp[i][0] = i
    for j in range(lb + 1):
        dp[0][j] = j
    for i in range(1, la + 1):
        for j in range(1, lb + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,        # deletion
                dp[i][j - 1] + 1,        # insertion
                dp[i - 1][j - 1] + cost, # substitution
            )
            if (
                i > 1
                and j > 1
                and a[i - 1] == b[j - 2]
                and a[i - 2] == b[j - 1]
            ):
                dp[i][j] = min(dp[i][j], dp[i - 2][j - 2] + 1)  # transposition
    return dp[la][lb]


def typosquat_candidate(
    name: str,
    max_distance: int = 2,
    min_length: int = 4,
) -> Optional[Tuple[str, int]]:
    """Return (popular_name, distance) if ``name`` looks like a typosquat.

    Returns None if:
      - the name is exactly a popular package, or in KNOWN_LEGITIMATE
      - the name is shorter than ``min_length`` (too many false positives)
      - no popular name lies within ``max_distance``

    ``name`` is expected to be PEP 503 canonicalized already.
    """
    canonical = name
    if canonical in POPULAR_PACKAGES or canonical in KNOWN_LEGITIMATE:
        return None
    if len(canonical) < min_length:
        return None
    best: Optional[Tuple[str, int]] = None
    for pop in POPULAR_PACKAGES:
        # Only consider popular names whose length is close enough; skip
        # obviously-different lengths for efficiency.
        if abs(len(pop) - len(canonical)) > max_distance:
            continue
        d = damerau_levenshtein(canonical, pop)
        if d == 0:
            return None  # exact match (shouldn't happen due to earlier check)
        if d <= max_distance and (best is None or d < best[1]):
            best = (pop, d)
    return best
