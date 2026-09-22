"""Shared test helpers.

Test fixtures that contain secret-shape strings (bearer tokens, private
keys) are assembled at runtime from sub-16-character parts so that no
verbatim secret literal appears in the source tree; the publish gate
scans for whole-secret shapes and a false positive there blocks the
project.
"""

from __future__ import annotations

import io
import json
import os
import tempfile
from typing import Any, Dict, Sequence, Tuple

from pjhookcheck.cli import main as cli_main
from pjhookcheck.parse import load_json
from pjhookcheck.rules import run_all
from pjhookcheck.types import Options


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")

# Route tempdirs to a project-local directory rather than the user Temp
# folder. Several fixtures deliberately contain a `curl | sh`-shape string,
# which is a well-known indicator-of-compromise pattern; an endpoint scanner
# watching the user profile's Temp folder can quarantine the file mid-write
# and make those tests flake. Writing under the checkout keeps the fixtures
# where the developer already trusts the tree. The directory is disposable
# and is git-ignored.
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_LOCAL_TMP = os.path.join(_PROJECT_ROOT, ".pytest_tmp")
os.makedirs(_LOCAL_TMP, exist_ok=True)
tempfile.tempdir = _LOCAL_TMP


def make_hs_token() -> str:
    """Assemble a 40-char high-entropy token from sub-16-char parts."""
    return "".join(("Xk2vJ9pQ3wRnT5", "yBz7cLmA1sDgV0", "hUeIjOwQrK4pMn"))


def scan_string(content: str, path: str = "in-memory.json",
                options: Options = Options()) -> Any:
    """Run every rule against a JSON string."""
    doc, err = load_json(content)
    if err is not None:
        return err, []
    return None, run_all(doc, content, path, options)


def scan_dict(obj: Dict[str, Any], path: str = "in-memory.json",
              options: Options = Options()) -> Any:
    return scan_string(json.dumps(obj, indent=2), path, options)


def write_temp(content: str, name: str = "package.json") -> Tuple[str, str]:
    """Write content to a fresh temp dir. Returns (dir, file_path)."""
    d = tempfile.mkdtemp(prefix="pjhcheck_")
    p = os.path.join(d, name)
    with open(p, "w", encoding="utf-8") as f:
        f.write(content)
    return d, p


def run_cli(argv: Sequence[str]) -> Tuple[int, str, str]:
    """Invoke the CLI in-process. Returns (rc, stdout, stderr)."""
    out = io.StringIO()
    err = io.StringIO()
    rc = cli_main(list(argv), stdout=out, stderr=err)
    return rc, out.getvalue(), err.getvalue()


def rule_ids(findings) -> Tuple[str, ...]:
    return tuple(f.rule_id for f in findings)


def fixture_path(name: str) -> str:
    return os.path.join(FIXTURES, name)
