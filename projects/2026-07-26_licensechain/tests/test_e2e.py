import json
import os
import sys
import unittest
import io
from contextlib import redirect_stdout

from licensechain.cli import main


EXAMPLES = os.path.join(os.path.dirname(os.path.dirname(__file__)), "examples")


def _run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(argv)
    return code, buf.getvalue()


class E2ESmokeTests(unittest.TestCase):

    def test_ok_chain_is_clean(self):
        path = os.path.join(EXAMPLES, "ok_chain.json")
        code, out = _run([path])
        self.assertEqual(code, 0, out)
        self.assertIn("no findings", out)

    def test_bad_chain_reports_multiple_rules(self):
        path = os.path.join(EXAMPLES, "bad_chain.json")
        code, out = _run([path])
        # bad_chain has several errors: LIC-004 (GPL->Apache), LIC-006
        # (CC-BY-SA->Apache), LIC-009 (NOASSERTION), LIC-011 (NC->commercial)
        self.assertEqual(code, 2, out)
        for rule in ("LIC-004", "LIC-006", "LIC-009", "LIC-011"):
            self.assertIn(rule, out, f"expected {rule} in output:\n{out}")

    def test_mixed_chain_is_clean_or_warn_only(self):
        path = os.path.join(EXAMPLES, "mixed_chain.json")
        code, out = _run([path])
        # public-data(CC0) + reference-corpus(CC-BY-4.0) -> Apache-2.0 model
        # -> MIT OR Apache-2.0 app: this composition is entirely legal;
        # notices are preserved on the app but not on reference-corpus so
        # LIC-005 may fire on the model->corpus edge.
        # The critical assertion: no ERROR-level findings.
        self.assertIn(code, (0, 1),
                      f"expected clean or warn-only, got {code}:\n{out}")
        for rule in ("LIC-004", "LIC-006", "LIC-007", "LIC-011"):
            self.assertNotIn(rule, out)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
