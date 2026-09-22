import unittest

from pjhookcheck.types import Finding, Options, ScanResult, Severity, Verdict
from pjhookcheck.verdict import compute_verdict, exit_code


def _finding(sev: Severity, rid: str = "PJH-001") -> Finding:
    return Finding(
        rule_id=rid, severity=sev, path="p.json", prop="scripts.install",
        line=1, column=1, message="m",
    )


class TestVerdict(unittest.TestCase):
    def test_no_files_default_unknown(self):
        v = compute_verdict(ScanResult(files_scanned=0), Options())
        self.assertIs(v, Verdict.UNKNOWN)

    def test_no_files_strict_unhealthy(self):
        v = compute_verdict(ScanResult(files_scanned=0), Options(strict=True))
        self.assertIs(v, Verdict.UNHEALTHY)

    def test_error_forces_unhealthy(self):
        v = compute_verdict(
            ScanResult(files_scanned=0, errors=("boom",)), Options())
        self.assertIs(v, Verdict.UNHEALTHY)

    def test_high_wins(self):
        v = compute_verdict(
            ScanResult(files_scanned=1,
                       findings=(_finding(Severity.HIGH), _finding(Severity.MEDIUM))),
            Options())
        self.assertIs(v, Verdict.UNHEALTHY)

    def test_medium_needs_attention(self):
        v = compute_verdict(
            ScanResult(files_scanned=1, findings=(_finding(Severity.MEDIUM),)),
            Options())
        self.assertIs(v, Verdict.NEEDS_ATTENTION)

    def test_info_hidden_by_default_stays_healthy(self):
        v = compute_verdict(
            ScanResult(files_scanned=1, findings=(_finding(Severity.INFO),)),
            Options())
        self.assertIs(v, Verdict.HEALTHY)

    def test_info_with_include_info_needs_attention(self):
        v = compute_verdict(
            ScanResult(files_scanned=1, findings=(_finding(Severity.INFO),)),
            Options(include_info=True))
        self.assertIs(v, Verdict.NEEDS_ATTENTION)

    def test_info_strict_unhealthy(self):
        v = compute_verdict(
            ScanResult(files_scanned=1, findings=(_finding(Severity.INFO),)),
            Options(strict=True))
        self.assertIs(v, Verdict.UNHEALTHY)

    def test_no_findings_healthy(self):
        v = compute_verdict(ScanResult(files_scanned=1), Options())
        self.assertIs(v, Verdict.HEALTHY)


class TestExitCodes(unittest.TestCase):
    def test_healthy_zero(self):
        self.assertEqual(exit_code(Verdict.HEALTHY), 0)

    def test_needs_attention_one(self):
        self.assertEqual(exit_code(Verdict.NEEDS_ATTENTION), 1)

    def test_unhealthy_two(self):
        self.assertEqual(exit_code(Verdict.UNHEALTHY), 2)

    def test_unknown_zero(self):
        self.assertEqual(exit_code(Verdict.UNKNOWN), 0)


if __name__ == "__main__":
    unittest.main()
