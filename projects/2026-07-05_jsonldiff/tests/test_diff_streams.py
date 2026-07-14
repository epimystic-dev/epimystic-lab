"""Tests for the stream / file interface: line mode + key mode."""

import io
import unittest

from jsonldiff.core import diff_streams


def run(baseline, candidate, **kw):
    return list(diff_streams(io.StringIO(baseline), io.StringIO(candidate), **kw))


class LineMode(unittest.TestCase):
    def test_identical_streams_no_diffs(self):
        s = '{"a":1}\n{"a":2}\n'
        self.assertEqual(run(s, s), [])

    def test_blank_lines_skipped(self):
        s1 = '{"a":1}\n\n{"a":2}\n'
        s2 = '{"a":1}\n{"a":2}\n'
        self.assertEqual(run(s1, s2), [])

    def test_scalar_diff_per_position(self):
        c = run('{"a":1}\n{"a":2}\n', '{"a":1}\n{"a":9}\n')
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].position, 2)
        self.assertEqual(c[0].kind, "changed")

    def test_extra_line_in_candidate_is_missing_in_baseline(self):
        c = run('{"a":1}\n', '{"a":1}\n{"a":2}\n')
        kinds = [x.kind for x in c]
        self.assertIn("missing_in_baseline", kinds)

    def test_extra_line_in_baseline_is_missing_in_candidate(self):
        c = run('{"a":1}\n{"a":2}\n', '{"a":1}\n')
        kinds = [x.kind for x in c]
        self.assertIn("missing_in_candidate", kinds)

    def test_parse_error_reported(self):
        c = run("not-json\n", '{"a":1}\n')
        kinds = [x.kind for x in c]
        self.assertIn("parse_error_baseline", kinds)

    def test_ignored_path_passed_through(self):
        c = run(
            '{"metrics":{"acc":0.9},"t":1}\n',
            '{"metrics":{"acc":0.9},"t":2}\n',
            ignore=["t"],
        )
        self.assertEqual(c, [])

    def test_max_diffs_truncates(self):
        base = '{"a":1}\n{"b":1}\n{"c":1}\n'
        cand = '{"a":9}\n{"b":9}\n{"c":9}\n'
        c = run(base, cand, max_diffs=1)
        self.assertEqual(len(c), 1)


class KeyMode(unittest.TestCase):
    def test_key_alignment_across_reorder(self):
        base = '{"id":"x","v":1}\n{"id":"y","v":2}\n'
        cand = '{"id":"y","v":2}\n{"id":"x","v":1}\n'
        self.assertEqual(run(base, cand, key="id"), [])

    def test_key_value_change(self):
        base = '{"id":"x","v":1}\n{"id":"y","v":2}\n'
        cand = '{"id":"y","v":22}\n{"id":"x","v":1}\n'
        c = run(base, cand, key="id")
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].kind, "changed")
        self.assertEqual(c[0].key, "y")
        self.assertEqual((c[0].baseline, c[0].candidate), (2, 22))

    def test_candidate_only_key_is_missing_in_baseline(self):
        base = '{"id":"x","v":1}\n'
        cand = '{"id":"x","v":1}\n{"id":"y","v":2}\n'
        c = run(base, cand, key="id")
        kinds = [x.kind for x in c]
        self.assertIn("missing_in_baseline", kinds)

    def test_baseline_only_key_is_missing_in_candidate(self):
        base = '{"id":"x","v":1}\n{"id":"y","v":2}\n'
        cand = '{"id":"x","v":1}\n'
        c = run(base, cand, key="id")
        kinds = [x.kind for x in c]
        self.assertIn("missing_in_candidate", kinds)

    def test_missing_key_in_record_flagged(self):
        base = '{"id":"x"}\n{"no_id":true}\n'
        cand = '{"id":"x"}\n'
        c = run(base, cand, key="id")
        kinds = [x.kind for x in c]
        self.assertIn("parse_error_baseline", kinds)

    def test_nested_key_path(self):
        base = '{"meta":{"run":"a"},"v":1}\n'
        cand = '{"meta":{"run":"a"},"v":2}\n'
        c = run(base, cand, key="meta.run")
        self.assertEqual(len(c), 1)
        self.assertEqual(c[0].key, "a")

    def test_duplicate_key_in_baseline_flagged(self):
        base = '{"id":"x","v":1}\n{"id":"x","v":2}\n'
        cand = '{"id":"x","v":1}\n'
        c = run(base, cand, key="id")
        kinds = [x.kind for x in c]
        self.assertIn("parse_error_baseline", kinds)


if __name__ == "__main__":
    unittest.main()
