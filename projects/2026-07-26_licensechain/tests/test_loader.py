import json
import os
import tempfile
import unittest

from licensechain.loader import load_manifest, LoadError, Chain, Component


VALID_MIN = {
    "version": 1,
    "chain": [
        {"name": "app", "role": "application", "license": "MIT"},
    ],
}


class HappyPathTests(unittest.TestCase):

    def test_load_from_json_string(self):
        chain = load_manifest(json.dumps(VALID_MIN))
        self.assertIsInstance(chain, Chain)
        self.assertEqual(len(chain.components), 1)
        self.assertEqual(chain.components[0].name, "app")
        self.assertEqual(chain.components[0].role, "application")
        self.assertEqual(chain.components[0].license, "MIT")

    def test_load_from_file_path(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8",
        ) as f:
            json.dump(VALID_MIN, f)
            path = f.name
        try:
            chain = load_manifest(path)
            self.assertEqual(chain.components[0].name, "app")
        finally:
            os.remove(path)

    def test_load_from_file_like(self):
        import io
        buf = io.StringIO(json.dumps(VALID_MIN))
        chain = load_manifest(buf)
        self.assertEqual(chain.components[0].name, "app")

    def test_load_full_chain(self):
        m = {
            "version": 1,
            "chain": [
                {"name": "d1", "role": "dataset", "license": "CC-BY-4.0"},
                {"name": "m1", "role": "model", "license": "Apache-2.0",
                 "trained_on": ["d1"]},
                {"name": "a1", "role": "application", "license": "MIT",
                 "uses": ["m1"]},
            ],
        }
        chain = load_manifest(json.dumps(m))
        self.assertEqual(len(chain.components), 3)
        by_name = chain.by_name()
        self.assertEqual(by_name["m1"].trained_on, ["d1"])
        self.assertEqual(by_name["a1"].uses, ["m1"])

    def test_default_values(self):
        m = {"version": 1, "chain": [{"name": "x"}]}
        chain = load_manifest(json.dumps(m))
        c = chain.components[0]
        self.assertEqual(c.role, "other")
        self.assertIsNone(c.license)
        self.assertFalse(c.preserves_notices)
        self.assertTrue(c.commercial_use)
        self.assertEqual(c.trained_on, [])
        self.assertEqual(c.derived_from, [])
        self.assertEqual(c.uses, [])

    def test_utf8_bom_is_accepted(self):
        with tempfile.NamedTemporaryFile(
            mode="wb", suffix=".json", delete=False,
        ) as f:
            f.write("﻿".encode("utf-8"))
            f.write(json.dumps(VALID_MIN).encode("utf-8"))
            path = f.name
        try:
            chain = load_manifest(path)
            self.assertEqual(chain.components[0].name, "app")
        finally:
            os.remove(path)


class IterEdgesTests(unittest.TestCase):

    def test_iter_edges_across_all_relation_kinds(self):
        m = {
            "version": 1,
            "chain": [
                {"name": "d", "role": "dataset", "license": "CC0-1.0"},
                {"name": "m", "role": "model", "license": "MIT",
                 "trained_on": ["d"]},
                {"name": "lib", "role": "library", "license": "Apache-2.0"},
                {"name": "a", "role": "application", "license": "MIT",
                 "uses": ["m"], "derived_from": ["lib"]},
            ],
        }
        chain = load_manifest(json.dumps(m))
        edges = list(chain.iter_edges())
        # 3 edges: m<-d(trained_on), a<-m(uses), a<-lib(derived_from)
        self.assertEqual(len(edges), 3)
        kinds = sorted(k for _d, _u, k in edges)
        self.assertEqual(kinds, ["derived_from", "trained_on", "uses"])


class StructuralErrorTests(unittest.TestCase):

    def test_invalid_json(self):
        with self.assertRaises(LoadError):
            load_manifest("{not json")

    def test_root_not_object(self):
        with self.assertRaises(LoadError):
            load_manifest("[]")

    def test_missing_chain(self):
        with self.assertRaises(LoadError):
            load_manifest('{"version": 1}')

    def test_empty_chain(self):
        with self.assertRaises(LoadError):
            load_manifest('{"version": 1, "chain": []}')

    def test_component_missing_name(self):
        with self.assertRaises(LoadError) as ctx:
            load_manifest(json.dumps({
                "version": 1, "chain": [{"role": "model"}]
            }))
        self.assertIn("name", str(ctx.exception))

    def test_component_empty_name(self):
        with self.assertRaises(LoadError):
            load_manifest(json.dumps({
                "version": 1, "chain": [{"name": "  ", "role": "model"}]
            }))

    def test_invalid_role(self):
        with self.assertRaises(LoadError) as ctx:
            load_manifest(json.dumps({
                "version": 1,
                "chain": [{"name": "x", "role": "banana"}]
            }))
        self.assertIn("role", str(ctx.exception))

    def test_license_wrong_type(self):
        with self.assertRaises(LoadError):
            load_manifest(json.dumps({
                "version": 1,
                "chain": [{"name": "x", "license": 42}]
            }))

    def test_upstream_list_wrong_type(self):
        with self.assertRaises(LoadError):
            load_manifest(json.dumps({
                "version": 1,
                "chain": [{"name": "x", "trained_on": [1, 2]}]
            }))

    def test_duplicate_names(self):
        with self.assertRaises(LoadError) as ctx:
            load_manifest(json.dumps({
                "version": 1,
                "chain": [
                    {"name": "x", "role": "model"},
                    {"name": "x", "role": "model"},
                ]
            }))
        self.assertIn("duplicate", str(ctx.exception).lower())

    def test_dangling_upstream_reference(self):
        with self.assertRaises(LoadError) as ctx:
            load_manifest(json.dumps({
                "version": 1,
                "chain": [
                    {"name": "m", "role": "model", "trained_on": ["ghost"]},
                ]
            }))
        self.assertIn("ghost", str(ctx.exception))

    def test_cycle_detected(self):
        with self.assertRaises(LoadError) as ctx:
            load_manifest(json.dumps({
                "version": 1,
                "chain": [
                    {"name": "a", "role": "model", "trained_on": ["b"]},
                    {"name": "b", "role": "model", "trained_on": ["a"]},
                ]
            }))
        self.assertIn("cycle", str(ctx.exception).lower())

    def test_missing_file(self):
        with self.assertRaises(LoadError):
            load_manifest("/no/such/path/manifest.json")

    def test_unsupported_version(self):
        with self.assertRaises(LoadError):
            load_manifest(json.dumps({"version": 999, "chain": []}))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
