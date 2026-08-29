"""Defaults for scanning and rule thresholds."""

from dataclasses import dataclass, field
from typing import Optional


DEFAULT_TEST_GLOBS = (
    "test_*.py",
    "*_test.py",
    "tests.py",
)


DEFAULT_TEST_DIRS = ("tests", "test")


DEFAULT_ASSERT_METHODS = frozenset({
    "assertEqual",
    "assertEquals",
    "assertNotEqual",
    "assertNotEquals",
    "assertIs",
    "assertIsNot",
    "assertTrue",
    "assertFalse",
    "assertGreater",
    "assertGreaterEqual",
    "assertLess",
    "assertLessEqual",
    "assertIn",
    "assertNotIn",
    "assertIsNone",
    "assertIsNotNone",
    "assertRegex",
    "assertNotRegex",
    "assertAlmostEqual",
    "assertSequenceEqual",
    "assertListEqual",
    "assertTupleEqual",
    "assertDictEqual",
    "assertSetEqual",
    "assertMultiLineEqual",
})


ROUNDTRIP_INVERSES = {
    ("dumps", "loads"),
    ("loads", "dumps"),
    ("dump", "load"),
    ("load", "dump"),
    ("encode", "decode"),
    ("decode", "encode"),
    ("serialize", "deserialize"),
    ("deserialize", "serialize"),
    ("to_json", "from_json"),
    ("from_json", "to_json"),
    ("to_dict", "from_dict"),
    ("from_dict", "to_dict"),
    ("marshal", "unmarshal"),
    ("unmarshal", "marshal"),
    ("pack", "unpack"),
    ("unpack", "pack"),
    ("encode_json", "decode_json"),
    ("decode_json", "encode_json"),
}


ROUNDTRIP_REPR_FUNCS = frozenset({"repr", "str", "ascii"})


@dataclass
class Config:
    max_files: int = 1000
    max_bytes: int = 1_048_576
    test_globs: tuple = DEFAULT_TEST_GLOBS
    test_dirs: tuple = DEFAULT_TEST_DIRS
    assert_methods: frozenset = DEFAULT_ASSERT_METHODS
    sut_module: Optional[str] = None
    include_info: bool = False
    strict: bool = False
    disabled_rules: frozenset = field(default_factory=frozenset)
