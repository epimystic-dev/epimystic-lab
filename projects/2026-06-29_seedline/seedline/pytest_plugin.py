"""Optional pytest fixture.

Not loaded by pytest automatically. To use:

    # conftest.py
    pytest_plugins = ["seedline.pytest_plugin"]

    # then in tests:
    def test_my_thing(seeded_run):
        with seeded_run(42):
            ...

Or, mark a whole test:

    import pytest
    @pytest.mark.seeded(123)
    def test_other(seeded_run):
        ...
"""

from __future__ import annotations

try:
    import pytest
except ImportError:  # pragma: no cover
    pytest = None  # type: ignore

from .core import seeded


if pytest is not None:

    @pytest.fixture
    def seeded_run():
        """Yield a callable that returns the :func:`seedline.seeded` ctx
        manager so tests can do ``with seeded_run(42): ...`` instead of
        importing seedline directly."""
        return seeded
