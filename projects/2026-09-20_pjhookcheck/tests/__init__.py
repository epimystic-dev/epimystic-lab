"""Test-package init.

Routes tempfile to a disposable, git-ignored path under the checkout
(see support.py for why).
Importing support at package init makes discovery-run tests (which do not
otherwise import support) pick up the same redirect.
"""

from . import support  # noqa: F401
