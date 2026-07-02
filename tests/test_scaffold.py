"""Scaffold tests: package metadata and the import-light guard.

Phase 0 scope fence: no real logic exists yet, so these tests only pin the
package version and enforce that the base import never pulls in optional-extra
dependencies (PLAN.md section 3.1: import-light core).
"""

import subprocess
import sys

import airlock


def test_version() -> None:
    assert airlock.__version__ == "0.0.1"


def test_base_import_is_light() -> None:
    """A fresh interpreter importing airlock must not load any extras' modules."""
    code = (
        "import sys\n"
        "import airlock\n"
        "assert 'sqlalchemy' not in sys.modules, 'sqlalchemy leaked into the base import'\n"
        "assert 'httpx' not in sys.modules, 'httpx leaked into the base import'\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"import-light guard failed:\n{result.stderr}"
