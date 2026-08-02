"""Fresh-interpreter checks for correlation package import boundaries."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPOSITORY_ROOT = Path(__file__).parents[3]
_IMPORT_ORDERS = (
    (
        "import agmind_immune.coverage.historical\n"
        "from agmind_immune.correlation import CorrelationProjectionAuthority\n"
    ),
    (
        "from agmind_immune.correlation import CorrelationProjectionAuthority\n"
        "import agmind_immune.coverage.historical\n"
    ),
)


@pytest.mark.parametrize(
    "imports",
    _IMPORT_ORDERS,
    ids=("historical-first", "public-authority-first"),
)
def test_correlation_package_import_orders_in_fresh_interpreter(
    imports: str,
) -> None:
    existing_pythonpath = os.environ.get("PYTHONPATH")
    pythonpath = str(_REPOSITORY_ROOT / "core")
    if existing_pythonpath:
        pythonpath = os.pathsep.join((pythonpath, existing_pythonpath))
    script = imports + (
        "import agmind_immune.correlation as public_module\n"
        "from agmind_immune.correlation.authority import "
        "CorrelationProjectionAuthority as implementation\n"
        "assert CorrelationProjectionAuthority is implementation\n"
        "assert public_module.CorrelationProjectionAuthority is implementation\n"
        "assert 'CorrelationProjectionAuthority' in public_module.__all__\n"
    )

    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=_REPOSITORY_ROOT,
        env={**os.environ, "PYTHONPATH": pythonpath},
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
