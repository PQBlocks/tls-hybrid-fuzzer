"""Tests for packaging (slice S13).

Spec §5 S13 contract:
- pyproject.toml + bin/pqblocks-tlsfuzz + console_scripts entry
- _version.py with __version__
- py.typed PEP 561 marker (empty)
- wheel and sdist build via python -m build
- console script entry works

These tests run only when a built wheel/sdist is requested, or when build
is available. They are designed to pass without a network connection.

EVIDENCE: these tests are the RED phase for S13. They must fail before
implementation and pass after.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

LANE_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = LANE_ROOT / "src" / "pqblocks_tlsfuzz"


def setup_module():
    if not (LANE_ROOT / "pyproject.toml").exists():
        pytest.skip("pyproject.toml not in isolated test root (cleanroom testing installed package)")


def test_console_script_entry():
    """Console script entry point exists in pyproject.toml and resolves to cli:main."""
    pyproject = LANE_ROOT / "pyproject.toml"
    assert pyproject.exists(), "pyproject.toml must exist"
    content = pyproject.read_text()
    assert "[project.scripts]" in content, "pyproject.toml must have [project.scripts]"
    assert "pqblocks-tlsfuzz" in content, "console script name must be pqblocks-tlsfuzz"
    # The entry point target must be importable
    from pqblocks_tlsfuzz.cli import main
    assert callable(main), "pqblocks_tlsfuzz.cli:main must be callable"


def test_version_module_exists():
    """_version.py must exist and expose __version__."""
    version_file = SRC_DIR / "_version.py"
    assert version_file.exists(), "_version.py must exist"
    # Read the version without importing (avoids side effects)
    content = version_file.read_text()
    assert "__version__" in content, "_version.py must define __version__"
    # Must be a valid version string
    import re
    match = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', content)
    assert match, "_version.py must have a string __version__"
    version = match.group(1)
    # Semantic versioning basic check
    parts = version.split(".")
    assert len(parts) >= 2, f"version must have at least major.minor, got {version}"


def test_version_importable():
    """__version__ is importable from the package."""
    import pqblocks_tlsfuzz
    assert hasattr(pqblocks_tlsfuzz, "__version__")
    assert isinstance(pqblocks_tlsfuzz.__version__, str)
    assert len(pqblocks_tlsfuzz.__version__) > 0


def test_py_typed_marker_exists():
    """py.typed marker must exist in src/pqblocks_tlsfuzz/ (PEP 561)."""
    marker = SRC_DIR / "py.typed"
    assert marker.exists(), "py.typed marker must exist in src/pqblocks_tlsfuzz/"
    # PEP 561: py.typed is an empty file
    assert marker.read_text() == "", "py.typed must be empty (PEP 561)"


def test_py_typed_in_wheel():
    """py.typed must be included in the wheel (package_data)."""
    # Check that pyproject.toml includes py.typed in package-data
    pyproject = LANE_ROOT / "pyproject.toml"
    content = pyproject.read_text()
    assert "py.typed" in content or "package-data" in content or "package_data" in content, \
        "pyproject.toml must include py.typed in package-data"


def test_wheel_builds():
    """Wheel builds successfully with python -m build --wheel."""
    # This test requires the 'build' package; skip if not available
    try:
        import build  # noqa: F401
    except ImportError:
        pytest.skip("build package not installed")

    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--outdir", tmpdir],
            cwd=str(LANE_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"wheel build failed: {result.stderr}"
        wheels = list(Path(tmpdir).glob("*.whl"))
        assert len(wheels) >= 1, "wheel build produced no wheel file"
        wheel = wheels[0]
        assert "pqblocks_tls" in wheel.name, f"wheel name should contain package: {wheel.name}"


def test_wheel_contains_py_typed():
    """The built wheel must contain py.typed."""
    try:
        import build  # noqa: F401
    except ImportError:
        pytest.skip("build package not installed")

    import tempfile
    import zipfile
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            [sys.executable, "-m", "build", "--wheel", "--outdir", tmpdir],
            cwd=str(LANE_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"wheel build failed: {result.stderr}"
        wheels = list(Path(tmpdir).glob("*.whl"))
        assert len(wheels) >= 1
        with zipfile.ZipFile(wheels[0]) as zf:
            names = zf.namelist()
            assert any("py.typed" in n for n in names), \
                f"py.typed must be in the wheel; got: {names}"


def test_sdist_builds():
    """Source distribution builds successfully with python -m build --sdist."""
    try:
        import build  # noqa: F401
    except ImportError:
        pytest.skip("build package not installed")

    import tempfile
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            [sys.executable, "-m", "build", "--sdist", "--outdir", tmpdir],
            cwd=str(LANE_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"sdist build failed: {result.stderr}"
        sdists = list(Path(tmpdir).glob("*.tar.gz"))
        assert len(sdists) >= 1, "sdist build produced no tarball"


def test_sdist_contains_py_typed():
    """The built sdist must contain py.typed."""
    try:
        import build  # noqa: F401
    except ImportError:
        pytest.skip("build package not installed")

    import tempfile
    import tarfile
    with tempfile.TemporaryDirectory() as tmpdir:
        result = subprocess.run(
            [sys.executable, "-m", "build", "--sdist", "--outdir", tmpdir],
            cwd=str(LANE_ROOT),
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0, f"sdist build failed: {result.stderr}"
        sdists = list(Path(tmpdir).glob("*.tar.gz"))
        assert len(sdists) >= 1
        with tarfile.open(sdists[0]) as tf:
            names = tf.getnames()
            assert any("py.typed" in n for n in names), \
                f"py.typed must be in the sdist; got: {names}"


def test_bin_script_exists():
    """bin/pqblocks-tlsfuzz console script shim must exist."""
    bin_script = LANE_ROOT / "bin" / "pqblocks-tlsfuzz"
    assert bin_script.exists(), "bin/pqblocks-tlsfuzz must exist"
    assert bin_script.is_file(), "bin/pqblocks-tlsfuzz must be a file"
    # Must be executable (on Unix)
    if sys.platform != "win32":
        assert os.access(bin_script, os.X_OK), "bin/pqblocks-tlsfuzz must be executable"


def test_bin_script_calls_main():
    """bin/pqblocks-tlsfuzz must import and call cli.main."""
    bin_script = LANE_ROOT / "bin" / "pqblocks-tlsfuzz"
    content = bin_script.read_text()
    assert "pqblocks_tlsfuzz" in content, "bin script must import pqblocks_tlsfuzz"
    assert "main" in content, "bin script must call main()"


def test_pyproject_name():
    """pyproject.toml must have name = 'pqblocks-tlsfuzz'."""
    pyproject = LANE_ROOT / "pyproject.toml"
    content = pyproject.read_text()
    assert 'name = "pqblocks-tls"' in content or 'name = "pqblocks-tlsfuzz"' in content, \
        "project name must be 'pqblocks-tls' or 'pqblocks-tlsfuzz'"


def test_pyproject_requires_python():
    """pyproject.toml must specify requires-python >= 3.10."""
    pyproject = LANE_ROOT / "pyproject.toml"
    content = pyproject.read_text()
    assert "requires-python" in content, "must specify requires-python"
    assert ">=3.10" in content, "requires-python must be >=3.10"