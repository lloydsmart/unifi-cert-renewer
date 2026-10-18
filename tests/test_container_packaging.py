"""Exercise installed curl version guards without Docker or package updates."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(
    os.name != "posix" or shutil.which("dpkg") is None,
    reason="Packaging guards require POSIX and Debian version comparison",
)


@pytest.mark.parametrize(
    "source",
    ["deployment/unifi/Dockerfile", "scripts/validate-container-packaging.sh"],
)
@pytest.mark.parametrize("package", ["curl", "libcurl4t64"])
@pytest.mark.parametrize(
    "status",
    [
        "installed",
        "config-files",
        "unpacked",
        "half-configured",
        "half-installed",
        "triggers-awaited",
        "triggers-pending",
        "not-installed",
        "",
        "invalid",
        " installed",
        "installed\ninvalid",
        "missing",
        "query-failed",
    ],
)
@pytest.mark.parametrize(
    "version,accepted",
    [
        ("8.18.0-1ubuntu2.5", False),
        ("8.18.0-1ubuntu2.7", False),
        ("8.18.0-1ubuntu2.8", True),
        ("8.18.0-1ubuntu2.10", True),
        ("", False),
        ("invalid", False),
        ("missing", False),
        ("query-failed", False),
    ],
)
def test_curl_guards_check_each_installed_package(
    tmp_path, source, package, status, version, accepted
):
    text = (ROOT / source).read_text().replace("\\\n", "")
    guard = re.search(r"for package in curl libcurl4t64; do\b.*?\bdone", text, re.S)
    assert guard is not None
    query = tmp_path / "dpkg-query"
    query.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "field = {'-f=${Version}': 'TEST_VERSION',\n"
        "         '-f=${db:Status-Status}': 'TEST_STATUS'}[sys.argv[2]]\n"
        "value = (os.environ[field]\n"
        "         if sys.argv[-1] == os.environ['TEST_PACKAGE']\n"
        "         else {'TEST_VERSION': '8.18.0-1ubuntu2.8',\n"
        "               'TEST_STATUS': 'installed'}[field])\n"
        "if value == 'missing':\n"
        "    sys.exit(1)\n"
        "if value == 'query-failed':\n"
        "    print('installed' if field == 'TEST_STATUS'\n"
        "          else '8.18.0-1ubuntu2.8', end='')\n"
        "    sys.exit(1)\n"
        "print(value, end='')\n"
    )
    query.chmod(0o700)
    result = subprocess.run(
        ["sh", "-ceu", guard.group()],
        env=os.environ
        | {
            "PATH": str(tmp_path) + os.pathsep + os.environ["PATH"],
            "TEST_PACKAGE": package,
            "TEST_VERSION": version,
            "TEST_STATUS": status,
        },
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    assert (result.returncode == 0) is (accepted and status == "installed"), (
        result.stdout + result.stderr
    )
