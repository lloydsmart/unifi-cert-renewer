"""Exercise installed package version guards without Docker or package updates."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUARD_SOURCES = [
    "deployment/unifi/Dockerfile",
    "scripts/validate-container-packaging.sh",
]
PACKAGE_STATUSES = [
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
]
pytestmark = pytest.mark.skipif(
    os.name != "posix" or shutil.which("dpkg") is None,
    reason="Packaging guards require POSIX and Debian version comparison",
)


@pytest.mark.parametrize("source", GUARD_SOURCES)
@pytest.mark.parametrize("package", ["curl", "libcurl4t64"])
@pytest.mark.parametrize("status", PACKAGE_STATUSES)
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
    _assert_installed_package_guard(
        tmp_path,
        source,
        "curl libcurl4t64",
        package,
        "8.18.0-1ubuntu2.8",
        status,
        version,
        accepted,
    )


@pytest.mark.parametrize("source", GUARD_SOURCES)
@pytest.mark.parametrize("status", PACKAGE_STATUSES)
@pytest.mark.parametrize(
    "version,accepted",
    [
        ("25.0.4.1+1-1~26.04.4", False),
        ("25.0.5.0.3+1-3~26.04.1", False),
        ("25.0.5.1+2-1~26.04.1", True),
        ("25.0.5.1+2-1~26.04.2", True),
        ("", False),
        ("invalid", False),
        ("missing", False),
        ("query-failed", False),
    ],
)
def test_openjdk_guards_require_installed_security_fix(
    tmp_path, source, status, version, accepted
):
    _assert_installed_package_guard(
        tmp_path,
        source,
        "openjdk-25-jre-headless",
        "openjdk-25-jre-headless",
        "25.0.5.1+2-1~26.04.1",
        status,
        version,
        accepted,
    )


def _assert_installed_package_guard(
    tmp_path, source, packages, package, minimum, status, version, accepted
):
    text = (ROOT / source).read_text().replace("\\\n", "")
    guard = re.search(
        rf"for package in {re.escape(packages)}; do\b.*?\bdone", text, re.S
    )
    assert guard is not None
    query = tmp_path / "dpkg-query"
    query.write_text(
        f"#!{sys.executable}\n"
        "import os, sys\n"
        "field = {'-f=${Version}': 'TEST_VERSION',\n"
        "         '-f=${db:Status-Status}': 'TEST_STATUS'}[sys.argv[2]]\n"
        "value = (os.environ[field]\n"
        "         if sys.argv[-1] == os.environ['TEST_PACKAGE']\n"
        "         else {'TEST_VERSION': os.environ['TEST_MINIMUM'],\n"
        "               'TEST_STATUS': 'installed'}[field])\n"
        "if value == 'missing':\n"
        "    sys.exit(1)\n"
        "if value == 'query-failed':\n"
        "    print('installed' if field == 'TEST_STATUS'\n"
        "          else os.environ['TEST_MINIMUM'], end='')\n"
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
            "TEST_MINIMUM": minimum,
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
