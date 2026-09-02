from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_required_project_scaffolding_exists():
    required_paths = (
        "README.md",
        "SECURITY.md",
        "AGENTS.md",
        "LICENSE",
        "pyproject.toml",
        "requirements.in",
        "requirements.txt",
        "requirements-dev.in",
        "requirements-dev.txt",
        "requirements-tools.in",
        "requirements-tools.txt",
        "requirements-security.in",
        "requirements-security.txt",
    )

    missing = [
        path for path in required_paths if not (REPOSITORY_ROOT / path).is_file()
    ]

    assert not missing, f"Missing required project files: {missing}"
