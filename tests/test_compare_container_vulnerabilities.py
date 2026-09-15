import importlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
comparator = importlib.import_module("compare_container_vulnerabilities")


def vulnerability(
    vulnerability_id: str,
    *,
    severity: str = "HIGH",
    package: str = "example-package",
    installed: str = "1.0",
    fixed: str | None = "1.1",
    package_id: str = "example-package@1.0",
    package_path: str | None = None,
) -> dict[str, str]:
    finding = {
        "VulnerabilityID": vulnerability_id,
        "PkgID": package_id,
        "PkgName": package,
        "InstalledVersion": installed,
        "Severity": severity,
    }
    if fixed is not None:
        finding["FixedVersion"] = fixed
    if package_path is not None:
        finding["PkgPath"] = package_path
    return finding


def result(
    *findings: dict[str, str],
    target: str = "image (debian 12)",
    result_class: str = "os-pkgs",
    result_type: str = "debian",
) -> dict[str, object]:
    scan_result: dict[str, object] = {
        "Target": target,
        "Class": result_class,
        "Type": result_type,
    }
    if findings:
        scan_result["Vulnerabilities"] = list(findings)
    return scan_result


def report(*results: dict[str, object]) -> dict[str, object]:
    if not results:
        results = (result(),)
    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "Metadata": {"OS": {"Family": "debian", "Name": "12"}},
        "Results": list(results),
    }


def compare(
    derivative: dict[str, object], upstream: dict[str, object]
) -> comparator.Comparison:
    return comparator.compare_reports(derivative, upstream)


def test_introduced_high_finding_blocks() -> None:
    comparison = compare(report(result(vulnerability("CVE-HIGH"))), report())

    assert comparison.blocked
    assert [finding.identity.vulnerability_id for finding in comparison.introduced] == [
        "CVE-HIGH"
    ]


def test_introduced_critical_finding_blocks() -> None:
    comparison = compare(
        report(result(vulnerability("CVE-CRITICAL", severity="CRITICAL"))), report()
    )

    assert comparison.blocked
    assert comparison.introduced[0].severity == "CRITICAL"


@pytest.mark.parametrize("severity", ["HIGH", "CRITICAL"])
def test_introduced_unfixed_finding_blocks(severity: str) -> None:
    comparison = compare(
        report(result(vulnerability("CVE-UNFIXED", severity=severity, fixed=None))),
        report(),
    )

    assert comparison.blocked
    assert comparison.introduced[0].fixed_version == ""
    assert "fixed=<none>" in comparator.render_comparison(comparison)


def test_inherited_finding_is_reported_and_passes() -> None:
    finding = vulnerability("CVE-INHERITED")
    comparison = compare(
        report(result(finding, target="derivative:reviewed (debian 12)")),
        report(result(finding, target="upstream@sha256:digest (debian 12)")),
    )

    assert not comparison.blocked
    assert len(comparison.inherited) == 1
    assert not comparison.introduced
    output = comparator.render_comparison(comparison)
    assert "Inherited HIGH/CRITICAL findings requiring impact review: 1" in output
    assert "PASS:" in output


def test_upstream_only_finding_is_removed_and_passes() -> None:
    comparison = compare(report(), report(result(vulnerability("CVE-REMOVED"))))

    assert not comparison.blocked
    assert len(comparison.removed) == 1
    assert not comparison.introduced


def test_duplicate_records_are_deduplicated() -> None:
    finding = vulnerability("CVE-DUPLICATE")
    comparison = compare(report(result(finding, finding)), report())

    assert len(comparison.introduced) == 1
    output = comparator.render_comparison(comparison)
    assert output.count('vulnerability="CVE-DUPLICATE"') == 1


def test_distinct_package_and_target_contexts_are_not_conflated() -> None:
    inherited = vulnerability("CVE-SHARED", package="alpha", package_id="alpha@1.0")
    other_package = vulnerability("CVE-SHARED", package="beta", package_id="beta@1.0")
    other_target = vulnerability("CVE-SHARED", package="alpha", package_id="alpha@1.0")
    upstream = report(
        result(
            inherited,
            target="usr/lib/python/site-packages",
            result_class="lang-pkgs",
            result_type="python-pkg",
        )
    )
    derivative = report(
        result(
            inherited,
            other_package,
            target="usr/lib/python/site-packages",
            result_class="lang-pkgs",
            result_type="python-pkg",
        ),
        result(
            other_target,
            target="opt/application/site-packages",
            result_class="lang-pkgs",
            result_type="python-pkg",
        ),
    )

    comparison = compare(derivative, upstream)

    assert len(comparison.inherited) == 1
    assert len(comparison.introduced) == 2
    assert {
        (finding.identity.package_name, finding.identity.target)
        for finding in comparison.introduced
    } == {
        ("beta", "usr/lib/python/site-packages"),
        ("alpha", "opt/application/site-packages"),
    }


def test_distinct_package_ids_in_one_target_are_not_conflated() -> None:
    first = vulnerability("CVE-SHARED", package_id="module-a:example-package@1.0")
    second = vulnerability("CVE-SHARED", package_id="module-b:example-package@1.0")
    context = {
        "target": "application.jar",
        "result_class": "lang-pkgs",
        "result_type": "jar",
    }

    comparison = compare(
        report(result(first, second, **context)), report(result(first, **context))
    )

    assert len(comparison.inherited) == 1
    assert len(comparison.introduced) == 1
    assert (
        comparison.introduced[0].identity.package_id == "module-b:example-package@1.0"
    )


@pytest.mark.parametrize(
    "malformed",
    [
        [],
        {},
        {"SchemaVersion": True, "ArtifactType": "container_image"},
        {"SchemaVersion": 1, "ArtifactType": "container_image"},
        {"SchemaVersion": 2, "ArtifactType": "filesystem"},
        {"SchemaVersion": 2, "ArtifactType": "container_image"},
        {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": None},
        {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": []},
        {"SchemaVersion": 2, "ArtifactType": "container_image", "Results": {}},
    ],
)
def test_malformed_top_level_json_fails_closed(malformed: object) -> None:
    with pytest.raises(comparator.InvalidReportError):
        comparator.normalize_findings(malformed, "derivative")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "malformed_result",
    [
        "not-an-object",
        {},
        {"Class": "os-pkgs", "Type": "debian"},
        {"Target": "image (debian 12)", "Type": "debian"},
        {"Target": "image (debian 12)", "Class": "os-pkgs"},
        result() | {"Vulnerabilities": {}},
        {
            "Target": "image (debian 12)",
            "Class": "os-pkgs",
            "Type": "debian",
            "Vulnerabilities": ["not-an-object"],
        },
        result({"PkgName": "missing-required-fields"}),
        result(vulnerability("CVE-WRONG-SCOPE", severity="MEDIUM")),
        result(vulnerability("CVE-NULL", fixed=None) | {"FixedVersion": None}),
    ],
)
def test_malformed_result_or_finding_fails_closed(malformed_result: object) -> None:
    malformed_report = report()
    malformed_report["Results"] = [malformed_result]

    with pytest.raises(comparator.InvalidReportError):
        comparator.normalize_findings(malformed_report, "derivative")


@pytest.mark.parametrize(
    "empty_report",
    [
        report(),
        report(result() | {"Vulnerabilities": []}),
        report(
            result(
                target="requirements.txt",
                result_class="lang-pkgs",
                result_type="python-pkg",
            )
        ),
    ],
)
def test_empty_valid_scan_passes(empty_report: dict[str, object]) -> None:
    comparison = compare(empty_report, report())

    assert not comparison.blocked
    assert not comparison.introduced
    assert not comparison.inherited
    assert not comparison.removed


def test_mixed_inherited_and_introduced_findings_blocks_for_introduced() -> None:
    inherited = vulnerability("CVE-INHERITED")
    introduced = vulnerability("CVE-INTRODUCED", severity="CRITICAL", fixed=None)
    comparison = compare(
        report(result(inherited, introduced)), report(result(inherited))
    )

    assert comparison.blocked
    assert len(comparison.inherited) == 1
    assert len(comparison.introduced) == 1
    assert comparison.introduced[0].identity.vulnerability_id == "CVE-INTRODUCED"


def test_output_order_is_deterministic() -> None:
    critical = vulnerability("CVE-Z", severity="CRITICAL")
    high_a = vulnerability("CVE-A")
    high_b = vulnerability("CVE-B")

    forward = compare(report(result(critical, high_b, high_a)), report())
    reverse = compare(report(result(high_a, high_b, critical)), report())

    assert comparator.render_comparison(forward) == comparator.render_comparison(
        reverse
    )
    assert [finding.identity.vulnerability_id for finding in forward.introduced] == [
        "CVE-Z",
        "CVE-A",
        "CVE-B",
    ]


def test_conflicting_duplicate_metadata_fails_closed() -> None:
    high = vulnerability("CVE-CONFLICT", severity="HIGH")
    critical = vulnerability("CVE-CONFLICT", severity="CRITICAL")

    with pytest.raises(
        comparator.InvalidReportError, match="conflicting duplicate findings"
    ):
        comparator.normalize_findings(report(result(high, critical)), "derivative")


def test_cli_returns_policy_and_invalid_report_exit_codes(tmp_path, capsys) -> None:
    derivative_path = tmp_path / "derivative.json"
    upstream_path = tmp_path / "upstream.json"
    derivative_path.write_text(
        json.dumps(report(result(vulnerability("CVE-CLI")))), encoding="utf-8"
    )
    upstream_path.write_text(json.dumps(report()), encoding="utf-8")

    assert comparator.main([str(derivative_path), str(upstream_path)]) == 1
    assert "BLOCKED:" in capsys.readouterr().out

    derivative_path.write_text("", encoding="utf-8")
    assert comparator.main([str(derivative_path), str(upstream_path)]) == 2
    captured = capsys.readouterr()
    assert "failed closed" in captured.err
    assert not captured.out


def test_duplicate_json_keys_fail_closed(tmp_path) -> None:
    path = tmp_path / "duplicate.json"
    path.write_text(
        '{"SchemaVersion":2,"SchemaVersion":2,"ArtifactType":"container_image"}',
        encoding="utf-8",
    )

    with pytest.raises(comparator.InvalidReportError, match="duplicate object key"):
        comparator.load_report(path, "derivative")
