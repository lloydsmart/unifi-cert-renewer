#!/usr/bin/env python3
"""Compare HIGH/CRITICAL findings from two Trivy container reports."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

TRIVY_SCHEMA_VERSION = 2
MAX_REPORT_BYTES = 128 * 1024 * 1024
BLOCKING_SEVERITIES = frozenset({"HIGH", "CRITICAL"})
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1}


class InvalidReportError(ValueError):
    """Raised when a Trivy report cannot be compared safely."""


@dataclass(frozen=True, order=True)
class FindingIdentity:
    """A component identity stable across derivative and upstream artifacts."""

    result_class: str
    result_type: str
    target: str
    vulnerability_id: str
    package_name: str
    package_id: str
    package_path: str
    installed_version: str


@dataclass(frozen=True)
class Finding:
    identity: FindingIdentity
    severity: str
    fixed_version: str


@dataclass(frozen=True)
class Comparison:
    introduced: tuple[Finding, ...]
    inherited: tuple[Finding, ...]
    removed: tuple[Finding, ...]

    @property
    def blocked(self) -> bool:
        return bool(self.introduced)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise InvalidReportError("JSON contains a duplicate object key")
        result[key] = value
    return result


def load_report(path: Path, role: str) -> dict[str, Any]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise InvalidReportError(f"{role} report is not readable") from error

    if size == 0:
        raise InvalidReportError(f"{role} report is empty")
    if size > MAX_REPORT_BYTES:
        raise InvalidReportError(f"{role} report exceeds the size limit")

    try:
        with path.open(encoding="utf-8") as report_file:
            report = json.load(report_file, object_pairs_hook=_reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise InvalidReportError(f"{role} report is not valid UTF-8 JSON") from error

    if not isinstance(report, dict):
        raise InvalidReportError(f"{role} report must be a JSON object")
    return report


def _required_text(value: Any, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise InvalidReportError(f"{description} must be non-empty text")
    return value


def _optional_text(container: dict[str, Any], key: str, description: str) -> str:
    if key not in container:
        return ""
    value = container[key]
    if not isinstance(value, str):
        raise InvalidReportError(f"{description} must be text when present")
    return value


def _os_target(report: dict[str, Any]) -> str:
    # Trivy's OS-result Target contains the scanned image name. Metadata.OS is
    # the stable component context shared by exact upstream and derivative scans.
    metadata = report.get("Metadata")
    if not isinstance(metadata, dict):
        raise InvalidReportError("OS findings require object Metadata")
    operating_system = metadata.get("OS")
    if not isinstance(operating_system, dict):
        raise InvalidReportError("OS findings require object Metadata.OS")
    family = _required_text(operating_system.get("Family"), "Metadata.OS.Family")
    name = _required_text(operating_system.get("Name"), "Metadata.OS.Name")
    return f"os:{family}/{name}"


def normalize_findings(
    report: dict[str, Any], role: str
) -> dict[FindingIdentity, Finding]:
    if not isinstance(report, dict):
        raise InvalidReportError(f"{role} report must be a JSON object")
    schema_version = report.get("SchemaVersion")
    if isinstance(schema_version, bool) or schema_version != TRIVY_SCHEMA_VERSION:
        raise InvalidReportError(
            f"{role} report does not use Trivy schema version {TRIVY_SCHEMA_VERSION}"
        )
    if report.get("ArtifactType") != "container_image":
        raise InvalidReportError(f"{role} report is not a container-image report")

    if "Results" not in report:
        raise InvalidReportError(f"{role} report is missing Results")
    results = report["Results"]
    if not isinstance(results, list):
        raise InvalidReportError(f"{role} report Results must be an array")
    if not results:
        raise InvalidReportError(f"{role} report Results must not be empty")

    normalized: dict[FindingIdentity, Finding] = {}
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise InvalidReportError(f"{role} result {result_index} must be an object")

        target = _required_text(result.get("Target"), "result Target")
        result_class = _required_text(result.get("Class"), "result Class")
        result_type = _required_text(result.get("Type"), "result Type")
        stable_target = _os_target(report) if result_class == "os-pkgs" else target

        vulnerabilities = result.get("Vulnerabilities", [])
        if not isinstance(vulnerabilities, list):
            raise InvalidReportError(
                f"{role} result {result_index} Vulnerabilities must be an array"
            )
        if not vulnerabilities:
            continue

        for finding_index, vulnerability in enumerate(vulnerabilities):
            if not isinstance(vulnerability, dict):
                raise InvalidReportError(
                    f"{role} result {result_index} finding {finding_index} "
                    "must be an object"
                )

            severity = _required_text(vulnerability.get("Severity"), "finding Severity")
            if severity not in BLOCKING_SEVERITIES:
                raise InvalidReportError(
                    f"{role} report contains a finding outside the requested "
                    "HIGH/CRITICAL severity scope"
                )

            identity = FindingIdentity(
                # Trivy's Fingerprint includes ArtifactID, and Layer identifies
                # image construction rather than the vulnerable component.
                result_class=result_class,
                result_type=result_type,
                target=stable_target,
                vulnerability_id=_required_text(
                    vulnerability.get("VulnerabilityID"), "finding VulnerabilityID"
                ),
                package_name=_required_text(
                    vulnerability.get("PkgName"), "finding PkgName"
                ),
                package_id=_optional_text(vulnerability, "PkgID", "finding PkgID"),
                package_path=_optional_text(
                    vulnerability, "PkgPath", "finding PkgPath"
                ),
                installed_version=_required_text(
                    vulnerability.get("InstalledVersion"),
                    "finding InstalledVersion",
                ),
            )
            finding = Finding(
                identity=identity,
                severity=severity,
                fixed_version=_optional_text(
                    vulnerability, "FixedVersion", "finding FixedVersion"
                ),
            )
            previous = normalized.get(identity)
            if previous is not None and previous != finding:
                raise InvalidReportError(
                    f"{role} report contains conflicting duplicate findings"
                )
            normalized[identity] = finding

    return normalized


def _finding_sort_key(finding: Finding) -> tuple[Any, ...]:
    identity = finding.identity
    return (
        SEVERITY_ORDER[finding.severity],
        identity.vulnerability_id,
        identity.package_name,
        identity.installed_version,
        identity.result_class,
        identity.result_type,
        identity.target,
        identity.package_id,
        identity.package_path,
    )


def compare_reports(
    derivative_report: dict[str, Any], upstream_report: dict[str, Any]
) -> Comparison:
    derivative = normalize_findings(derivative_report, "derivative")
    upstream = normalize_findings(upstream_report, "upstream")
    derivative_keys = set(derivative)
    upstream_keys = set(upstream)

    return Comparison(
        introduced=tuple(
            sorted(
                (derivative[key] for key in derivative_keys - upstream_keys),
                key=_finding_sort_key,
            )
        ),
        inherited=tuple(
            sorted(
                (derivative[key] for key in derivative_keys & upstream_keys),
                key=_finding_sort_key,
            )
        ),
        removed=tuple(
            sorted(
                (upstream[key] for key in upstream_keys - derivative_keys),
                key=_finding_sort_key,
            )
        ),
    )


def _quoted(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def _format_finding(finding: Finding) -> str:
    identity = finding.identity
    fixed_version = (
        _quoted(finding.fixed_version) if finding.fixed_version else "<none>"
    )
    fields = [
        finding.severity,
        f"vulnerability={_quoted(identity.vulnerability_id)}",
        f"package={_quoted(identity.package_name)}",
        f"installed={_quoted(identity.installed_version)}",
        f"fixed={fixed_version}",
        f"class={_quoted(identity.result_class)}",
        f"type={_quoted(identity.result_type)}",
        f"target={_quoted(identity.target)}",
    ]
    if identity.package_id:
        fields.append(f"package_id={_quoted(identity.package_id)}")
    if identity.package_path:
        fields.append(f"package_path={_quoted(identity.package_path)}")
    return "  " + " | ".join(fields)


def render_comparison(comparison: Comparison) -> str:
    lines: list[str] = []
    categories = (
        ("Introduced derivative-only HIGH/CRITICAL findings", comparison.introduced),
        (
            "Inherited HIGH/CRITICAL findings requiring impact review",
            comparison.inherited,
        ),
        ("Removed upstream-only HIGH/CRITICAL findings", comparison.removed),
    )
    for heading, findings in categories:
        lines.append(f"{heading}: {len(findings)}")
        lines.extend(_format_finding(finding) for finding in findings)

    if comparison.blocked:
        lines.append(
            "BLOCKED: derivative-only HIGH/CRITICAL vulnerabilities were found."
        )
    else:
        lines.append(
            "PASS: no derivative-only HIGH/CRITICAL vulnerabilities were found."
        )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare derivative and exact-upstream Trivy JSON reports."
    )
    parser.add_argument("derivative_report", type=Path)
    parser.add_argument("upstream_report", type=Path)
    arguments = parser.parse_args(argv)

    try:
        derivative_report = load_report(arguments.derivative_report, "derivative")
        upstream_report = load_report(arguments.upstream_report, "upstream")
        comparison = compare_reports(derivative_report, upstream_report)
    except InvalidReportError as error:
        print(f"Comparison failed closed: {error}", file=sys.stderr)
        return 2

    print(render_comparison(comparison))
    return 1 if comparison.blocked else 0


if __name__ == "__main__":
    raise SystemExit(main())
