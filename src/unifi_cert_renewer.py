"""Application orchestration through Stage 7's explicit device seams.

There is deliberately no CLI configuration loader.
Preparation signs through OPNsense but does not mutate UniFi. Optional installation
requires an explicitly supplied UniFi adapter and requests the executor's own
live TLS verification before reporting completion. Production callers use the
fixed, permission-controlled key-owner-local Unix-socket adapter.
"""

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from certificate import validate_issued_signature_policy
from opnsense_client import OPNsenseClient
from unifi_client import (
    CertificateImportPlan,
    CertificateImportRequest,
    CertificatePolicy,
    UnifiCertificateInspection,
    UnifiClient,
    prepare_certificate_import,
    validate_requested_csr,
)


def _current_time() -> datetime:
    return datetime.now(UTC)


class RenewalStageError(ValueError):
    """A failed stage, with no untrusted diagnostics in the operator message."""


@dataclass(frozen=True, slots=True)
class InstallationStageResult:
    """Public evidence for preparation, pending verification, or completion."""

    state: Literal[
        "prepared", "installed_pending_live_verification", "renewal_complete"
    ]
    request: CertificateImportRequest
    plan: CertificateImportPlan
    installed: UnifiCertificateInspection | None

    @property
    def renewal_complete(self) -> bool:
        return self.state == "renewal_complete"


def run_to_installation(
    *,
    unifi: UnifiClient,
    opnsense: OPNsenseClient,
    policy: CertificatePolicy,
    trusted_ca_data: bytes,
    ca_description: str,
    certificate_description: str,
    issued_signature_oid: str,
    lifetime_days: int = 30,
    digest: str = "sha384",
    install: bool = False,
    minimum_remaining_days: int | None = None,
) -> InstallationStageResult:
    """Inspect, issue, optionally install, verify live TLS, and finalise.

    This is not a dry run: even with install=False, signing creates a public
    certificate in OPNsense. There are no automatic retries of state changes.
    The configured issuing CA is independent of the OPNsense HTTPS trust store.
    """

    stage = "configuration validation"
    try:
        if type(install) is not bool:
            raise ValueError("install must be a boolean")
        if type(lifetime_days) is not int or not 1 <= lifetime_days <= 397:
            raise ValueError("invalid signing policy")
        if minimum_remaining_days is not None and (
            type(minimum_remaining_days) is not int
            or not 1 <= minimum_remaining_days <= 397
        ):
            raise ValueError("invalid minimum remaining lifetime")
        ca_pem = validate_issued_signature_policy(
            trusted_ca_data, digest, issued_signature_oid
        )
        stage = "current UniFi inspection"
        before = unifi.inspect_current(policy)
        stage = "CSR generation and validation"
        csr_pem = unifi.request_csr(policy)
        csr_info = validate_requested_csr(csr_pem, policy)
        stage = "OPNsense CA resolution"
        caref = opnsense.resolve_ca(ca_description)
        stage = "OPNsense signing; issuance may have occurred"
        certificate_uuid = opnsense.sign_csr(
            csr_pem,
            csr_info,
            expected_spki_sha256=policy.expected_spki_sha256,
            caref=caref,
            digest=digest,
            lifetime_days=lifetime_days,
            description=certificate_description,
        )
        stage = "issued public certificate retrieval"
        issued = opnsense.get_certificate(certificate_uuid)
        stage = "issued certificate and installation validation"
        validation_time = _current_time()
        request = CertificateImportRequest(
            before,
            policy,
            csr_pem,
            issued,
            ca_pem,
            lifetime_days,
            digest,
            issued_signature_oid,
            validation_time,
        )
        plan = prepare_certificate_import(request)
        if (
            minimum_remaining_days is not None
            and plan.issued.not_valid_after
            <= validation_time + timedelta(days=minimum_remaining_days)
        ):
            raise ValueError("issued certificate remains in renewal window")
        if not install:
            return InstallationStageResult("prepared", request, plan, None)
        stage = "UniFi installation or verification; keystore may have changed"
        installed = unifi.install_certificate(request)
        stage = "trusted live UniFi TLS verification"
        unifi.verify_pending()
        return InstallationStageResult("renewal_complete", request, plan, installed)
    except Exception:
        raise RenewalStageError(f"Renewal stopped during {stage}") from None
