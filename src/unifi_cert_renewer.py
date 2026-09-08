"""First application entrypoint: prepare stage 6 through explicit device seams.

There is deliberately no production command runner or CLI configuration loader.
Preparation signs through OPNsense but does not mutate UniFi. Optional installation
requires an explicitly supplied UniFi adapter; no such adapter ships here.
"""

from dataclasses import dataclass
from typing import Literal

from certificate import validate_installation_ca
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


class RenewalStageError(ValueError):
    """A failed stage, with no untrusted diagnostics in the operator message."""


@dataclass(frozen=True, slots=True)
class InstallationStageResult:
    """Stage 6 evidence only. Neither state is a completed renewal."""

    state: Literal["prepared", "installed_pending_live_verification"]
    request: CertificateImportRequest
    plan: CertificateImportPlan
    installed: UnifiCertificateInspection | None

    @property
    def renewal_complete(self) -> Literal[False]:
        return False


def run_to_installation(
    *,
    unifi: UnifiClient,
    opnsense: OPNsenseClient,
    policy: CertificatePolicy,
    trusted_ca_data: bytes,
    ca_description: str,
    certificate_description: str,
    lifetime_days: int = 30,
    digest: str = "sha384",
    install: bool = False,
) -> InstallationStageResult:
    """Inspect -> CSR -> sign -> retrieve -> validate -> guarded installation seam.

    This is not a dry run: even with install=False, signing creates a public
    certificate in OPNsense. There are no automatic retries of state changes.
    The configured issuing CA is independent of the OPNsense HTTPS trust store.
    """

    stage = "configuration validation"
    try:
        if type(install) is not bool:
            raise ValueError("install must be a boolean")
        if (
            type(lifetime_days) is not int
            or not 1 <= lifetime_days <= 397
            or digest not in {"sha256", "sha384", "sha512"}
        ):
            raise ValueError("invalid signing policy")
        ca_pem = validate_installation_ca(trusted_ca_data)
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
        request = CertificateImportRequest(
            before, policy, csr_pem, issued, ca_pem, lifetime_days
        )
        plan = prepare_certificate_import(request)
        if not install:
            return InstallationStageResult("prepared", request, plan, None)
        stage = "UniFi installation or verification; keystore may have changed"
        installed = unifi.install_certificate(request)
        return InstallationStageResult(
            "installed_pending_live_verification", request, plan, installed
        )
    except Exception:
        raise RenewalStageError(f"Renewal stopped during {stage}") from None
