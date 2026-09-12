"""Application orchestration through Stage 7's explicit device seams.

There is deliberately no CLI configuration loader.
Preparation signs through OPNsense but does not mutate UniFi. Optional installation
requires an explicitly supplied UniFi adapter. Supplying a live endpoint additionally
requires fresh TLS verification and crash-safe finalisation. Production callers
use the fixed, permission-controlled key-owner-local Unix-socket adapter.
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
from unifi_tls import (
    DEFAULT_READINESS_POLICY,
    EndpointNotReadyError,
    LiveTLSEndpoint,
    ReadinessPolicy,
    ServedCertificateMismatchError,
    TLSAuthenticationError,
    TLSHandshakeError,
    prepare_live_tls_verification,
    verify_prepared_live_tls_certificate,
)


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
    lifetime_days: int = 30,
    digest: str = "sha384",
    install: bool = False,
    live_endpoint: LiveTLSEndpoint | None = None,
    readiness: ReadinessPolicy = DEFAULT_READINESS_POLICY,
) -> InstallationStageResult:
    """Inspect, issue, optionally install, verify live TLS, and finalise.

    This is not a dry run: even with install=False, signing creates a public
    certificate in OPNsense. There are no automatic retries of state changes.
    The configured issuing CA is independent of the OPNsense HTTPS trust store.
    """

    stage = "configuration validation"
    try:
        live_verification = None
        if type(install) is not bool:
            raise ValueError("install must be a boolean")
        if live_endpoint is not None and not install:
            raise ValueError("live TLS verification requires installation")
        if (
            type(lifetime_days) is not int
            or not 1 <= lifetime_days <= 397
            or digest not in {"sha256", "sha384", "sha512"}
        ):
            raise ValueError("invalid signing policy")
        ca_pem = validate_installation_ca(trusted_ca_data)
        if live_endpoint is not None:
            live_verification = prepare_live_tls_verification(
                endpoint=live_endpoint,
                readiness=readiness,
                trusted_ca_data=ca_pem,
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
        request = CertificateImportRequest(
            before, policy, csr_pem, issued, ca_pem, lifetime_days
        )
        plan = prepare_certificate_import(request)
        if not install:
            return InstallationStageResult("prepared", request, plan, None)
        stage = "UniFi installation or verification; keystore may have changed"
        installed = unifi.install_certificate(request)
        if live_endpoint is None:
            return InstallationStageResult(
                "installed_pending_live_verification", request, plan, installed
            )
        stage = "live UniFi TLS verification"
        try:
            verify_prepared_live_tls_certificate(
                prepared=live_verification,
                expected_leaf_der=plan.certificate_chain_der[0],
            )
        except EndpointNotReadyError:
            stage = "UniFi TLS endpoint readiness"
            raise
        except TLSAuthenticationError:
            stage = "UniFi TLS chain or hostname authentication"
            raise
        except TLSHandshakeError:
            stage = "UniFi TLS handshake"
            raise
        except ServedCertificateMismatchError:
            stage = "exact served-certificate comparison"
            raise
        stage = "verified transaction finalisation"
        unifi.finalize_live_verification(plan.certificate_chain_der[0])
        return InstallationStageResult("renewal_complete", request, plan, installed)
    except Exception:
        raise RenewalStageError(f"Renewal stopped during {stage}") from None
