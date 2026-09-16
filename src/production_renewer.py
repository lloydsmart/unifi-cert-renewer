"""Strict one-shot production entrypoint for the unprivileged renewer."""

import json
import math
import sys
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from certificate import (
    MAX_CERTIFICATE_LIFETIME_DAYS,
    MAX_TRUST_BUNDLE_BYTES,
    CertificateInfo,
    validate_installation_ca,
)
from csr import CSRInfo
from opnsense_client import OPNsenseClient, validate_base_url
from secure_file import SecureFileError, open_secure_file, validate_secure_filename
from unifi_cert_renewer import InstallationStageResult, run_to_installation
from unifi_client import (
    CertificatePolicy,
    UnifiClient,
    build_unifi_csr_command,
    inspect_public_keystore_state,
    validate_requested_csr,
)
from unifi_executor_service import SocketUnifiExecutionBoundary
from unifi_tls import (
    LiveTLSEndpoint,
    ReadinessPolicy,
    validate_live_tls_configuration,
)

CONFIG_NAME = "renewer-config.json"
MAX_CONFIG_BYTES = 64 * 1024
MODES = frozenset({"inspect", "csr", "prepare", "install", "renew"})
Mode = Literal["inspect", "csr", "prepare", "install", "renew"]
DEFAULT_RENEW_BEFORE_DAYS = 30
_UNSAFE_TEXT_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


class ProductionConfigurationError(ValueError):
    """Safe-to-display invalid production configuration."""


class ProductionRunError(ValueError):
    """A bounded operator-facing one-shot failure."""


class _DuplicateJSONKeyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProductionConfig:
    policy: CertificatePolicy
    opnsense_base_url: str
    opnsense_timeout_seconds: float
    opnsense_tls_ca_name: str | None
    issuing_ca_description: str
    certificate_description: str
    trusted_ca_name: str
    lifetime_days: int
    renew_before_days: int
    digest: str
    live_endpoint: LiveTLSEndpoint | None
    readiness: ReadinessPolicy | None


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError
        result[key] = value
    return result


def _object_fields(value, required_fields, label, *, optional_fields=frozenset()):
    if not isinstance(value, dict):
        raise ProductionConfigurationError(f"{label} fields are invalid")
    keys = set(value)
    required = set(required_fields)
    allowed = required | set(optional_fields)
    if not required <= keys or not keys <= allowed:
        raise ProductionConfigurationError(f"{label} fields are invalid")
    return value


def _exact_object(value, fields, label):
    return _object_fields(value, fields, label)


def _safe_text(value, label, maximum=255):
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ProductionConfigurationError(f"{label} is invalid")
    if any(
        unicodedata.category(character) in _UNSAFE_TEXT_CATEGORIES
        for character in value
    ):
        raise ProductionConfigurationError(f"{label} is invalid")
    return value


def _string_tuple(value, label):
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ProductionConfigurationError(f"{label} is invalid")
    return tuple(value)


def _positive_number(value, label):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ProductionConfigurationError(f"{label} is invalid")
    return float(value)


def _nonnegative_number(value, label):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value < 0
    ):
        raise ProductionConfigurationError(f"{label} is invalid")
    return float(value)


def _parse_live_tls(value):
    if value is None:
        return None, None
    value = _exact_object(
        value,
        {
            "address",
            "server_hostname",
            "port",
            "timeout_seconds",
            "attempt_timeout_seconds",
            "retry_delay_seconds",
            "max_attempts",
        },
        "live_tls",
    )
    endpoint = LiveTLSEndpoint(
        value["address"], value["server_hostname"], value["port"]
    )
    readiness = ReadinessPolicy(
        _positive_number(value["timeout_seconds"], "live_tls timeout_seconds"),
        _positive_number(
            value["attempt_timeout_seconds"], "live_tls attempt_timeout_seconds"
        ),
        _nonnegative_number(
            value["retry_delay_seconds"], "live_tls retry_delay_seconds"
        ),
        value["max_attempts"],
    )
    try:
        validate_live_tls_configuration(endpoint, readiness)
    except (TypeError, ValueError):
        raise ProductionConfigurationError(
            "live_tls configuration is invalid"
        ) from None
    return endpoint, readiness


def _parse_config(value) -> ProductionConfig:
    value = _object_fields(
        value,
        {
            "certificate_policy",
            "opnsense",
            "issuing_ca_description",
            "certificate_description",
            "trusted_ca_name",
            "lifetime_days",
            "digest",
            "live_tls",
        },
        "configuration",
        optional_fields={"renew_before_days"},
    )
    policy_value = _exact_object(
        value["certificate_policy"],
        {"expected_spki_sha256", "subject", "dns_sans", "ip_sans"},
        "certificate_policy",
    )
    policy = CertificatePolicy(
        expected_spki_sha256=policy_value["expected_spki_sha256"],
        subject=policy_value["subject"],
        dns_sans=_string_tuple(policy_value["dns_sans"], "dns_sans"),
        ip_sans=_string_tuple(policy_value["ip_sans"], "ip_sans"),
    )
    try:
        build_unifi_csr_command(policy)
    except (TypeError, ValueError):
        raise ProductionConfigurationError("certificate_policy is invalid") from None

    opnsense = _exact_object(
        value["opnsense"],
        {"base_url", "timeout_seconds", "tls_ca_name"},
        "opnsense",
    )
    try:
        base_url = validate_base_url(opnsense["base_url"])
    except (TypeError, ValueError):
        raise ProductionConfigurationError("opnsense base_url is invalid") from None
    timeout = _positive_number(opnsense["timeout_seconds"], "opnsense timeout_seconds")
    tls_ca_name = opnsense["tls_ca_name"]
    if tls_ca_name is not None:
        try:
            tls_ca_name = validate_secure_filename(
                tls_ca_name, source_name="OPNsense TLS CA file"
            )
        except (TypeError, SecureFileError):
            raise ProductionConfigurationError(
                "opnsense tls_ca_name is invalid"
            ) from None

    try:
        trusted_ca_name = validate_secure_filename(
            value["trusted_ca_name"], source_name="Issuing CA file"
        )
    except (TypeError, SecureFileError):
        raise ProductionConfigurationError("trusted_ca_name is invalid") from None
    lifetime_days = value["lifetime_days"]
    renew_before_days = value.get("renew_before_days", DEFAULT_RENEW_BEFORE_DAYS)
    digest = value["digest"]
    if (
        type(lifetime_days) is not int
        or not 1 <= lifetime_days <= 397
        or not isinstance(digest, str)
        or digest not in {"sha256", "sha384", "sha512"}
    ):
        raise ProductionConfigurationError("signing policy is invalid")
    if (
        type(renew_before_days) is not int
        or not 1 <= renew_before_days <= MAX_CERTIFICATE_LIFETIME_DAYS
    ):
        raise ProductionConfigurationError("renewal policy is invalid")
    live_endpoint, readiness = _parse_live_tls(value["live_tls"])
    return ProductionConfig(
        policy=policy,
        opnsense_base_url=base_url,
        opnsense_timeout_seconds=timeout,
        opnsense_tls_ca_name=tls_ca_name,
        issuing_ca_description=_safe_text(
            value["issuing_ca_description"], "issuing_ca_description"
        ),
        certificate_description=_safe_text(
            value["certificate_description"], "certificate_description"
        ),
        trusted_ca_name=trusted_ca_name,
        lifetime_days=lifetime_days,
        renew_before_days=renew_before_days,
        digest=digest,
        live_endpoint=live_endpoint,
        readiness=readiness,
    )


def load_production_config() -> ProductionConfig:
    """Load the fixed, bounded config file beneath ``/run/secrets``."""

    try:
        with open_secure_file(CONFIG_NAME, source_name="Renewer configuration") as file:
            data = file.read(MAX_CONFIG_BYTES + 1)
    except (OSError, SecureFileError):
        raise ProductionConfigurationError(
            "Renewer configuration could not be read safely"
        ) from None
    if len(data) > MAX_CONFIG_BYTES:
        raise ProductionConfigurationError(
            "Renewer configuration exceeds the size limit"
        )
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_json_object)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJSONKeyError):
        raise ProductionConfigurationError(
            "Renewer configuration is invalid JSON"
        ) from None
    return _parse_config(value)


def build_production_unifi_client() -> UnifiClient:
    """Construct the sole supported production UniFi access path."""

    return UnifiClient(SocketUnifiExecutionBoundary())


def _read_trusted_ca(name: str) -> bytes:
    try:
        with open_secure_file(name, source_name="Issuing CA file") as file:
            data = file.read(MAX_TRUST_BUNDLE_BYTES + 1)
        if len(data) > MAX_TRUST_BUNDLE_BYTES:
            raise ValueError
        return validate_installation_ca(data)
    except Exception:
        raise ProductionRunError(
            "Renewer stopped during issuing CA validation"
        ) from None


def _certificate_output(info):
    return {
        "subject": info.subject,
        "issuer": info.issuer,
        "serial_number": info.serial_number,
        "not_valid_before": info.not_valid_before.isoformat(),
        "not_valid_after": info.not_valid_after.isoformat(),
        "certificate_sha256": info.certificate_sha256,
        "spki_sha256": info.spki_sha256,
        "dns_sans": list(info.dns_sans),
        "ip_sans": list(info.ip_sans),
    }


def _csr_output(info: CSRInfo):
    return {
        "subject": info.subject,
        "spki_sha256": info.spki_sha256,
        "public_key_algorithm": info.public_key_algorithm,
        "public_key_size": info.public_key_size,
        "dns_sans": list(info.dns_sans),
        "ip_sans": list(info.ip_sans),
        "signature_valid": info.signature_valid,
    }


def _renewal_output(result: InstallationStageResult, mode: Mode):
    output_mode = "install" if result.installed is not None else "prepare"
    if mode == "renew":
        output_mode = mode
    return {
        "mode": output_mode,
        "state": result.state,
        "renewal_complete": result.renewal_complete,
        "issued_certificate": _certificate_output(result.plan.issued),
    }


def _renewal_is_due(
    certificate: CertificateInfo,
    renew_before_days: int,
    *,
    now: datetime | None = None,
) -> bool:
    current_time = datetime.now(UTC) if now is None else now
    if not isinstance(current_time, datetime) or current_time.tzinfo is None:
        raise ValueError("current time must be timezone-aware")
    return certificate.not_valid_after <= current_time.astimezone(UTC) + timedelta(
        days=renew_before_days
    )


def run_one_shot(mode: Mode, *, now: datetime | None = None):
    """Run exactly one selected mode without scheduling or state-changing retry."""

    if mode not in MODES:
        raise ProductionRunError("Renewer mode is invalid")
    try:
        config = load_production_config()
    except Exception:
        raise ProductionRunError(
            "Renewer stopped during configuration validation"
        ) from None
    unifi = build_production_unifi_client()
    try:
        if mode == "inspect":
            state = unifi.inspect_current(config.policy)
            return {
                "mode": mode,
                "certificate": _certificate_output(
                    inspect_public_keystore_state(state).certificate
                ),
            }
        if mode == "csr":
            csr_pem = unifi.request_csr(config.policy)
            return {
                "mode": mode,
                "csr": _csr_output(validate_requested_csr(csr_pem, config.policy)),
            }
        if mode == "renew":
            state = unifi.inspect_current(config.policy)
            certificate = inspect_public_keystore_state(state).certificate
            if not _renewal_is_due(certificate, config.renew_before_days, now=now):
                return {
                    "mode": mode,
                    "state": "renewal_not_due",
                    "renewal_due": False,
                    "renewal_complete": False,
                    "renew_before_days": config.renew_before_days,
                    "certificate": _certificate_output(certificate),
                }
    except Exception:
        raise ProductionRunError(f"Renewer stopped during {mode}") from None

    install = mode in {"install", "renew"}
    if mode == "renew" and (config.live_endpoint is None or config.readiness is None):
        raise ProductionRunError(
            f"Renewer stopped because {mode} requires live TLS verification"
        )
    trusted_ca_data = _read_trusted_ca(config.trusted_ca_name)
    if mode == "install" and (config.live_endpoint is None or config.readiness is None):
        raise ProductionRunError(
            "Renewer stopped because install requires live TLS verification"
        )
    try:
        opnsense = OPNsenseClient(
            config.opnsense_base_url,
            timeout=config.opnsense_timeout_seconds,
            tls_ca_name=config.opnsense_tls_ca_name,
        )
    except Exception:
        raise ProductionRunError(
            "Renewer stopped during OPNsense client configuration"
        ) from None
    try:
        result = run_to_installation(
            unifi=unifi,
            opnsense=opnsense,
            policy=config.policy,
            trusted_ca_data=trusted_ca_data,
            ca_description=config.issuing_ca_description,
            certificate_description=config.certificate_description,
            lifetime_days=config.lifetime_days,
            digest=config.digest,
            install=install,
            live_endpoint=config.live_endpoint if install else None,
            readiness=config.readiness if install else ReadinessPolicy(),
        )
    except Exception:
        raise ProductionRunError(f"Renewer stopped during {mode}") from None
    output = _renewal_output(result, mode)
    if mode == "renew":
        output.update(
            renewal_due=True,
            renew_before_days=config.renew_before_days,
        )
    return output


def main(argv=None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if len(arguments) != 1 or arguments[0] not in MODES:
        print(
            "Usage: production_renewer.py {inspect|csr|prepare|install|renew}",
            file=sys.stderr,
        )
        return 2
    try:
        result = run_one_shot(arguments[0])
    except ProductionRunError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
