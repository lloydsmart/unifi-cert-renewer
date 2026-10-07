"""Strict one-shot production entrypoint for the unprivileged renewer."""

import argparse
import errno
import fcntl
import json
import math
import os
import stat
import sys
import unicodedata
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal

from certificate import MAX_CERTIFICATE_LIFETIME_DAYS, CertificateInfo
from csr import CSRInfo
from opnsense_client import OPNsenseClient, validate_base_url
from renewal_policy import RenewalPolicy, load_policy
from run_result import Operation, Outcome, Reason, RunEvidence
from secure_file import SecureFileError, open_secure_file, validate_secure_filename
from unifi_cert_renewer import InstallationStageResult, run_to_installation
from unifi_client import (
    CertificatePolicy,
    UnifiClient,
    inspect_public_keystore_state,
    validate_requested_csr,
)
from unifi_executor_service import SocketUnifiExecutionBoundary

CONFIG_NAME = "renewer-config.json"
MAX_CONFIG_BYTES = 64 * 1024
MODES = frozenset({"inspect", "csr", "prepare", "install", "renew"})
Mode = Literal["inspect", "csr", "prepare", "install", "renew"]
DEFAULT_RENEW_BEFORE_DAYS = 30
LIFECYCLE_DIRECTORY = "/run/unifi-cert-renewer-lifecycle"
LIFECYCLE_LOCK = "renewal.lock"
LIFECYCLE_OWNER_UID = 0
LIFECYCLE_GROUP_GID = 1000
_UNSAFE_TEXT_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


class ProductionConfigurationError(ValueError):
    """Safe-to-display invalid production configuration."""


class ProductionRunError(ValueError):
    """A bounded operator-facing one-shot failure."""


class _LifecycleBusy(Exception):
    pass


@contextmanager
def _lifecycle_lock():
    """Serialize a deployment's complete signing and installation lifecycle."""

    directory = lock = None
    try:
        directory = os.open(
            LIFECYCLE_DIRECTORY,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        info = os.fstat(directory)
        if (
            info.st_uid != LIFECYCLE_OWNER_UID
            or info.st_gid != LIFECYCLE_GROUP_GID
            or stat.S_IMODE(info.st_mode) != 0o750
        ):
            raise OSError("unsafe lifecycle directory")
        lock = os.open(
            LIFECYCLE_LOCK,
            os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory,
        )
        file_info = os.fstat(lock)
        if (
            not stat.S_ISREG(file_info.st_mode)
            or file_info.st_uid != LIFECYCLE_OWNER_UID
            or file_info.st_gid != LIFECYCLE_GROUP_GID
            or stat.S_IMODE(file_info.st_mode) != 0o660
            or file_info.st_nlink != 1
            or file_info.st_size != 0
        ):
            raise OSError("unsafe lifecycle lock")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in {errno.EAGAIN, errno.EWOULDBLOCK}:
                raise _LifecycleBusy from None
            raise
        path_info = os.stat(LIFECYCLE_LOCK, dir_fd=directory, follow_symlinks=False)
        current_directory = os.stat(LIFECYCLE_DIRECTORY, follow_symlinks=False)
        if (
            (file_info.st_dev, file_info.st_ino) != (path_info.st_dev, path_info.st_ino)
            or (info.st_dev, info.st_ino)
            != (current_directory.st_dev, current_directory.st_ino)
            or os.fstat(lock).st_nlink != 1
        ):
            raise OSError("lifecycle lock replaced")
    except _LifecycleBusy:
        raise
    except OSError:
        raise ProductionRunError("Renewer lifecycle lock unavailable") from None
    else:
        yield
    finally:
        if lock is not None:
            os.close(lock)
        if directory is not None:
            os.close(directory)


class _DuplicateJSONKeyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ProductionConfig:
    authority: RenewalPolicy
    policy: CertificatePolicy
    opnsense_base_url: str
    opnsense_timeout_seconds: float
    opnsense_tls_ca_name: str | None
    certificate_description: str
    renew_before_days: int


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


def _positive_number(value, label):
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ProductionConfigurationError(f"{label} is invalid")
    return float(value)


def _parse_config(value, authority: RenewalPolicy) -> ProductionConfig:
    value = _object_fields(
        value,
        {"expected_spki_sha256", "opnsense", "certificate_description"},
        "configuration",
        optional_fields={"renew_before_days"},
    )
    policy = authority.certificate_policy(value["expected_spki_sha256"])

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

    renew_before_days = value.get("renew_before_days", DEFAULT_RENEW_BEFORE_DAYS)
    if (
        type(renew_before_days) is not int
        or not 1 <= renew_before_days <= MAX_CERTIFICATE_LIFETIME_DAYS
    ):
        raise ProductionConfigurationError("renewal policy is invalid")
    return ProductionConfig(
        authority=authority,
        policy=policy,
        opnsense_base_url=base_url,
        opnsense_timeout_seconds=timeout,
        opnsense_tls_ca_name=tls_ca_name,
        certificate_description=_safe_text(
            value["certificate_description"], "certificate_description"
        ),
        renew_before_days=renew_before_days,
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
    return _parse_config(value, load_policy())


def build_production_unifi_client(
    authority: RenewalPolicy, *, on_dispatch=None
) -> UnifiClient:
    """Construct the sole supported production UniFi access path."""

    return UnifiClient(
        SocketUnifiExecutionBoundary(
            authority, **({"on_dispatch": on_dispatch} if on_dispatch else {})
        )
    )


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


def run_one_shot(mode: Mode, *, now: datetime | None = None, evidence=None):
    """Run exactly one selected mode without scheduling or state-changing retry."""

    if mode not in MODES:
        raise ProductionRunError("Renewer mode is invalid")
    if mode in {"prepare", "install", "renew"}:
        try:
            if evidence is not None:
                evidence.stage = "lock"
            with _lifecycle_lock():
                return _run_one_shot(mode, now=now, evidence=evidence)
        except _LifecycleBusy:
            if evidence is not None:
                evidence.failure(reason=Reason.LOCK_BUSY)
            return {"mode": mode, "state": "busy", "renewal_complete": False}
    return _run_one_shot(mode, now=now, evidence=evidence)


def _run_one_shot(mode: Mode, *, now: datetime | None = None, evidence=None):
    if evidence is not None:
        evidence.stage = "configuration"
    try:
        config = load_production_config()
    except Exception:
        raise ProductionRunError(
            "Renewer stopped during configuration validation"
        ) from None
    if mode == "renew" and config.renew_before_days >= config.authority.lifetime_days:
        raise ProductionRunError("Renewer stopped during configuration validation")
    unifi = build_production_unifi_client(
        config.authority,
        **({"on_dispatch": evidence.executor_dispatch} if evidence else {}),
    )
    try:
        if mode == "inspect":
            if evidence is not None:
                evidence.stage = "inspection"
            state = unifi.inspect_current(config.policy)
            certificate = inspect_public_keystore_state(state).certificate
            if evidence is not None:
                evidence.certificate = certificate
                evidence.stage = "decision"
                due = _renewal_is_due(certificate, config.renew_before_days, now=now)
                evidence.success(
                    Outcome.ATTENTION_DUE if due else Outcome.SUCCESS_NO_CHANGE,
                    "Certificate renewal attention is due."
                    if due
                    else "Certificate is outside the renewal window.",
                    renewal_due=due,
                )
            return {
                "mode": mode,
                "certificate": _certificate_output(certificate),
            }
        if mode == "csr":
            if evidence is not None:
                evidence.stage = "csr_generation"
            csr_pem = unifi.request_csr(config.policy)
            csr_info = validate_requested_csr(csr_pem, config.policy)
            if evidence is not None:
                evidence.confirm("csr")
                evidence.success(Outcome.SUCCESS_PREPARED, "CSR validated.")
            return {
                "mode": mode,
                "csr": _csr_output(csr_info),
            }
        if mode == "renew":
            if evidence is not None:
                evidence.stage = "inspection"
            state = unifi.inspect_current(config.policy)
            certificate = inspect_public_keystore_state(state).certificate
            if evidence is not None:
                evidence.stage = "decision"
                evidence.certificate = certificate
            if not _renewal_is_due(certificate, config.renew_before_days, now=now):
                if evidence is not None:
                    evidence.success(
                        Outcome.SUCCESS_NO_CHANGE,
                        "Certificate is not due for renewal.",
                        renewal_due=False,
                    )
                return {
                    "mode": mode,
                    "state": "renewal_not_due",
                    "renewal_due": False,
                    "renewal_complete": False,
                    "renew_before_days": config.renew_before_days,
                    "certificate": _certificate_output(certificate),
                }
            if evidence is not None:
                evidence.target.renewal_due = True
                evidence.certificate = None
    except Exception:
        raise ProductionRunError(f"Renewer stopped during {mode}") from None

    install = mode in {"install", "renew"}
    if evidence is not None:
        evidence.stage = "configuration"
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
            trusted_ca_data=config.authority.ca_pem,
            ca_description=config.authority.issuing_ca_description,
            certificate_description=config.certificate_description,
            lifetime_days=config.authority.lifetime_days,
            digest=config.authority.signing_digest,
            issued_signature_oid=config.authority.issued_signature_oid,
            install=install,
            minimum_remaining_days=(
                config.renew_before_days if mode == "renew" else None
            ),
            **({"evidence": evidence} if evidence is not None else {}),
        )
    except Exception:
        raise ProductionRunError(f"Renewer stopped during {mode}") from None
    output = _renewal_output(result, mode)
    if evidence is not None:
        evidence.success(
            Outcome.SUCCESS_CHANGED if install else Outcome.SUCCESS_PREPARED,
            (
                "Certificate renewal verified by live HTTPS."
                if install
                else "Certificate issued and validated."
            ),
            renewal_due=True if mode == "renew" else None,
        )
    if mode == "renew":
        output.update(
            renewal_due=True,
            renew_before_days=config.renew_before_days,
        )
    return output


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError from None


def _parse_arguments(arguments):
    parser = _Parser(add_help=False, allow_abbrev=False, usage=argparse.SUPPRESS)
    parser.add_argument("mode", choices=sorted(MODES))
    parser.add_argument("--output", choices=["json"])
    try:
        parsed = parser.parse_args(arguments)
    except (ValueError, SystemExit):
        print(
            "Usage: production_renewer.py {inspect|csr|prepare|install|renew}",
            file=sys.stderr,
        )
        return None
    return parsed


def main(argv=None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    parsed = _parse_arguments(arguments)
    if parsed is None:
        return 2
    if parsed.output == "json":
        evidence = RunEvidence(
            {
                "inspect": Operation.INSPECT,
                "csr": Operation.GENERATE_CSR,
                "prepare": Operation.SIGN_CSR,
                "install": Operation.INSTALL,
                "renew": Operation.RENEW_DUE,
            }[parsed.mode]
        )
        try:
            with (
                open(os.devnull, "w", encoding="utf-8") as sink,
                redirect_stdout(sink),
                redirect_stderr(sink),
            ):
                legacy = run_one_shot(parsed.mode, evidence=evidence)
        except Exception:
            evidence.failure()
            exit_code = 1
        else:
            exit_code = 75 if legacy.get("state") == "busy" else 0
        print(evidence.finish())
        return exit_code
    try:
        result = run_one_shot(parsed.mode)
    except ProductionRunError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 75 if result.get("state") == "busy" else 0


if __name__ == "__main__":
    raise SystemExit(main())
