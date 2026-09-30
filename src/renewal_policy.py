"""Executor-owned, versioned public certificate-use policy.

The digest detects deployment drift. It is public and grants no authority.
"""

import hashlib
import json
import os
import re
import stat
from dataclasses import dataclass

from certificate import (
    IssuedCertificateValidationError,
    validate_issued_signature_policy,
)
from unifi_client import CertificatePolicy, build_unifi_csr_command
from unifi_tls import (
    LiveTLSEndpoint,
    ReadinessPolicy,
    validate_live_tls_configuration,
)

POLICY_DIRECTORY = "/run/unifi-cert-renewer-policy"
POLICY_NAME = "policy.json"
MAX_POLICY_BYTES = 64 * 1024
MAX_VERIFICATION_SECONDS = 120
SCHEMA_VERSION = 2
_SPKI_RE = re.compile(r"[0-9a-fA-F]{64}\Z")


class PolicyError(ValueError):
    """Invalid or unsafe public deployment policy; never includes its contents."""


@dataclass(frozen=True, slots=True)
class RenewalPolicy:
    digest: str
    subject: str
    dns_sans: tuple[str, ...]
    ip_sans: tuple[str, ...]
    ca_pem: bytes
    lifetime_days: int
    signing_digest: str
    issued_signature_oid: str
    csr_signature_algorithm: str
    endpoint: LiveTLSEndpoint
    readiness: ReadinessPolicy
    issuing_ca_description: str

    def certificate_policy(self, observed_spki: str) -> CertificatePolicy:
        if (
            not isinstance(observed_spki, str)
            or _SPKI_RE.fullmatch(observed_spki) is None
        ):
            raise PolicyError("invalid observed public key identity")
        return CertificatePolicy(
            observed_spki, self.subject, self.dns_sans, self.ip_sans
        )


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError("duplicate policy field")
        result[key] = value
    return result


def _exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise PolicyError("invalid policy fields")
    return value


def parse_policy(data: bytes) -> RenewalPolicy:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_POLICY_BYTES:
        raise PolicyError("invalid policy size")
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_object)
        value = _exact(
            value,
            {
                "schema_version",
                "subject",
                "dns_sans",
                "ip_sans",
                "issuing_ca_pem",
                "issuing_ca_description",
                "lifetime_days",
                "signing_digest",
                "issued_signature_oid",
                "csr_signature_algorithm",
                "live_tls",
            },
        )
        if (
            type(value["schema_version"]) is not int
            or value["schema_version"] != SCHEMA_VERSION
        ):
            raise PolicyError("unsupported policy schema")
        if (
            not isinstance(value["dns_sans"], list)
            or not isinstance(value["ip_sans"], list)
            or not isinstance(value["subject"], str)
        ):
            raise PolicyError("invalid certificate identity policy")
        dns_sans = tuple(value["dns_sans"])
        ip_sans = tuple(value["ip_sans"])
        build_unifi_csr_command(
            CertificatePolicy("0" * 64, value["subject"], dns_sans, ip_sans)
        )
        if not dns_sans and not ip_sans:
            raise PolicyError("certificate identity requires a SAN")
        if not isinstance(value["issuing_ca_pem"], str):
            raise PolicyError("invalid issuing CA")
        try:
            ca_pem = validate_issued_signature_policy(
                value["issuing_ca_pem"].encode("ascii"),
                value["signing_digest"],
                value["issued_signature_oid"],
            )
        except IssuedCertificateValidationError as error:
            raise PolicyError(str(error)) from None
        lifetime = value["lifetime_days"]
        if type(lifetime) is not int or not 1 <= lifetime <= 397:
            raise PolicyError("invalid certificate lifetime policy")
        digest = value["signing_digest"]
        if value["csr_signature_algorithm"] != "SHA384withRSA":
            raise PolicyError("invalid CSR signature policy")
        description = value["issuing_ca_description"]
        if (
            not isinstance(description, str)
            or not 1 <= len(description) <= 255
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in description
            )
        ):
            raise PolicyError("invalid issuing CA description")
        live = _exact(
            value["live_tls"],
            {
                "address",
                "server_hostname",
                "port",
                "timeout_seconds",
                "attempt_timeout_seconds",
                "retry_delay_seconds",
                "max_attempts",
            },
        )
        endpoint = LiveTLSEndpoint(
            live["address"], live["server_hostname"], live["port"]
        )
        readiness = ReadinessPolicy(
            live["timeout_seconds"],
            live["attempt_timeout_seconds"],
            live["retry_delay_seconds"],
            live["max_attempts"],
        )
        validate_live_tls_configuration(endpoint, readiness)
        if readiness.timeout_seconds > MAX_VERIFICATION_SECONDS:
            raise PolicyError("live verification exceeds executor response budget")
        return RenewalPolicy(
            hashlib.sha256(data).hexdigest(),
            value["subject"],
            dns_sans,
            ip_sans,
            ca_pem,
            lifetime,
            digest,
            value["issued_signature_oid"],
            value["csr_signature_algorithm"],
            endpoint,
            readiness,
            description,
        )
    except PolicyError:
        raise
    except (UnicodeError, ValueError, TypeError, KeyError, OverflowError):
        raise PolicyError("invalid deployment policy") from None


def load_policy() -> RenewalPolicy:
    """Read the fixed host-owned mount without following links or trusting worker files."""
    directory = file_descriptor = None
    try:
        directory = os.open(
            POLICY_DIRECTORY,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        root = os.fstat(directory)
        if not stat.S_ISDIR(root.st_mode) or root.st_uid != 0 or root.st_mode & 0o022:
            raise PolicyError("unsafe policy directory")
        file_descriptor = os.open(
            POLICY_NAME,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
            dir_fd=directory,
        )
        before = os.fstat(file_descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != 0
            or before.st_mode & 0o022
            or before.st_nlink != 1
            or not 1 <= before.st_size <= MAX_POLICY_BYTES
        ):
            raise PolicyError("unsafe policy file")
        data = os.read(file_descriptor, MAX_POLICY_BYTES + 1)
        after = os.fstat(file_descriptor)
        named = os.stat(POLICY_NAME, dir_fd=directory, follow_symlinks=False)
        if (
            len(data) != before.st_size
            or len(data) > MAX_POLICY_BYTES
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            or (before.st_dev, before.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise PolicyError("policy changed while loading")
        return parse_policy(data)
    except (OSError, PolicyError):
        raise PolicyError("deployment policy could not be loaded safely") from None
    finally:
        if file_descriptor is not None:
            os.close(file_descriptor)
        if directory is not None:
            os.close(directory)
