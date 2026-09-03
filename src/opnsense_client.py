"""Narrow HTTPS client for the OPNsense Trust certificate API."""

import base64
import json
import math
import re
import ssl
import unicodedata
import uuid
from ipaddress import ip_address
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from csr import CSRInfo, inspect_csr, validate_csr_spki
from secure_file import SecureFileError, open_secure_file
from tls_policy import TLSConfigurationError, create_client_tls_context

CA_LIST_PATH = "/api/trust/cert/ca_list"
CERT_ADD_PATH = "/api/trust/cert/add"
CERTIFICATE_PATH = "/api/trust/cert/generate_file/{uuid}/crt"

MAX_RESPONSE_BYTES = 1024 * 1024
MAX_CERTIFICATE_PEM_BYTES = 64 * 1024
MAX_SECRET_FILE_BYTES = 16 * 1024
MAX_DESCRIPTION_CHARS = 255
MAX_SUBJECT_CHARS = 4096
MAX_SAN_ENTRIES = 100
MIN_LIFETIME_DAYS = 1
MAX_LIFETIME_DAYS = 397

ALLOWED_DIGESTS = frozenset({"sha256", "sha384", "sha512"})
SUPPORTED_RSA_KEY_SIZES = frozenset({2048, 3072, 4096})
OPNSENSE_API_KEY_NAME = "opnsense-api-key"
OPNSENSE_API_SECRET_NAME = "opnsense-api-secret"

_CA_REFERENCE_RE = re.compile(r"[0-9a-f]{13}\Z")
_DNS_LABEL_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")
_UNSAFE_TEXT_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})


class OPNsenseAPIError(ValueError):
    """A safe-to-display OPNsense input, API, or response error."""


class RejectRedirectHandler(HTTPRedirectHandler):
    """Leave redirects unhandled so urllib raises the original HTTP error."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _DuplicateJSONKeyError(ValueError):
    """Internal marker for ambiguous JSON objects."""


def _open_url(request: Request, *, timeout: float, ssl_context: ssl.SSLContext):
    opener = build_opener(
        RejectRedirectHandler(),
        HTTPSHandler(context=ssl_context),
    )
    return opener.open(request, timeout=timeout)


def validate_base_url(base_url: str) -> str:
    """Validate and canonicalize an origin-only HTTPS base URL."""

    if not isinstance(base_url, str) or not base_url.strip():
        raise ValueError("OPNsense base URL must be a non-empty HTTPS URL")
    candidate = base_url.strip()
    if any(
        character.isspace()
        or unicodedata.category(character) in _UNSAFE_TEXT_CATEGORIES
        for character in candidate
    ):
        raise ValueError("OPNsense base URL contains unsupported characters")

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError("OPNsense base URL is invalid") from error

    if parsed.scheme.casefold() != "https" or not hostname:
        raise ValueError("OPNsense base URL must be a valid HTTPS URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("OPNsense base URL must not contain credentials")
    if "?" in candidate or "#" in candidate:
        raise ValueError("OPNsense base URL must not contain a query or fragment")
    if parsed.path not in {"", "/"}:
        raise ValueError("OPNsense base URL must not contain a path")
    if parsed.netloc.endswith(":") or (port is not None and not 1 <= port <= 65535):
        raise ValueError("OPNsense base URL contains an invalid port")
    _validate_url_hostname(hostname)

    return candidate.rstrip("/")


def _validate_url_hostname(hostname: str) -> None:
    if "%" in hostname:
        raise ValueError("OPNsense base URL contains an invalid hostname")
    try:
        ip_address(hostname)
        return
    except ValueError:
        pass
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("OPNsense base URL contains an invalid hostname") from None
    dns_name = hostname[:-1] if hostname.endswith(".") else hostname
    if (
        not dns_name
        or len(dns_name) > 253
        or any(_DNS_LABEL_RE.fullmatch(label) is None for label in dns_name.split("."))
    ):
        raise ValueError("OPNsense base URL contains an invalid hostname")


def _validate_timeout(timeout: float) -> float:
    if (
        isinstance(timeout, bool)
        or not isinstance(timeout, (int, float))
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        raise ValueError("OPNsense timeout must be a positive finite number")
    return float(timeout)


def _read_secret_file(secret_name: str, source_name: str) -> str:
    try:
        with open_secure_file(
            secret_name,
            source_name=source_name,
            require_private=True,
        ) as secret_file:
            secret_bytes = secret_file.read(MAX_SECRET_FILE_BYTES + 1)
    except SecureFileError as error:
        raise OPNsenseAPIError(str(error)) from None
    except OSError:
        raise OPNsenseAPIError(f"{source_name} could not be read") from None

    if len(secret_bytes) > MAX_SECRET_FILE_BYTES:
        raise OPNsenseAPIError(f"{source_name} exceeds the size limit")
    if b"\x00" in secret_bytes:
        raise OPNsenseAPIError(f"{source_name} contains NUL")
    try:
        secret = secret_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise OPNsenseAPIError(f"{source_name} must contain valid UTF-8") from None

    if secret.endswith("\r\n"):
        secret = secret[:-2]
    elif secret.endswith("\n"):
        secret = secret[:-1]
    if not secret:
        raise OPNsenseAPIError(f"{source_name} is empty")
    if secret.splitlines() != [secret]:
        raise OPNsenseAPIError(f"{source_name} must contain exactly one line")
    return secret


def _validate_safe_text(value: str, label: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{label} must be text")
    if not value:
        raise OPNsenseAPIError(f"{label} must not be empty")
    if len(value) > maximum:
        raise OPNsenseAPIError(f"{label} exceeds the size limit")
    if any(
        unicodedata.category(character) in _UNSAFE_TEXT_CATEGORIES
        for character in value
    ):
        raise OPNsenseAPIError(f"{label} contains unsafe characters")
    return value


def _validate_caref(caref: str) -> str:
    if not isinstance(caref, str) or _CA_REFERENCE_RE.fullmatch(caref) is None:
        raise OPNsenseAPIError("OPNsense CA reference is invalid")
    return caref


def _validate_uuid(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise OPNsenseAPIError(f"{label} is invalid")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        raise OPNsenseAPIError(f"{label} is invalid") from None
    if str(parsed) != value:
        raise OPNsenseAPIError(f"{label} is invalid")
    return value


def _derive_key_type(csr_info: CSRInfo) -> str:
    if csr_info.public_key_algorithm != "RSA":
        raise OPNsenseAPIError("CSR public-key algorithm is unsupported for signing")
    if csr_info.public_key_size not in SUPPORTED_RSA_KEY_SIZES:
        raise OPNsenseAPIError("CSR RSA key size is unsupported for signing")
    return str(csr_info.public_key_size)


def _validate_csr_identity(
    csr_info: CSRInfo,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    _validate_safe_text(csr_info.subject, "CSR subject", MAX_SUBJECT_CHARS)
    if csr_info.unsupported_san_types:
        raise OPNsenseAPIError("CSR contains an unsupported SAN identity type")
    if len(csr_info.dns_sans) + len(csr_info.ip_sans) > MAX_SAN_ENTRIES:
        raise OPNsenseAPIError("CSR SAN count exceeds the size limit")
    if not csr_info.dns_sans and not csr_info.ip_sans:
        raise OPNsenseAPIError("CSR must contain at least one DNS or IP SAN")

    dns_names: list[str] = []
    seen_dns: set[str] = set()
    for name in csr_info.dns_sans:
        _validate_safe_text(name, "CSR DNS SAN", 253)
        try:
            name.encode("ascii")
        except UnicodeEncodeError:
            raise OPNsenseAPIError("CSR DNS SAN is not an ASCII DNS name") from None
        if any(_DNS_LABEL_RE.fullmatch(label) is None for label in name.split(".")):
            raise OPNsenseAPIError("CSR DNS SAN is not a valid DNS name")
        canonical = name.casefold()
        if canonical in seen_dns:
            raise OPNsenseAPIError("CSR contains a duplicate DNS SAN")
        seen_dns.add(canonical)
        dns_names.append(name)

    ip_addresses: list[str] = []
    seen_ips: set[str] = set()
    for address in csr_info.ip_sans:
        _validate_safe_text(address, "CSR IP SAN", 64)
        if "%" in address:
            raise OPNsenseAPIError("CSR IP SAN must not contain a scope identifier")
        try:
            canonical = str(ip_address(address))
        except ValueError:
            raise OPNsenseAPIError("CSR IP SAN is not a valid IP address") from None
        if canonical in seen_ips:
            raise OPNsenseAPIError("CSR contains a duplicate IP SAN")
        seen_ips.add(canonical)
        ip_addresses.append(canonical)
    return tuple(dns_names), tuple(ip_addresses)


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJSONKeyError
        result[key] = value
    return result


class OPNsenseClient:
    """Access only the Trust API routes needed to sign and fetch a certificate."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 30,
        tls_ca_name: str | None = None,
    ) -> None:
        self.base_url = validate_base_url(base_url)
        self.timeout = _validate_timeout(timeout)
        self._authorization = self._load_authorization()
        try:
            self._ssl_context = create_client_tls_context(ca_name=tls_ca_name)
        except (OSError, ssl.SSLError, TLSConfigurationError):
            raise OPNsenseAPIError(
                "OPNsense TLS trust could not be configured"
            ) from None

    @staticmethod
    def _load_authorization() -> str:
        api_key = _read_secret_file(OPNSENSE_API_KEY_NAME, "OPNsense API key")
        api_secret = _read_secret_file(
            OPNSENSE_API_SECRET_NAME,
            "OPNsense API secret",
        )
        credentials = f"{api_key}:{api_secret}".encode()
        return "Basic " + base64.b64encode(credentials).decode("ascii")

    def _request_json(
        self, method: str, path: str, payload: dict[str, object] | None = None
    ) -> dict[str, object]:
        headers = {
            "Accept": "application/json",
            "Authorization": self._authorization,
        }
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload, separators=(",", ":")).encode("utf-8")

        request = Request(
            f"{self.base_url}{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with _open_url(
                request,
                timeout=self.timeout,
                ssl_context=self._ssl_context,
            ) as response:
                response_data = response.read(MAX_RESPONSE_BYTES + 1)
        except HTTPError as error:
            raise OPNsenseAPIError(
                f"OPNsense API request failed with HTTP {error.code}"
            ) from None
        except (URLError, TimeoutError, OSError):
            raise OPNsenseAPIError("OPNsense API connection failed") from None

        if len(response_data) > MAX_RESPONSE_BYTES:
            raise OPNsenseAPIError("OPNsense API response exceeds the size limit")
        try:
            result = json.loads(
                response_data.decode("utf-8"), object_pairs_hook=_json_object
            )
        except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateJSONKeyError):
            raise OPNsenseAPIError("OPNsense API returned malformed JSON") from None
        if not isinstance(result, dict):
            raise OPNsenseAPIError("OPNsense API returned a non-object JSON response")
        return result

    def resolve_ca(self, description: str) -> str:
        """Resolve one exact CA description to its public reference identifier."""

        description = _validate_safe_text(
            description, "OPNsense CA description", MAX_DESCRIPTION_CHARS
        )
        response = self._request_json("GET", CA_LIST_PATH)
        rows = response.get("rows")
        count = response.get("count")
        if (
            not isinstance(rows, list)
            or not isinstance(count, int)
            or isinstance(count, bool)
            or count != len(rows)
        ):
            raise OPNsenseAPIError("OPNsense CA list response is malformed")

        matches: list[str] = []
        for row in rows:
            if not isinstance(row, dict):
                raise OPNsenseAPIError("OPNsense CA list response is malformed")
            row_description = row.get("descr")
            caref = row.get("caref")
            if not isinstance(row_description, str) or not isinstance(caref, str):
                raise OPNsenseAPIError("OPNsense CA list response is malformed")
            if row_description == description:
                matches.append(caref)

        if not matches:
            raise OPNsenseAPIError("OPNsense CA description was not found")
        if len(matches) != 1:
            raise OPNsenseAPIError("OPNsense CA description is not unique")
        if _CA_REFERENCE_RE.fullmatch(matches[0]) is None:
            raise OPNsenseAPIError("OPNsense returned an invalid CA reference")
        return matches[0]

    def sign_csr(
        self,
        csr_pem: bytes,
        csr_info: CSRInfo,
        *,
        expected_spki_sha256: str,
        caref: str,
        digest: str,
        lifetime_days: int,
        description: str,
    ) -> str:
        """Submit an inspected CSR, deriving all signed identity fields from it."""

        if not isinstance(csr_info, CSRInfo):
            raise TypeError("CSR information must be CSRInfo")
        inspected_info = inspect_csr(csr_pem)
        if inspected_info != csr_info:
            raise OPNsenseAPIError("CSR information does not match the CSR payload")
        validate_csr_spki(inspected_info, expected_spki_sha256)

        caref = _validate_caref(caref)
        if digest not in ALLOWED_DIGESTS:
            raise OPNsenseAPIError("OPNsense digest is not allowed")
        if (
            not isinstance(lifetime_days, int)
            or isinstance(lifetime_days, bool)
            or not MIN_LIFETIME_DAYS <= lifetime_days <= MAX_LIFETIME_DAYS
        ):
            raise OPNsenseAPIError(
                f"OPNsense lifetime must be between {MIN_LIFETIME_DAYS} and "
                f"{MAX_LIFETIME_DAYS} days"
            )
        description = _validate_safe_text(
            description, "Certificate description", MAX_DESCRIPTION_CHARS
        )
        key_type = _derive_key_type(inspected_info)
        dns_names, ip_addresses = _validate_csr_identity(inspected_info)
        try:
            csr_payload = csr_pem.decode("ascii")
        except UnicodeDecodeError:
            raise OPNsenseAPIError("CSR PEM must be ASCII") from None

        response = self._request_json(
            "POST",
            CERT_ADD_PATH,
            {
                "cert": {
                    "action": "sign_csr",
                    "caref": caref,
                    "digest": digest,
                    "cert_type": "server_cert",
                    "lifetime": lifetime_days,
                    "key_type": key_type,
                    "csr_payload": csr_payload,
                    "altnames_dns": "\n".join(dns_names),
                    "altnames_ip": "\n".join(ip_addresses),
                    "descr": description,
                }
            },
        )
        if response.get("result") != "saved":
            raise OPNsenseAPIError("OPNsense did not save the signed certificate")
        return _validate_uuid(response.get("uuid"), "OPNsense certificate UUID")

    def get_certificate(self, certificate_uuid: str) -> bytes:
        """Retrieve only the public certificate for a canonical UUID."""

        certificate_uuid = _validate_uuid(certificate_uuid, "Certificate UUID")
        response = self._request_json(
            "POST",
            CERTIFICATE_PATH.format(uuid=certificate_uuid),
            {},
        )
        payload = response.get("payload")
        if response.get("status") != "ok" or not isinstance(payload, str):
            raise OPNsenseAPIError("OPNsense public certificate response is malformed")
        payload = payload.strip()
        if not payload:
            raise OPNsenseAPIError("OPNsense public certificate response is malformed")
        try:
            certificate_pem = payload.encode("ascii") + b"\n"
        except UnicodeEncodeError:
            raise OPNsenseAPIError(
                "OPNsense public certificate response is not ASCII"
            ) from None
        if len(certificate_pem) > MAX_CERTIFICATE_PEM_BYTES:
            raise OPNsenseAPIError(
                "OPNsense public certificate payload exceeds the size limit"
            )
        return certificate_pem
