import base64
import io
import json
import ssl
from ipaddress import ip_address
from urllib.error import HTTPError, URLError

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

import opnsense_client
import secure_file
from csr import CSRInfo, inspect_csr

BASE_URL = "https://opnsense.test:8443"
CA_REF = "0123456789abc"
CERTIFICATE_UUID = "abcdef12-1234-5678-9234-567812345678"


class JSONResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()


def json_response(value: object) -> JSONResponse:
    return JSONResponse(json.dumps(value).encode())


@pytest.fixture(autouse=True)
def credential_files(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(secure_file, "SECURE_FILE_ROOT", str(tmp_path))
    key_file = tmp_path / opnsense_client.OPNSENSE_API_KEY_NAME
    secret_file = tmp_path / opnsense_client.OPNSENSE_API_SECRET_NAME
    key_file.write_text("test-api-key", encoding="utf-8")
    secret_file.write_text("test-api-secret", encoding="utf-8")
    key_file.chmod(0o600)
    secret_file.chmod(0o600)


@pytest.fixture(scope="module")
def rsa_4096_csr() -> tuple[bytes, CSRInfo]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    request = _make_csr(key)
    pem = request.public_bytes(serialization.Encoding.PEM)
    return pem, inspect_csr(pem)


def _make_csr(key) -> x509.CertificateSigningRequest:
    return (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.test")])
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("unifi.test"),
                    x509.DNSName("controller.test"),
                    x509.IPAddress(ip_address("192.0.2.10")),
                    x509.IPAddress(ip_address("2001:db8::10")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )


@pytest.mark.parametrize(
    "base_url",
    [
        "https://opnsense.test",
        "https://opnsense.test/",
        BASE_URL,
        "https://[2001:db8::1]",
    ],
)
def test_accepts_origin_only_https_urls(base_url) -> None:
    assert opnsense_client.validate_base_url(base_url).startswith("https://")


@pytest.mark.parametrize(
    ("base_url", "message"),
    [
        ("http://opnsense.test", "HTTPS"),
        ("https://key:secret@opnsense.test", "credentials"),
        ("https://opnsense.test/api", "path"),
        ("https://opnsense.test?query=1", "query or fragment"),
        ("https://opnsense.test?", "query or fragment"),
        ("https://opnsense.test#fragment", "query or fragment"),
        ("https://opnsense.test#", "query or fragment"),
        ("https://opnsense.test:", "invalid port"),
        ("https://opnsense.test:0", "invalid port"),
        ("https://opnsense.test:65536", "invalid"),
        ("https://opn sense.test", "unsupported characters"),
        ("https://opnsense_test", "invalid hostname"),
    ],
)
def test_rejects_unsafe_base_urls(base_url, message) -> None:
    with pytest.raises(ValueError, match=message):
        opnsense_client.validate_base_url(base_url)


def test_reject_redirect_handler_never_builds_redirect_request() -> None:
    handler = opnsense_client.RejectRedirectHandler()

    assert handler.redirect_request(None, None, 302, "Found", {}, BASE_URL) is None


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (HTTPError(BASE_URL, 302, "Found", {}, None), "HTTP 302"),
        (HTTPError(BASE_URL, 500, "secret response", {}, None), "HTTP 500"),
        (URLError("credential-bearing network detail"), "connection failed"),
        (TimeoutError("secret timeout detail"), "connection failed"),
    ],
)
def test_normalizes_http_and_network_failures(monkeypatch, failure, message) -> None:
    def fail(*args, **kwargs):
        raise failure

    monkeypatch.setattr(opnsense_client, "_open_url", fail)

    with pytest.raises(opnsense_client.OPNsenseAPIError, match=message) as raised:
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("Internal CA")

    assert "secret response" not in str(raised.value)
    assert "credential-bearing" not in str(raised.value)


@pytest.mark.parametrize(
    ("response_data", "message"),
    [
        (b"x" * (opnsense_client.MAX_RESPONSE_BYTES + 1), "size limit"),
        (b"\xff", "malformed JSON"),
        (b"not-json", "malformed JSON"),
        (b'{"count":0,"count":1,"rows":[]}', "malformed JSON"),
        (b"[]", "non-object"),
    ],
)
def test_rejects_invalid_json_responses(monkeypatch, response_data, message) -> None:
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: JSONResponse(response_data),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match=message):
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("Internal CA")


def test_uses_basic_authentication_and_verified_tls(monkeypatch) -> None:
    captured = {}

    def fake_open(request, **kwargs):
        captured["request"] = request
        captured.update(kwargs)
        return json_response({"rows": [], "count": 0})

    monkeypatch.setattr(opnsense_client, "_open_url", fake_open)
    client = opnsense_client.OPNsenseClient(BASE_URL)
    with pytest.raises(opnsense_client.OPNsenseAPIError, match="not found"):
        client.resolve_ca("Internal CA")

    expected = base64.b64encode(b"test-api-key:test-api-secret").decode("ascii")
    assert captured["request"].get_header("Authorization") == f"Basic {expected}"
    assert captured["request"].get_method() == "GET"
    assert captured["ssl_context"].check_hostname is True
    assert captured["ssl_context"].verify_mode == ssl.CERT_REQUIRED
    assert captured["ssl_context"].minimum_version == ssl.TLSVersion.TLSv1_2


def test_client_passes_only_optional_tls_ca_name(monkeypatch) -> None:
    context = object()
    calls: list[str | None] = []
    monkeypatch.setattr(
        opnsense_client,
        "create_client_tls_context",
        lambda *, ca_name: calls.append(ca_name) or context,
    )

    client = opnsense_client.OPNsenseClient(
        BASE_URL,
        tls_ca_name="opnsense-ca.pem",
    )

    assert calls == ["opnsense-ca.pem"]
    assert client._ssl_context is context


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"rows": [], "count": True},
        {"rows": [], "count": 1},
        {"rows": {}, "count": 0},
        {"rows": ["bad"], "count": 1},
        {"rows": [{"descr": 1, "caref": CA_REF}], "count": 1},
        {"rows": [{"descr": "Internal CA", "caref": 1}], "count": 1},
    ],
)
def test_rejects_malformed_ca_lists(monkeypatch, response) -> None:
    monkeypatch.setattr(
        opnsense_client, "_open_url", lambda *args, **kwargs: json_response(response)
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="malformed"):
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("Internal CA")


def test_resolves_one_exact_ca_description(monkeypatch) -> None:
    response = {
        "rows": [
            {"descr": "Other CA", "caref": "abcdef0123456"},
            {"descr": "Internal CA", "caref": CA_REF},
        ],
        "count": 2,
    }
    monkeypatch.setattr(
        opnsense_client, "_open_url", lambda *args, **kwargs: json_response(response)
    )

    assert opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("Internal CA") == CA_REF


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        ([], "not found"),
        (
            [
                {"descr": "Internal CA", "caref": CA_REF},
                {"descr": "Internal CA", "caref": "abcdef0123456"},
            ],
            "not unique",
        ),
        ([{"descr": "Internal CA", "caref": "ABCDEF0123456"}], "invalid"),
    ],
)
def test_rejects_missing_ambiguous_or_malformed_ca(monkeypatch, rows, message) -> None:
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response({"rows": rows, "count": len(rows)}),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match=message):
        opnsense_client.OPNsenseClient(BASE_URL).resolve_ca("Internal CA")


def test_signing_payload_derives_rsa_4096_and_csr_identity(
    monkeypatch, rsa_4096_csr
) -> None:
    csr_pem, csr_info = rsa_4096_csr
    captured = {}

    def fake_open(request, **kwargs):
        captured["request"] = request
        return json_response({"result": "saved", "uuid": CERTIFICATE_UUID})

    monkeypatch.setattr(opnsense_client, "_open_url", fake_open)
    result = opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
        csr_pem,
        csr_info,
        expected_spki_sha256=csr_info.spki_sha256,
        caref=CA_REF,
        digest="sha256",
        lifetime_days=397,
        description="UniFi HTTPS",
    )

    assert result == CERTIFICATE_UUID
    assert captured["request"].full_url == BASE_URL + opnsense_client.CERT_ADD_PATH
    assert captured["request"].get_method() == "POST"
    assert json.loads(captured["request"].data) == {
        "cert": {
            "action": "sign_csr",
            "caref": CA_REF,
            "digest": "sha256",
            "cert_type": "server_cert",
            "lifetime": 397,
            "key_type": "4096",
            "csr_payload": csr_pem.decode("ascii"),
            "altnames_dns": "unifi.test\ncontroller.test",
            "altnames_ip": "192.0.2.10\n2001:db8::10",
            "descr": "UniFi HTTPS",
        }
    }


@pytest.mark.parametrize("size", [2048, 3072])
def test_deliberately_supported_rsa_sizes_are_derived(monkeypatch, size) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=size)
    pem = _make_csr(key).public_bytes(serialization.Encoding.PEM)
    info = inspect_csr(pem)
    captured = {}

    def fake_request(self, method, path, payload=None):
        captured["payload"] = payload
        return {"result": "saved", "uuid": CERTIFICATE_UUID}

    monkeypatch.setattr(opnsense_client.OPNsenseClient, "_request_json", fake_request)
    opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
        pem,
        info,
        expected_spki_sha256=info.spki_sha256,
        caref=CA_REF,
        digest="sha384",
        lifetime_days=30,
        description="UniFi HTTPS",
    )

    assert captured["payload"]["cert"]["key_type"] == str(size)


def test_rejects_unsupported_rsa_size_before_network(monkeypatch) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    pem = _make_csr(key).public_bytes(serialization.Encoding.PEM)
    info = inspect_csr(pem)
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: pytest.fail("network must not be used"),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="key size"):
        opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
            pem,
            info,
            expected_spki_sha256=info.spki_sha256,
            caref=CA_REF,
            digest="sha256",
            lifetime_days=30,
            description="UniFi HTTPS",
        )


def test_rejects_ec_csr_before_network(monkeypatch) -> None:
    pem = _make_csr(ec.generate_private_key(ec.SECP256R1())).public_bytes(
        serialization.Encoding.PEM
    )
    info = inspect_csr(pem)
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: pytest.fail("network must not be used"),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="algorithm"):
        opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
            pem,
            info,
            expected_spki_sha256=info.spki_sha256,
            caref=CA_REF,
            digest="sha256",
            lifetime_days=30,
            description="UniFi HTTPS",
        )


def test_rejects_csr_with_unsupported_san_identity_before_network(
    monkeypatch,
) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    request = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.test")])
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("unifi.test"),
                    x509.RFC822Name("operator@example.test"),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    pem = request.public_bytes(serialization.Encoding.PEM)
    info = inspect_csr(pem)
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: pytest.fail("network must not be used"),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="unsupported SAN"):
        opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
            pem,
            info,
            expected_spki_sha256=info.spki_sha256,
            caref=CA_REF,
            digest="sha256",
            lifetime_days=30,
            description="UniFi HTTPS",
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"caref": "ABCDEF0123456"}, "CA reference"),
        ({"digest": "sha1"}, "digest"),
        ({"digest": "SHA256"}, "digest"),
        ({"lifetime_days": True}, "lifetime"),
        ({"lifetime_days": 0}, "lifetime"),
        ({"lifetime_days": 398}, "lifetime"),
        ({"description": ""}, "description"),
        ({"description": "x" * 256}, "description"),
        ({"description": "unsafe\nname"}, "description"),
    ],
)
def test_rejects_invalid_signing_policy(
    monkeypatch, rsa_4096_csr, overrides, message
) -> None:
    csr_pem, info = rsa_4096_csr
    arguments = {
        "expected_spki_sha256": info.spki_sha256,
        "caref": CA_REF,
        "digest": "sha256",
        "lifetime_days": 397,
        "description": "UniFi HTTPS",
    }
    arguments.update(overrides)
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: pytest.fail("network must not be used"),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match=message):
        opnsense_client.OPNsenseClient(BASE_URL).sign_csr(csr_pem, info, **arguments)


def test_rejects_wrong_expected_spki_before_network(monkeypatch, rsa_4096_csr) -> None:
    csr_pem, info = rsa_4096_csr
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: pytest.fail("network must not be used"),
    )

    with pytest.raises(ValueError, match="expected SPKI"):
        opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
            csr_pem,
            info,
            expected_spki_sha256="0" * 64,
            caref=CA_REF,
            digest="sha256",
            lifetime_days=397,
            description="UniFi HTTPS",
        )


def test_rejects_csr_info_that_does_not_match_payload(
    monkeypatch, rsa_4096_csr
) -> None:
    csr_pem, info = rsa_4096_csr
    changed = CSRInfo(
        subject="CN=different.test",
        spki_sha256=info.spki_sha256,
        public_key_algorithm=info.public_key_algorithm,
        public_key_size=info.public_key_size,
        dns_sans=info.dns_sans,
        ip_sans=info.ip_sans,
        subject_key_identifier=info.subject_key_identifier,
        signature_algorithm_oid=info.signature_algorithm_oid,
        signature_hash_algorithm=info.signature_hash_algorithm,
        signature_valid=True,
    )
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: pytest.fail("network must not be used"),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match="does not match"):
        opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
            csr_pem,
            changed,
            expected_spki_sha256=info.spki_sha256,
            caref=CA_REF,
            digest="sha256",
            lifetime_days=397,
            description="UniFi HTTPS",
        )


@pytest.mark.parametrize(
    "response",
    [
        {"result": "failed", "uuid": CERTIFICATE_UUID},
        {"result": "saved"},
        {"result": "saved", "uuid": "not-a-uuid"},
        {"result": "saved", "uuid": CERTIFICATE_UUID.upper()},
    ],
)
def test_rejects_signing_failure_and_invalid_uuid(
    monkeypatch, rsa_4096_csr, response
) -> None:
    csr_pem, info = rsa_4096_csr
    monkeypatch.setattr(
        opnsense_client,
        "_open_url",
        lambda *args, **kwargs: json_response(response),
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError):
        opnsense_client.OPNsenseClient(BASE_URL).sign_csr(
            csr_pem,
            info,
            expected_spki_sha256=info.spki_sha256,
            caref=CA_REF,
            digest="sha256",
            lifetime_days=397,
            description="UniFi HTTPS",
        )


def test_get_certificate_requests_only_public_crt(monkeypatch) -> None:
    captured = {}

    def fake_open(request, **kwargs):
        captured["request"] = request
        return json_response({"status": "ok", "payload": " CERTIFICATE PEM "})

    monkeypatch.setattr(opnsense_client, "_open_url", fake_open)

    assert (
        opnsense_client.OPNsenseClient(BASE_URL).get_certificate(CERTIFICATE_UUID)
        == b"CERTIFICATE PEM\n"
    )
    assert captured["request"].full_url.endswith(f"/{CERTIFICATE_UUID}/crt")
    assert captured["request"].get_method() == "POST"
    assert captured["request"].data == b"{}"


@pytest.mark.parametrize(
    ("response", "message"),
    [
        ({"status": "failed", "payload": "certificate"}, "malformed"),
        ({"status": "ok"}, "malformed"),
        ({"status": "ok", "payload": ""}, "malformed"),
        ({"status": "ok", "payload": "\u2603"}, "not ASCII"),
        (
            {
                "status": "ok",
                "payload": "x" * opnsense_client.MAX_CERTIFICATE_PEM_BYTES,
            },
            "size limit",
        ),
    ],
)
def test_rejects_malformed_certificate_retrieval(
    monkeypatch, response, message
) -> None:
    monkeypatch.setattr(
        opnsense_client, "_open_url", lambda *args, **kwargs: json_response(response)
    )

    with pytest.raises(opnsense_client.OPNsenseAPIError, match=message):
        opnsense_client.OPNsenseClient(BASE_URL).get_certificate(CERTIFICATE_UUID)


@pytest.mark.parametrize(
    ("contents", "message"),
    [
        (b"", "empty"),
        (b"secret\x00", "NUL"),
        (b"first\nsecond", "exactly one line"),
        ("first\u2028second".encode(), "exactly one line"),
        (b"secret\xff", "valid UTF-8"),
        (b"x" * (opnsense_client.MAX_SECRET_FILE_BYTES + 1), "size limit"),
    ],
)
def test_rejects_unsafe_secret_content_without_leaking_value(
    monkeypatch, tmp_path, contents, message
) -> None:
    path = tmp_path / opnsense_client.OPNSENSE_API_KEY_NAME
    path.write_bytes(contents)
    path.chmod(0o600)

    with pytest.raises(opnsense_client.OPNsenseAPIError, match=message) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)

    assert "first" not in str(raised.value)
    assert "secret" not in str(raised.value)


@pytest.mark.parametrize("mode", [0o600, 0o400])
def test_accepts_private_credential_file_modes(tmp_path, mode) -> None:
    credential_path = tmp_path / opnsense_client.OPNSENSE_API_KEY_NAME
    credential_path.chmod(mode)

    opnsense_client.OPNsenseClient(BASE_URL)


@pytest.mark.parametrize(
    ("mode", "message"),
    [
        (0o644, "group-readable"),
        (0o444, "group-readable"),
        (0o640, "group-readable"),
        (0o604, "world-readable"),
    ],
)
def test_rejects_readable_credential_file_modes_without_disclosing_path(
    tmp_path, mode, message
) -> None:
    credential_path = tmp_path / opnsense_client.OPNSENSE_API_KEY_NAME
    credential_path.chmod(mode)

    with pytest.raises(opnsense_client.OPNsenseAPIError, match=message) as raised:
        opnsense_client.OPNsenseClient(BASE_URL)

    assert str(credential_path) not in str(raised.value)


def test_environment_paths_and_direct_credentials_cannot_redirect_fixed_names(
    monkeypatch,
) -> None:
    monkeypatch.setenv("OPNSENSE_API_KEY_FILE", "/etc/passwd")
    monkeypatch.setenv("OPNSENSE_API_SECRET_FILE", "../outside")
    monkeypatch.setenv("OPNSENSE_API_KEY", "must-not-be-used")
    monkeypatch.setenv("OPNSENSE_API_SECRET", "must-not-be-used")

    authorization = opnsense_client.OPNsenseClient(BASE_URL)._authorization

    expected = base64.b64encode(b"test-api-key:test-api-secret").decode("ascii")
    assert authorization == f"Basic {expected}"
