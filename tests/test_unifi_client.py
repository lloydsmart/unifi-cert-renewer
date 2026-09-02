from datetime import UTC, datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from certificate import CertificateInspectionError
from unifi_client import (
    MAX_ALIAS_CHARS,
    MAX_DNS_SAN_CHARS,
    MAX_IP_SAN_CHARS,
    MAX_KEYSTORE_PATH_CHARS,
    MAX_KEYTOOL_OUTPUT_CHARS,
    MAX_METADATA_VALUE_CHARS,
    MAX_PASSWORD_ENV_NAME_CHARS,
    MAX_SAN_ENTRIES,
    MAX_SUBJECT_DN_CHARS,
    CertreqCommandError,
    ExpectedAliasNotFoundError,
    KeytoolMetadataError,
    UnexpectedEntryTypeError,
    build_keytool_certreq_command,
    inspect_unifi_certificate,
    parse_keytool_metadata,
)

KEYTOOL_OUTPUT = """\
Keystore type: PKCS12
Keystore provider: SUN

Your keystore contains 1 entry

Alias name: unifi
Creation date: Jul 23, 2024
Entry type: PrivateKeyEntry
Certificate chain length: 1
Certificate[1]:
Owner: CN=value-that-must-not-be-parsed
Issuer: CN=value-that-must-not-be-parsed
Serial number: deadbeef
"""


def test_parses_pkcs12_sun_and_unifi_alias_metadata() -> None:
    keystore, alias = parse_keytool_metadata(KEYTOOL_OUTPUT)

    assert keystore.keystore_type == "PKCS12"
    assert keystore.provider == "SUN"
    assert alias.alias_name == "unifi"
    assert alias.entry_type == "PrivateKeyEntry"
    assert alias.certificate_chain_length == 1


def test_combines_keytool_metadata_with_der_certificate_data() -> None:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "from-der")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(1)
        .not_valid_before(datetime(2026, 1, 1, tzinfo=UTC))
        .not_valid_after(datetime(2027, 1, 1, tzinfo=UTC))
        .sign(private_key, hashes.SHA256())
    )

    result = inspect_unifi_certificate(
        KEYTOOL_OUTPUT,
        certificate.public_bytes(serialization.Encoding.DER),
    )

    assert result.keystore.keystore_type == "PKCS12"
    assert result.alias.alias_name == "unifi"
    assert result.certificate.subject == "CN=from-der"


def test_rejects_missing_expected_alias() -> None:
    output = KEYTOOL_OUTPUT.replace("Alias name: unifi", "Alias name: other")

    with pytest.raises(ExpectedAliasNotFoundError, match="alias is missing"):
        parse_keytool_metadata(output)


def test_rejects_trusted_certificate_entry_before_requiring_chain_length() -> None:
    output = KEYTOOL_OUTPUT.replace(
        "Entry type: PrivateKeyEntry\nCertificate chain length: 1\n",
        "Entry type: trustedCertEntry\n",
    )

    with pytest.raises(UnexpectedEntryTypeError, match="PrivateKeyEntry"):
        parse_keytool_metadata(output)


@pytest.mark.parametrize(
    ("output", "message"),
    [
        (KEYTOOL_OUTPUT.replace("Keystore type: PKCS12\n", ""), "type.*missing"),
        (
            KEYTOOL_OUTPUT.replace("Keystore provider: SUN\n", ""),
            "provider.*missing",
        ),
        (
            KEYTOOL_OUTPUT.replace("Entry type: PrivateKeyEntry\n", ""),
            "entry type.*missing",
        ),
        (
            KEYTOOL_OUTPUT.replace("Certificate chain length: 1", ""),
            "chain length.*missing",
        ),
        (
            KEYTOOL_OUTPUT.replace(
                "Certificate chain length: 1", "Certificate chain length: many"
            ),
            "not a valid integer",
        ),
        (
            KEYTOOL_OUTPUT.replace(
                "Certificate chain length: 1", "Certificate chain length: 0"
            ),
            "must be positive",
        ),
    ],
)
def test_rejects_malformed_keytool_metadata(output: str, message: str) -> None:
    with pytest.raises(KeytoolMetadataError, match=message):
        parse_keytool_metadata(output)


def test_combined_inspection_rejects_invalid_certificate_der() -> None:
    with pytest.raises(CertificateInspectionError, match="invalid certificate DER"):
        inspect_unifi_certificate(KEYTOOL_OUTPUT, b"not DER")


def test_rejects_keytool_output_over_size_limit() -> None:
    oversized_output = "x" * (MAX_KEYTOOL_OUTPUT_CHARS + 1)

    with pytest.raises(KeytoolMetadataError, match="exceeds the size limit"):
        parse_keytool_metadata(oversized_output)


@pytest.mark.parametrize("label", ["Keystore type", "Keystore provider"])
def test_rejects_duplicated_keystore_metadata(label: str) -> None:
    existing_line = next(
        line for line in KEYTOOL_OUTPUT.splitlines() if line.startswith(f"{label}:")
    )
    output = KEYTOOL_OUTPUT.replace(existing_line, f"{existing_line}\n{existing_line}")

    with pytest.raises(KeytoolMetadataError, match="metadata is duplicated"):
        parse_keytool_metadata(output)


def test_rejects_duplicated_expected_alias_section() -> None:
    duplicate_alias = """\
Alias name: unifi
Entry type: PrivateKeyEntry
Certificate chain length: 1
"""

    with pytest.raises(KeytoolMetadataError, match="alias metadata is duplicated"):
        parse_keytool_metadata(f"{KEYTOOL_OUTPUT}\n{duplicate_alias}")


def test_rejects_control_characters_in_parsed_metadata() -> None:
    output = KEYTOOL_OUTPUT.replace(
        "Keystore provider: SUN", "Keystore provider: S\x1bUN"
    )

    with pytest.raises(KeytoolMetadataError, match="control characters"):
        parse_keytool_metadata(output)


def test_rejects_overlong_parsed_metadata() -> None:
    overlong_provider = "S" * (MAX_METADATA_VALUE_CHARS + 1)
    output = KEYTOOL_OUTPUT.replace(
        "Keystore provider: SUN", f"Keystore provider: {overlong_provider}"
    )

    with pytest.raises(KeytoolMetadataError, match="exceeds the size limit"):
        parse_keytool_metadata(output)


def test_builds_exact_deterministic_keytool_certreq_argv() -> None:
    argv = build_keytool_certreq_command(
        alias="unifi",
        keystore_path="/config/data/keystore",
        password_env_name="UNIFI_KEYSTORE_PASSWORD",
        subject="CN=controller.example.internal",
        dns_sans=("controller.example.internal", "alternate.example.internal"),
        ip_sans=("192.0.2.10", "2001:0db8::10"),
    )

    assert argv == (
        "keytool",
        "-certreq",
        "-alias",
        "unifi",
        "-keystore",
        "/config/data/keystore",
        "-storepass:env",
        "UNIFI_KEYSTORE_PASSWORD",
        "-keypass:env",
        "UNIFI_KEYSTORE_PASSWORD",
        "-dname",
        "CN=controller.example.internal",
        "-ext",
        "SAN=DNS:controller.example.internal,DNS:alternate.example.internal,"
        "IP:192.0.2.10,IP:2001:db8::10",
        "-rfc",
    )
    assert "-rfc" in argv
    assert "-file" not in argv


def test_password_value_cannot_appear_in_certreq_argv() -> None:
    password_value = "synthetic password that is not an environment name"

    argv = build_keytool_certreq_command(
        alias="unifi",
        keystore_path="/config/data/keystore",
        password_env_name="UNIFI_KEYSTORE_PASSWORD",
        subject="CN=unifi.test",
        dns_sans=("unifi.test",),
    )

    assert password_value not in argv
    assert argv[argv.index("-storepass:env") + 1] == "UNIFI_KEYSTORE_PASSWORD"
    assert argv[argv.index("-keypass:env") + 1] == "UNIFI_KEYSTORE_PASSWORD"


def test_requires_at_least_one_san() -> None:
    with pytest.raises(CertreqCommandError, match="at least one"):
        build_keytool_certreq_command(
            alias="unifi",
            keystore_path="/config/data/keystore",
            password_env_name="UNIFI_KEYSTORE_PASSWORD",
            subject="CN=unifi.test",
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"alias": ""}, "alias.*empty"),
        ({"keystore_path": ""}, "path.*empty"),
        ({"subject": ""}, "subject.*empty"),
    ],
)
def test_rejects_empty_required_certreq_inputs(
    overrides: dict[str, object],
    message: str,
) -> None:
    arguments: dict[str, object] = {
        "alias": "unifi",
        "keystore_path": "/config/data/keystore",
        "password_env_name": "UNIFI_KEYSTORE_PASSWORD",
        "subject": "CN=unifi.test",
        "dns_sans": ("unifi.test",),
    }
    arguments.update(overrides)

    with pytest.raises(CertreqCommandError, match=message):
        build_keytool_certreq_command(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "dns_name",
    [
        "",
        "contains a space.test",
        "-starts-with-hyphen.test",
        "ends-with-hyphen-.test",
        "two..dots.test",
        f"{'a' * 64}.test",
        "comma,test",
        "täst.test",
    ],
)
def test_rejects_invalid_dns_san(dns_name: str) -> None:
    with pytest.raises(CertreqCommandError, match="DNS SAN"):
        build_keytool_certreq_command(
            alias="unifi",
            keystore_path="/config/data/keystore",
            password_env_name="UNIFI_KEYSTORE_PASSWORD",
            subject="CN=unifi.test",
            dns_sans=(dns_name,),
        )


@pytest.mark.parametrize("address", ["", "192.0.2.999", "not-an-ip", "fe80::1%eth0"])
def test_rejects_invalid_ip_san(address: str) -> None:
    with pytest.raises(CertreqCommandError, match="IP SAN"):
        build_keytool_certreq_command(
            alias="unifi",
            keystore_path="/config/data/keystore",
            password_env_name="UNIFI_KEYSTORE_PASSWORD",
            subject="CN=unifi.test",
            ip_sans=(address,),
        )


def test_rejects_relative_keystore_path() -> None:
    with pytest.raises(CertreqCommandError, match="absolute POSIX path"):
        build_keytool_certreq_command(
            alias="unifi",
            keystore_path="config/data/keystore",
            password_env_name="UNIFI_KEYSTORE_PASSWORD",
            subject="CN=unifi.test",
            dns_sans=("unifi.test",),
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"alias": "uni\nfi"}, "alias.*control"),
        ({"keystore_path": "/config/\x1bkeystore"}, "path.*control"),
        ({"subject": "CN=unifi\rtest"}, "subject.*control"),
        ({"dns_sans": ("unifi\ntest",)}, "DNS SAN.*control"),
        ({"ip_sans": ("192.0.2.1\t",)}, "IP SAN.*control"),
    ],
)
def test_rejects_control_characters_in_certreq_inputs(
    overrides: dict[str, object],
    message: str,
) -> None:
    arguments: dict[str, object] = {
        "alias": "unifi",
        "keystore_path": "/config/data/keystore",
        "password_env_name": "UNIFI_KEYSTORE_PASSWORD",
        "subject": "CN=unifi.test",
        "dns_sans": ("unifi.test",),
    }
    arguments.update(overrides)

    with pytest.raises(CertreqCommandError, match=message):
        build_keytool_certreq_command(**arguments)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "unsafe_character",
    [
        "\u202e",
        "\u2066",
        "\u2028",
        "\u2029",
        "\ud800",
    ],
    ids=[
        "right-to-left-override",
        "left-to-right-isolate",
        "line-separator",
        "paragraph-separator",
        "lone-surrogate",
    ],
)
@pytest.mark.parametrize(
    ("field", "template"),
    [
        ("alias", "uni{}fi"),
        ("keystore_path", "/config/{}keystore"),
        ("subject", "CN=unifi{}test"),
    ],
)
def test_rejects_unsafe_unicode_categories_in_text_inputs(
    unsafe_character: str,
    field: str,
    template: str,
) -> None:
    arguments = {
        "alias": "unifi",
        "keystore_path": "/config/data/keystore",
        "password_env_name": "UNIFI_KEYSTORE_PASSWORD",
        "subject": "CN=unifi.test",
        "dns_sans": ("unifi.test",),
    }
    arguments[field] = template.format(unsafe_character)

    with pytest.raises(CertreqCommandError, match="contains control characters"):
        build_keytool_certreq_command(**arguments)


def test_permits_normal_printable_unicode_text() -> None:
    argv = build_keytool_certreq_command(
        alias="unifi-猫",
        keystore_path="/config/証明書/keystore",
        password_env_name="UNIFI_KEYSTORE_PASSWORD",
        subject="CN=contrôleur.test,O=Café",
        dns_sans=("unifi.test",),
    )

    assert "unifi-猫" in argv
    assert "/config/証明書/keystore" in argv
    assert "CN=contrôleur.test,O=Café" in argv


@pytest.mark.parametrize(
    "environment_name",
    ["", "9PASSWORD", "PASSWORD-NAME", "PASSWORD VALUE", "PASSWORD=value"],
)
def test_rejects_invalid_password_environment_variable_name(
    environment_name: str,
) -> None:
    with pytest.raises(CertreqCommandError, match="POSIX identifier"):
        build_keytool_certreq_command(
            alias="unifi",
            keystore_path="/config/data/keystore",
            password_env_name=environment_name,
            subject="CN=unifi.test",
            dns_sans=("unifi.test",),
        )


def test_rejects_overlong_password_environment_variable_name() -> None:
    with pytest.raises(CertreqCommandError, match="environment-variable.*size"):
        build_keytool_certreq_command(
            alias="unifi",
            keystore_path="/config/data/keystore",
            password_env_name="P" * (MAX_PASSWORD_ENV_NAME_CHARS + 1),
            subject="CN=unifi.test",
            dns_sans=("unifi.test",),
        )


def test_rejects_overlong_dns_san() -> None:
    with pytest.raises(CertreqCommandError, match="DNS SAN.*size"):
        build_keytool_certreq_command(
            alias="unifi",
            keystore_path="/config/data/keystore",
            password_env_name="UNIFI_KEYSTORE_PASSWORD",
            subject="CN=unifi.test",
            dns_sans=("a" * (MAX_DNS_SAN_CHARS + 1),),
        )


def test_rejects_overlong_ip_san() -> None:
    with pytest.raises(CertreqCommandError, match="IP SAN.*size"):
        build_keytool_certreq_command(
            alias="unifi",
            keystore_path="/config/data/keystore",
            password_env_name="UNIFI_KEYSTORE_PASSWORD",
            subject="CN=unifi.test",
            ip_sans=("1" * (MAX_IP_SAN_CHARS + 1),),
        )


def test_rejects_more_than_maximum_dns_sans() -> None:
    dns_sans = tuple(f"host-{index}.test" for index in range(MAX_SAN_ENTRIES + 1))

    with pytest.raises(CertreqCommandError, match="DNS SAN count.*size"):
        build_keytool_certreq_command(
            alias="unifi",
            keystore_path="/config/data/keystore",
            password_env_name="UNIFI_KEYSTORE_PASSWORD",
            subject="CN=unifi.test",
            dns_sans=dns_sans,
        )


def test_rejects_combined_san_count_over_maximum() -> None:
    dns_count = MAX_SAN_ENTRIES // 2
    ip_count = MAX_SAN_ENTRIES - dns_count + 1
    dns_sans = tuple(f"host-{index}.test" for index in range(dns_count))
    ip_sans = tuple(f"2001:db8::{index + 1:x}" for index in range(ip_count))

    with pytest.raises(CertreqCommandError, match="SAN count.*size"):
        build_keytool_certreq_command(
            alias="unifi",
            keystore_path="/config/data/keystore",
            password_env_name="UNIFI_KEYSTORE_PASSWORD",
            subject="CN=unifi.test",
            dns_sans=dns_sans,
            ip_sans=ip_sans,
        )


@pytest.mark.parametrize(
    ("dns_sans", "ip_sans", "message"),
    [
        (("unifi.test", "UNIFI.TEST"), (), "duplicate DNS"),
        ((), ("2001:db8::1", "2001:0db8:0:0:0:0:0:1"), "duplicate IP"),
    ],
)
def test_rejects_semantically_duplicate_sans(
    dns_sans: tuple[str, ...],
    ip_sans: tuple[str, ...],
    message: str,
) -> None:
    with pytest.raises(CertreqCommandError, match=message):
        build_keytool_certreq_command(
            alias="unifi",
            keystore_path="/config/data/keystore",
            password_env_name="UNIFI_KEYSTORE_PASSWORD",
            subject="CN=unifi.test",
            dns_sans=dns_sans,
            ip_sans=ip_sans,
        )


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"alias": "a" * (MAX_ALIAS_CHARS + 1)}, "alias.*size"),
        (
            {"keystore_path": "/" + "k" * MAX_KEYSTORE_PATH_CHARS},
            "path.*size",
        ),
        ({"subject": "C" * (MAX_SUBJECT_DN_CHARS + 1)}, "subject.*size"),
    ],
)
def test_rejects_overlong_certreq_inputs(
    overrides: dict[str, object],
    message: str,
) -> None:
    arguments: dict[str, object] = {
        "alias": "unifi",
        "keystore_path": "/config/data/keystore",
        "password_env_name": "UNIFI_KEYSTORE_PASSWORD",
        "subject": "CN=unifi.test",
        "dns_sans": ("unifi.test",),
    }
    arguments.update(overrides)

    with pytest.raises(CertreqCommandError, match=message):
        build_keytool_certreq_command(**arguments)  # type: ignore[arg-type]


def test_shell_metacharacters_remain_literal_argv_data() -> None:
    alias = "unifi;echo-not-executed"
    subject = "CN=$(echo-not-executed)"

    argv = build_keytool_certreq_command(
        alias=alias,
        keystore_path="/config/data/keystore",
        password_env_name="UNIFI_KEYSTORE_PASSWORD",
        subject=subject,
        dns_sans=("unifi.test",),
    )

    assert argv[argv.index("-alias") + 1] == alias
    assert argv[argv.index("-dname") + 1] == subject
