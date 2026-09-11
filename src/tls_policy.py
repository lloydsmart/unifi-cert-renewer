"""TLS client policy for verified HTTPS connections."""

import ssl

from secure_file import SecureFileError, open_secure_file

MAX_TLS_CA_FILE_BYTES = 256 * 1024


class TLSConfigurationError(ValueError):
    """A safe-to-display TLS trust configuration error."""


def create_client_tls_context(
    *, ca_name: str | None = None, ca_data: bytes | None = None
) -> ssl.SSLContext:
    """Create a verified client context with TLS 1.2 as its protocol floor."""

    try:
        if ca_name is not None and ca_data is not None:
            raise TLSConfigurationError("TLS CA sources are mutually exclusive")
        if ca_name is None and ca_data is None:
            context = ssl.create_default_context()
        else:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            source = "TLS CA file" if ca_name is not None else "TLS CA data"
            if ca_data is None:
                with open_secure_file(ca_name, source_name="TLS CA file") as ca_file:
                    ca_data = ca_file.read(MAX_TLS_CA_FILE_BYTES + 1)
            elif not isinstance(ca_data, bytes):
                raise TLSConfigurationError("TLS CA data must be bytes")
            if not ca_data:
                raise TLSConfigurationError(f"{source} is empty")
            if len(ca_data) > MAX_TLS_CA_FILE_BYTES:
                raise TLSConfigurationError(f"{source} exceeds the size limit")
            try:
                ca_text = ca_data.decode("ascii")
            except UnicodeDecodeError:
                raise TLSConfigurationError(f"{source} must be ASCII PEM") from None
            context.load_verify_locations(cadata=ca_text)
    except TLSConfigurationError:
        raise
    except SecureFileError as error:
        raise TLSConfigurationError(str(error)) from None
    except (OSError, ssl.SSLError):
        raise TLSConfigurationError("TLS CA file could not be loaded") from None
    context.minimum_version = ssl.TLSVersion.TLSv1_2

    if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
        raise RuntimeError("TLS client verification context is not securely configured")
    return context
