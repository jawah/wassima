"""
the Wassima library is a simple wrapper around the crate rustls-native-certs.
It aims to provide a pythonic way to retrieve root CAs from your system without any difficulties or hazmat.
"""
from __future__ import annotations

import ssl
from functools import lru_cache
from ssl import DER_cert_to_PEM_cert

from ._version import VERSION, __version__

#: Determine if we could load correctly the non-native rust module.
RUSTLS_LOADED: bool

try:
    from ._rustls import root_der_certificates

    RUSTLS_LOADED = True
except ImportError:
    RUSTLS_LOADED = False
    from ssl import PEM_cert_to_DER_cert

    try:
        import certifi  # type: ignore
    except ImportError:
        certifi = None

    if certifi is None:
        import platform
        import warnings

        warnings.warn(
            f"""Unable to access your system root CAs. Your particular interpreter and/or
            operating system ({platform.python_implementation()}, {platform.uname()}, {platform.python_version()})
            is not be supported. While it is not ideal, you may circumvent that warning by having certifi
            installed in your environment. Run `python -m pip install certifi`.
            You may also open an issue at https://github.com/jawah/wassima/issues to get your platform compatible.""",
            RuntimeWarning,
        )

    @lru_cache()
    def root_der_certificates() -> list[bytes]:
        if certifi is None:
            return []

        certs: list[bytes] = []

        with open(certifi.where(), encoding="utf-8") as fp:
            for pem_cert in fp.read().split("\n\n"):
                certs.append(PEM_cert_to_DER_cert(pem_cert))

        return certs


@lru_cache()
def root_pem_certificates() -> list[str]:
    """
    Retrieve a list of root certificate from your operating system trust store.
    They will be PEM encoded.
    """
    pem_certs = []

    for bin_cert in root_der_certificates():
        pem_certs.append(DER_cert_to_PEM_cert(bin_cert))

    return pem_certs


def generate_ca_bundle() -> str:
    """
    Generate an aggregated CA bundle that originate from your system trust store.
    Simply put, concatenated root PEM certificate.
    """
    return "\n\n".join(root_pem_certificates())


def create_default_ssl_context() -> ssl.SSLContext:
    """
    Instantiate a native SSLContext (client purposes) that ships with your system root CAs.
    In addition to that, assign it the default OpenSSL ciphers suite and set
    TLS 1.2 as the minimum supported version. Also disable commonName check and enforce
    hostname altName verification.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    ctx.load_verify_locations(cadata=generate_ca_bundle())
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("DEFAULT")
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        ctx.hostname_checks_common_name = False
    except AttributeError:
        pass

    try:
        ctx.check_hostname = True
    except AttributeError:
        pass

    return ctx


__all__ = (
    "root_der_certificates",
    "root_pem_certificates",
    "generate_ca_bundle",
    "create_default_ssl_context",
    "__version__",
    "VERSION",
    "RUSTLS_LOADED",
)
