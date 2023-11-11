"""
the Wassima library is a simple wrapper around the crate rustls-native-certs.
It aims to provide a pythonic way to retrieve root CAs from your system without any difficulties or hazmat.
"""
from __future__ import annotations

import ssl
from functools import lru_cache
from os import environ
from ssl import DER_cert_to_PEM_cert
from threading import RLock

from ._version import VERSION, __version__

#: Determine if we could load correctly the non-native rust module.
RUSTLS_LOADED: bool
# Mozilla TLS recommendations for ciphers
# General-purpose servers with a variety of clients, recommended for almost all systems.
MOZ_INTERMEDIATE_CIPHERS: str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"
#: Contain user custom CAs
_MANUALLY_REGISTERED_CA: list[bytes] = []
#: Lock for shared register-ca
_USER_APPEND_CA_LOCK = RLock()

try:
    from ._rustls import root_der_certificates as _root_der_certificates

    @lru_cache()
    def root_der_certificates() -> list[bytes]:
        try:
            bck = environ.pop("SSL_CERT_FILE")
        except KeyError:
            bck = None

        try:
            with _USER_APPEND_CA_LOCK:
                return _root_der_certificates() + _MANUALLY_REGISTERED_CA
        finally:
            if bck is not None:
                environ["SSL_CERT_FILE"] = bck

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
            is not supported. While it is not ideal, you may circumvent that warning by having certifi
            installed in your environment. Run `python -m pip install certifi`.
            You may also open an issue at https://github.com/jawah/wassima/issues to get your platform supported.""",
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


def register_ca(pem_or_der_certificate: bytes | str) -> None:
    """
    You may register your own CA certificate in addition to your system trust store.
    """
    with _USER_APPEND_CA_LOCK:
        if isinstance(pem_or_der_certificate, str):
            pem_or_der_certificate = PEM_cert_to_DER_cert(pem_or_der_certificate)

        if pem_or_der_certificate not in _MANUALLY_REGISTERED_CA:
            _MANUALLY_REGISTERED_CA.append(pem_or_der_certificate)

            root_pem_certificates.cache_clear()
            root_der_certificates.cache_clear()


def create_default_ssl_context() -> ssl.SSLContext:
    """
    Instantiate a native SSLContext (client purposes) that ships with your system root CAs.
    In addition to that, assign it the default OpenSSL ciphers suite and set
    TLS 1.2 as the minimum supported version. Also disable commonName check and enforce
    hostname altName verification. The Mozilla Recommended Cipher Suite is used instead of system default.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    ctx.load_verify_locations(cadata=generate_ca_bundle())
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(MOZ_INTERMEDIATE_CIPHERS)
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
    "register_ca",
    "__version__",
    "VERSION",
    "RUSTLS_LOADED",
)
