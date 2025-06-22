"""
the Wassima library is a simple library.
It aims to provide a pythonic way to retrieve root CAs from your system without any difficulties or hazmat.
"""

from __future__ import annotations

import ssl
from functools import lru_cache
from threading import RLock

from ._os import (
    root_der_certificates as _root_der_certificates,
)
from ._os._embed import root_der_certificates as fallback_der_certificates
from ._version import VERSION, __version__

# Mozilla TLS recommendations for ciphers
# General-purpose servers with a variety of clients, recommended for almost all systems.
MOZ_INTERMEDIATE_CIPHERS: str = "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"  # noqa: E501
#: Contain user custom CAs
_MANUALLY_REGISTERED_CA: list[bytes] = []
#: Lock for shared register-ca
_USER_APPEND_CA_LOCK = RLock()


@lru_cache()
def root_der_certificates() -> list[bytes]:
    with _USER_APPEND_CA_LOCK:
        certificates = _root_der_certificates()

        if not certificates:
            certificates = fallback_der_certificates()

        certificates.extend(_MANUALLY_REGISTERED_CA)

        return certificates


@lru_cache()
def root_pem_certificates() -> list[str]:
    """
    Retrieve a list of root certificate from your operating system trust store.
    They will be PEM encoded.
    """
    pem_certs = []

    for bin_cert in root_der_certificates():
        pem_certs.append(ssl.DER_cert_to_PEM_cert(bin_cert))

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
            pem_or_der_certificate = ssl.PEM_cert_to_DER_cert(pem_or_der_certificate)

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
    except AttributeError:  # Defensive: very old 3.7 branch
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
)
