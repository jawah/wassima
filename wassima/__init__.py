"""
the Wassima library is a simple wrapper around the crate rustls-native-certs.
It aims to provide a pythonic way to retrieve root CAs from your system without any difficulties or hazmat.
"""
from __future__ import annotations

import ssl
from functools import lru_cache
from ssl import DER_cert_to_PEM_cert

from ._rustls import root_der_certificates


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
)
