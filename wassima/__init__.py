"""
the Wassima library is a simple wrapper around the crate rustls-native-certs.
It aims to provide a pythonic way to retrieve root CAs from your system without any difficulties or hazmat.
"""
from __future__ import annotations

import contextlib
import os
import ssl
import typing
from functools import lru_cache
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


def _split_certifi_bundle(data: bytes) -> list[str]:
    line_ending = b"\n" if b"-----\r\n" not in data else b"\r\n"
    boundary = b"-----END CERTIFICATE-----" + line_ending

    certificates = []

    for chunk in data.split(boundary):
        if chunk:
            start_marker = chunk.find(b"-----BEGIN CERTIFICATE-----" + line_ending)
            if start_marker == -1:
                break
            pem_reconstructed = b"".join([chunk[start_marker:], boundary]).decode(
                "ascii"
            )
            certificates.append(pem_reconstructed)

    return certificates


@contextlib.contextmanager
def _shelve_environment(*keys: str) -> typing.Generator[None, None, None]:
    ctx = {}

    for key in keys:
        try:
            ctx[key] = os.environ.pop(key)
        except KeyError:
            ...

    try:
        yield
    finally:
        for key in ctx:
            os.environ[key] = ctx[key]


def _certifi_fallback() -> list[bytes]:
    import certifi  # type: ignore

    certs: list[bytes] = []

    try:
        with open(certifi.where(), "rb") as fp:
            for pem_cert in _split_certifi_bundle(fp.read()):
                certs.append(ssl.PEM_cert_to_DER_cert(pem_cert))
    except (OSError, PermissionError) as e:
        warnings.warn(
            "Unable to fallback on Certifi due to an error trying to read the vendored CA bundle. "
            f"{str(e)}"
        )
        return certs

    return certs


try:
    from ._rustls import root_der_certificates as _root_der_certificates

    @lru_cache()
    def root_der_certificates() -> list[bytes]:
        with _shelve_environment("SSL_CERT_FILE", "SSL_CERT_DIR"):
            with _USER_APPEND_CA_LOCK:
                try:
                    return _root_der_certificates() + _MANUALLY_REGISTERED_CA
                except RuntimeError:
                    try:
                        fallback_certificates = _certifi_fallback()
                    except ImportError:
                        fallback_certificates = []

                    return fallback_certificates + _MANUALLY_REGISTERED_CA

    RUSTLS_LOADED = True
except ImportError:
    RUSTLS_LOADED = False

    try:
        import certifi
    except ImportError:
        certifi = None

    if certifi is None:
        import platform
        import warnings

        warnings.warn(
            "Unable to access your system root CAs. Your particular interpreter and/or "
            f"operating system ({platform.python_implementation()}, {platform.uname()}, {platform.python_version()}) "
            "is not supported. While it is not ideal, you may circumvent that warning by having certifi "
            "installed in your environment. Run `python -m pip install certifi`. "
            "You may also open an issue at https://github.com/jawah/wassima/issues to get your platform supported.",
            RuntimeWarning,
        )

    @lru_cache()
    def root_der_certificates() -> list[bytes]:
        try:
            return _certifi_fallback()
        except ImportError:
            return []


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
