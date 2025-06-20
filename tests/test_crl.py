from __future__ import annotations

import ssl
import sys
from os import unlink
from tempfile import NamedTemporaryFile

import pytest

from wassima import certificate_revocation_lists_der, create_default_ssl_context

IS_WINDOWS = sys.platform == "win32"
IS_MACOS = sys.platform == "darwin"


@pytest.mark.skipif(not (IS_WINDOWS or IS_MACOS), reason="test requires Windows or MacOS")
def test_crl_are_fetched() -> None:
    crls = certificate_revocation_lists_der()

    assert len(crls) >= 1

    with NamedTemporaryFile("w", suffix=".pem", delete=False) as fp:
        pem_formatted = ssl.DER_cert_to_PEM_cert(crls[0])

        pem_formatted = pem_formatted.replace("-----BEGIN CERTIFICATE-----", "-----BEGIN X509 CRL-----")
        pem_formatted = pem_formatted.replace("-----END CERTIFICATE-----", "-----END X509 CRL-----")

        fp.write(pem_formatted)

    ctx = create_default_ssl_context()
    ctx.load_verify_locations(cafile=fp.name)

    assert ctx.cert_store_stats()["crl"] == 1

    unlink(fp.name)


@pytest.mark.skipif(IS_WINDOWS or IS_MACOS, reason="test requires not Windows and not MacOS")
def test_crl_are_not_fetched() -> None:
    assert not certificate_revocation_lists_der()
