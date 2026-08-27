from __future__ import annotations


def run() -> None:
    import os
    import ssl
    import sys

    import wassima._os as os_backend
    from wassima._os import _linux

    conscrypt = "/apex/com.android.conscrypt/cacerts"
    legacy = "/system/etc/security/cacerts"

    assert sys.platform in {"android", "linux"}, sys.platform
    assert hasattr(sys, "getandroidapilevel")
    assert os_backend.IS_ANDROID
    assert os_backend.IS_LINUX
    assert os_backend.root_der_certificates.__module__ == "wassima._os._linux"

    assert os.path.isdir(conscrypt)
    assert _linux._directory_has_entries(conscrypt)
    directories = _linux._bundle_trust_store_directories()
    assert conscrypt in directories
    assert legacy not in directories

    # Test the native backend directly so the embedded fallback cannot hide a failure.
    certificates = _linux.root_der_certificates()
    assert certificates
    assert len(certificates) == len(set(certificates))
    for certificate in certificates:
        assert ssl.DER_cert_to_PEM_cert(certificate).startswith("-----BEGIN CERTIFICATE-----")
