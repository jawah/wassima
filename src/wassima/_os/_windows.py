from __future__ import annotations

from ssl import enum_certificates  # type: ignore[attr-defined]

# ROOT: Highest level of trust. Trust anchors. Self-Signed.
# MY: User installed/custom trust anchors. Self-Signed.
# CA: Intermediates CA. Not trusted directly, not self-signed.
WINDOWS_STORES: list[str] = [
    "ROOT",
    "MY",
    "CA",
]
SERVER_AUTH_OID: str = "1.3.6.1.5.5.7.3.1"


def root_der_certificates() -> list[bytes]:
    certificates = []

    for system_store in WINDOWS_STORES:
        try:
            for cert_bytes, encoding_type, trust in enum_certificates(system_store):
                if not trust:
                    continue  # Defensive: edge case, rare one.

                # if not True, then, we MUST LOOK for SERVER_AUTH oid EKU
                if not isinstance(trust, bool) and SERVER_AUTH_OID not in trust:
                    continue

                # Check it's in X.509 ASN.1 format and is trusted
                if (
                    encoding_type == "x509_asn"  # X.509 ASN.1 data
                ):
                    certificates.append(cert_bytes)
        except PermissionError:  # Defensive: we can't cover that scenario in CI.
            continue

    return certificates


__all__ = ("root_der_certificates",)
