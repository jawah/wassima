from __future__ import annotations

from ssl import enum_certificates, enum_crls  # type: ignore[attr-defined]


def root_der_certificates() -> list[bytes]:
    certificates = []
    for cert_bytes, encoding_type, trust in enum_certificates("ROOT") + enum_certificates("MY"):
        if not trust:
            continue

        # if not True, then, we MUST LOOK for SERVER_AUTH oid EKU
        if not isinstance(trust, bool) and "1.3.6.1.5.5.7.3.1" not in trust:
            continue

        # Check it's in X.509 ASN.1 format and is trusted
        if (
            encoding_type == "x509_asn"  # X.509 ASN.1 data
        ):
            certificates.append(cert_bytes)

    return certificates


def certificate_revocation_lists_der() -> list[bytes]:
    crls = []

    for cert_bytes, encoding_type, trust in enum_crls("ROOT") + enum_crls("MY"):
        crls.append(cert_bytes)  # CRLs are always DER-encoded

    return crls


__all__ = (
    "root_der_certificates",
    "certificate_revocation_lists_der",
)
