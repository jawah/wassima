from __future__ import annotations

import os
from pathlib import Path
from ssl import PEM_cert_to_DER_cert

# source: http://gagravarr.org/writing/openssl-certs/others.shtml
BUNDLE_TRUST_STORE_DIRECTORIES: list[str] = [
    "/var/ssl",
    "/usr/share/ssl",
    "/usr/local/ssl",
    "/usr/local/openssl",
    "/usr/local/etc/openssl",
    "/usr/local/share",
    "/usr/lib/ssl",
    "/usr/ssl",
    "/etc/openssl",
    "/etc/pki/ca-trust/extracted/pem",
    "/etc/pki/tls",
    "/etc/ssl",
    "/etc/certs",
    "/opt/etc/ssl",
    "/system/etc/security/cacerts",
    "/boot/system/data/ssl",
]

KNOWN_TRUST_STORE_EXTENSIONS: list[str] = [
    "pem",
    "crt",
]

BANNED_KEYWORD_NOT_TLS: set[str] = {
    "email",
    "objsign",
    "trust",
    "timestamp",
    "codesign",
    "ocsp",
}


def root_der_certificates() -> list[bytes]:
    certificates: list[bytes] = []

    for directory in BUNDLE_TRUST_STORE_DIRECTORIES:
        if not os.path.exists(directory):
            continue

        # Use rglob to recursively search all files in directory and subdirectories
        for filepath in Path(directory).rglob("*"):
            if not filepath.is_file():  # Skip directories
                continue

            extension = str(filepath).split(".")[-1]

            if extension not in KNOWN_TRUST_STORE_EXTENSIONS and extension.isdigit() is False:
                continue

            if any(kw in str(filepath).lower() for kw in BANNED_KEYWORD_NOT_TLS):
                continue

            try:
                with open(filepath, encoding="utf-8") as f:
                    bundle = f.read()

                if not bundle.strip():  # Skip empty files
                    continue  # Defensive:

                line_ending = "\n" if "-----END CERTIFICATE-----\r\n" not in bundle else "\r\n"
                boundary = "-----END CERTIFICATE-----" + line_ending

                for chunk in bundle.split(boundary):
                    if chunk:
                        start_marker = chunk.find("-----BEGIN CERTIFICATE-----" + line_ending)

                        if start_marker == -1:
                            break

                        pem_reconstructed = "".join([chunk[start_marker:], boundary])

                        try:
                            der_certificate = PEM_cert_to_DER_cert(pem_reconstructed)
                        except ValueError:  # Defensive: malformed cert/base64?
                            continue

                        if der_certificate not in certificates:
                            certificates.append(der_certificate)

            except (OSError, UnicodeDecodeError):  # Defensive: Skip files we can't read
                # OSError -> e.g. PermissionError
                # UnicodeDecodeError -> DER ASN.1 encoded
                continue

    return certificates
