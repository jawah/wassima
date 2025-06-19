from pathlib import Path
import os
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

            if (
                extension not in KNOWN_TRUST_STORE_EXTENSIONS
                and extension.isdigit() is False
            ):
                continue

            try:
                with open(filepath, "rb") as f:
                    content = f.read()

                if not content:  # Skip empty files
                    continue

                # Try to handle the file as PEM certificate(s) first
                try:
                    ascii_content = content.decode("ascii")
                    # Split on PEM certificate boundaries
                    pem_certs = [
                        cert
                        for cert in ascii_content.split("-----BEGIN CERTIFICATE-----")
                        if cert.strip()
                    ]  # Remove empty strings

                    for pem_cert in pem_certs:
                        try:
                            # Restore the header if it's not the first cert
                            if not pem_cert.startswith("-----BEGIN CERTIFICATE-----"):
                                pem_cert = "-----BEGIN CERTIFICATE-----" + pem_cert

                            der_cert = PEM_cert_to_DER_cert(pem_cert)
                            if der_cert not in certificates:
                                certificates.append(der_cert)
                        except ValueError:
                            # Skip invalid PEM certificates
                            continue

                except (ValueError, UnicodeDecodeError):
                    # Not a valid PEM certificate file
                    continue

            except (IOError, OSError):
                # Skip files we can't read
                continue

    return certificates


def certificate_revocation_lists_der() -> list[bytes]:
    return []
