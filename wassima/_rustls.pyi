from __future__ import annotations

def root_der_certificates() -> list[bytes]:
    """
    Retrieve a list of root certificate from your operating system trust store.
    They will be DER (binary) encoded.
    """
