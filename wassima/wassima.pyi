import typing


def root_der_certificates() -> typing.List[bytes]:
    """
    Retrieve a list of root certificate from your operating system trust store.
    They will be DER (binary) encoded.
    """
    ...
