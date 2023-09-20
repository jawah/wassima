from __future__ import annotations

from socket import AF_INET, SOCK_STREAM, socket
from ssl import SSLError

import pytest

from wassima import create_default_ssl_context


@pytest.mark.parametrize(
    "host, port, expect_failure, failure_label",
    [
        ("1.1.1.1", 443, False, None),
        ("google.com", 443, False, None),
        ("self-signed.badssl.com", 443, True, "self-signed certificate"),
        ("untrusted-root.badssl.com", 443, True, "self-signed certificate"),
        ("tls-v1-2.badssl.com", 1012, False, None),
        (
            "sha1-intermediate.badssl.com",
            443,
            True,
            "unable to get local issuer certificate",
        ),
        ("one.one.one.one", 443, False, None),
        ("edellroot.badssl.com", 443, True, "unable to get local issuer certificate"),
        ("developer.mozilla.org", 443, False, None),
        ("letsencrypt.org", 443, False, None),
    ],
)
def test_ctx_use_system_store(
    host: str, port: int, expect_failure: bool, failure_label: str
) -> None:
    ctx = create_default_ssl_context()

    s = socket(AF_INET, SOCK_STREAM)
    s = ctx.wrap_socket(s, server_hostname=host)

    if expect_failure:
        with pytest.raises(SSLError) as exc:
            s.connect((host, port))

        assert failure_label in exc.value.args[1]
    else:
        s.connect((host, port))
        assert s.getpeercert() is not None

    s.close()
